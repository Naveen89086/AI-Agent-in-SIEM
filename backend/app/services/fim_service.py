"""File Integrity Monitoring (FIM) service.

Two modes, mirroring SCA:

- Demo mode seeds deterministic syscheck data (see endpoint_seed) and the
  query endpoints are powered by it. Real agent traffic never mixes with it.
- Real mode: endpoint agents enroll with a per-agent API key, persist an
  authoritative file baseline (``SyscheckFile``) and submit SHA-256 evidence
  through ``POST /api/v1/fim/ingest``.

The server is always the final authority: the event type is *reclassified*
against the persisted baseline (an "added" report for a path that is already
in the baseline becomes "modified", a "modified" report for an unknown path
becomes "added", etc.) and the severity is assigned deterministically by the
rule engine in ``fim_rules`` - never by the client and never by AI.

Baseline rows are never deleted: "deleted" files are marked ``status=deleted``
so history survives for audit and correlation.
"""

import hashlib
import logging
import secrets
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)
from app.models.syscheck import SyscheckAgent, SyscheckEvent, SyscheckFile
from app.schemas.fim import FimIngestRequest
from app.services import fim_rules
from app.services.protected_endpoint_service import ProtectedEndpointService

log = logging.getLogger("siem.fim")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def normalize_path(path: str) -> str:
    """Normalize a Windows path to a canonical comparison key.

    Only used as a string key for baseline lookups - never to touch the
    filesystem. Converts forward slashes, uppercases the drive letter and
    collapses duplicate separators.
    """
    if not path:
        return path
    p = path.replace("/", "\\")
    parts = [part for part in p.split("\\") if part not in ("", ".")]
    p = "\\".join(parts)
    if len(p) >= 2 and p[1] == ":":
        p = p[0].upper() + p[1:]
    if p.startswith("\\\\"):
        p = "\\\\" + p.lstrip("\\")
    elif not p.startswith("\\"):
        p = p  # keep relative names as-is
    return p


def _event_type_field(event_type: str) -> str:
    """Map a real event_type to the legacy ``event`` column (added/modified/deleted)."""
    if event_type == "renamed":
        return "modified"
    return event_type


class FimService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------ serializers
    def _agent_dict(self, agent: SyscheckAgent) -> dict:
        return {
            "code": agent.code,
            "name": agent.name,
            "platform": agent.platform,
            "os_name": agent.os_name,
            "status": agent.status,
            "registry_entries": agent.registry_entries,
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "ip_address": agent.ip_address,
            "version": agent.version,
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
            "enabled": agent.enabled,
            "demo": bool(settings.fim_demo_mode),
        }

    def agents(self) -> list[dict]:
        rows = self.db.execute(
            select(SyscheckAgent).order_by(SyscheckAgent.code)
        ).scalars().all()
        return [self._agent_dict(a) for a in rows]

    # ------------------------------------------------------------ enrollment
    def register_agent(
        self,
        *,
        agent_code: str,
        hostname: str = "",
        ip_address: str = "",
        os_name: str = "",
        platform: str = "windows",
        version: str = "1.0.0",
        machine_guid: str | None = None,
        registration_token: str | None = None,
    ) -> dict:
        if settings.fim_registration_token:
            if not registration_token or not secrets.compare_digest(
                registration_token, settings.fim_registration_token
            ):
                raise UnauthorizedError(
                    "Invalid registration token", code="invalid_registration_token"
                )
        agent_code = agent_code.strip()
        if not agent_code or len(agent_code) > 64:
            raise ValidationError("agent_code is required (max 64 chars)")
        if not hostname:
            raise ValidationError("hostname is required")

        existing = self.db.scalar(
            select(SyscheckAgent).where(SyscheckAgent.code == agent_code)
        )
        if existing is not None:
            raise ConflictError(f"Agent '{agent_code}' already registered")

        api_key = secrets.token_urlsafe(32)
        agent = SyscheckAgent(
            code=agent_code,
            name=hostname,
            hostname=hostname,
            ip_address=ip_address,
            os_name=os_name or platform,
            platform=platform or "windows",
            version=version or "1.0.0",
            status="active",
            last_seen=_now(),
            api_key_hash=_hash_api_key(api_key),
            enabled=True,
            machine_guid=machine_guid or None,
        )
        self.db.add(agent)
        self.db.commit()
        self.db.refresh(agent)
        data = self._agent_dict(agent)
        data["api_key"] = api_key  # returned once; only the hash is stored
        return data

    def heartbeat(self, agent_code: str, api_key: str, status: str = "online") -> dict:
        agent = self._authenticated_agent(agent_code, api_key)
        ProtectedEndpointService(self.db).validate_ingest_agent(agent)
        agent.status = status if status in ("active", "inactive") else "active"
        agent.last_seen = _now()
        self.db.commit()
        self.db.refresh(agent)
        return self._agent_dict(agent)

    def _authenticated_agent(self, agent_code: str, api_key: str) -> SyscheckAgent:
        if not api_key:
            raise UnauthorizedError("Missing agent API key", code="invalid_api_key")
        agent = self.db.scalar(
            select(SyscheckAgent).where(SyscheckAgent.code == agent_code)
        )
        if agent is None:
            raise NotFoundError(f"Agent '{agent_code}' not registered")
        if not agent.api_key_hash or not secrets.compare_digest(
            _hash_api_key(api_key), agent.api_key_hash
        ):
            raise UnauthorizedError("Invalid agent API key", code="invalid_api_key")
        return agent

    # --------------------------------------------------------------- ingest
    def ingest(self, agent_code: str, api_key: str, payload: FimIngestRequest) -> dict:
        agent = self._authenticated_agent(agent_code, api_key)
        ProtectedEndpointService(self.db).validate_ingest_agent(agent)
        agent.last_seen = _now()

        # Dedupe: if the agent already delivered this exact event, drop it.
        if payload.event_id:
            dup = self.db.scalar(
                select(SyscheckEvent).where(
                    SyscheckEvent.agent_id == agent.id,
                    SyscheckEvent.event_id == payload.event_id,
                )
            )
            if dup is not None:
                self.db.commit()
                return {"accepted": False, "duplicated": True, "event_type": dup.event_type}

        normalized = normalize_path(payload.path)
        if payload.old_path:
            old_normalized = normalize_path(payload.old_path)
        else:
            old_normalized = None

        classified, baseline = self._classify(agent, payload, normalized, old_normalized)

        rule = fim_rules.evaluate_rule(classified.get("path", normalized))
        event = SyscheckEvent(
            agent_id=agent.id,
            timestamp=payload.modified_time or _now(),
            path=classified.get("path", normalized),
            event=_event_type_field(classified["event_type"]),
            user=payload.user or "unknown",
            rule=rule["rule"],
            level=rule["level"],
            rule_id=_rule_number(rule["rule_id"]),
            manager_name="kaliinux",
            event_id=payload.event_id,
            event_type=classified["event_type"],
            old_path=classified.get("old_path"),
            old_sha256=payload.old_sha256,
            new_sha256=payload.new_sha256,
            sha256=payload.sha256,
            owner=payload.owner,
            size=payload.size,
            source=payload.source or "fim-agent",
            severity=rule["severity"],
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return {
            "accepted": True,
            "duplicated": False,
            "event_type": classified["event_type"],
            "severity": rule["severity"],
            "level": rule["level"],
            "rule_id": rule["rule_id"],
            "rule": rule["rule"],
            "event_id": event.id,
        }

    def _classify(
        self,
        agent: SyscheckAgent,
        payload: FimIngestRequest,
        normalized: str,
        old_normalized: str | None,
    ) -> tuple[dict, SyscheckFile | None]:
        """Reclassify the reported change against the server-side baseline.

        The server, not the agent, decides the event type. Returns
        ``(classified, baseline_row)`` where ``classified`` carries the final
        ``event_type`` and any paths used on the stored event.
        """
        existing = self.db.scalar(
            select(SyscheckFile).where(
                SyscheckFile.agent_id == agent.id,
                SyscheckFile.file_path == normalized,
            )
        )

        if payload.event_type == "renamed":
            if old_normalized:
                old_row = self.db.scalar(
                    select(SyscheckFile).where(
                        SyscheckFile.agent_id == agent.id,
                        SyscheckFile.file_path == old_normalized,
                    )
                )
                if old_row is not None and existing is None:
                    old_row.file_path = normalized
                    old_row.sha256 = payload.sha256
                    old_row.last_modified = payload.modified_time or _now()
                    old_row.last_seen = _now()
                    old_row.status = "active"
                    return (
                        {"event_type": "renamed", "path": normalized, "old_path": old_normalized},
                        old_row,
                    )
            if existing is not None:
                existing.sha256 = payload.sha256
                existing.last_modified = payload.modified_time or _now()
                existing.last_seen = _now()
                existing.status = "active"
                return ({"event_type": "modified", "path": normalized}, existing)
            return ({"event_type": "added", "path": normalized}, self._upsert_baseline(agent, payload, normalized))

        if payload.event_type in ("added", "modified"):
            if existing is not None and existing.sha256 == payload.sha256:
                existing.last_seen = _now()
                return ({"event_type": "modified", "path": normalized}, existing)
            if existing is not None:
                existing.sha256 = payload.sha256
                existing.last_modified = payload.modified_time or _now()
                existing.last_seen = _now()
                existing.status = "active"
                return ({"event_type": "modified", "path": normalized}, existing)
            row = self._upsert_baseline(agent, payload, normalized)
            return ({"event_type": "added", "path": normalized}, row)

        if payload.event_type == "deleted":
            if existing is not None:
                existing.status = "deleted"
                existing.last_seen = _now()
                payload.old_sha256 = payload.sha256 or existing.sha256
                return ({"event_type": "deleted", "path": normalized}, existing)
            return ({"event_type": "deleted", "path": normalized}, None)

        raise ValidationError(f"Unsupported event_type: {payload.event_type}")

    def _upsert_baseline(
        self, agent: SyscheckAgent, payload: FimIngestRequest, normalized: str
    ) -> SyscheckFile:
        existing = self.db.scalar(
            select(SyscheckFile).where(
                SyscheckFile.agent_id == agent.id,
                SyscheckFile.file_path == normalized,
            )
        )
        now = _now()
        if existing is not None:
            existing.sha256 = payload.sha256
            existing.last_modified = payload.modified_time or now
            existing.last_seen = now
            existing.status = "active"
            return existing
        row = SyscheckFile(
            agent_id=agent.id,
            file_path=normalized,
            last_modified=payload.modified_time or now,
            user=payload.user or "unknown",
            user_id=payload.user_id or "",
            size=payload.size or 0,
            sha256=payload.sha256,
            first_seen=now,
            last_seen=now,
            owner=payload.owner,
            permissions=payload.permissions,
            file_type=payload.file_type,
            status="active",
        )
        self.db.add(row)
        self.db.flush()
        return row


def _rule_number(rule_id: str) -> int:
    """Stable integer for the legacy ``rule_id`` column from a FIM rule id."""
    digest = hashlib.sha1(rule_id.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 90000 + 1000
