"""Indicators of Compromise (IOC) service.

Agent registry, indicator corpus sync, deterministic lookups (offline list
first, optional online provider second) and the observation/match stream.

Honesty rules (enforced in code, not just docs):

- ``unknown`` is the default verdict for anything not confidently matched.
- Online provider failures are logged and downgraded to ``unknown``.
- Demo rows carry ``source_label="demo"`` so the UI can label them; real agent
  observations always carry ``source_label="real_endpoint"``.
"""

import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)
from app.models.ioc import IOC_TYPES, IocAgent, IocIndicator, IocMatch, IocObservation
from app.services.ioc_data import (
    canonical_value,
    lookup_offline,
    offline_indicators,
)

log = logging.getLogger("siem.ioc.service")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class IocService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # =================================================================== agents
    def agents(self) -> list[dict]:
        rows = self.db.execute(select(IocAgent).order_by(IocAgent.agent_code)).scalars().all()
        return [self._agent_dict(a) for a in rows]

    def register_agent(
        self,
        *,
        agent_code: str,
        hostname: str = "",
        ip_address: str = "",
        operating_system: str = "",
        platform: str = "windows",
        version: str = "1.0.0",
        machine_guid: str | None = None,
        registration_token: str | None = None,
    ) -> dict:
        if settings.ioc_registration_token:
            if not registration_token or not secrets.compare_digest(
                registration_token, settings.ioc_registration_token
            ):
                raise UnauthorizedError(
                    "Invalid registration token", code="invalid_registration_token"
                )
        agent_code = agent_code.strip()
        if not agent_code or len(agent_code) > 64:
            raise ValidationError("agent_code is required (max 64 chars)")

        existing = self.db.scalar(select(IocAgent).where(IocAgent.agent_code == agent_code))
        if existing is not None:
            raise ConflictError(f"Agent '{agent_code}' already registered")

        api_key = secrets.token_urlsafe(32)
        agent = IocAgent(
            agent_code=agent_code,
            hostname=hostname or agent_code,
            ip_address=ip_address or None,
            operating_system=operating_system or "Windows",
            platform=platform or "windows",
            version=version or "1.0.0",
            status="online",
            last_seen=_now(),
            api_key_hash=_hash_api_key(api_key),
            enabled=True,
            machine_guid=machine_guid or None,
        )
        self.db.add(agent)
        self.db.commit()
        self.db.refresh(agent)
        data = self._agent_dict(agent)
        data["api_key"] = api_key
        return data

    def heartbeat(self, agent_code: str, api_key: str, status: str = "online") -> dict:
        agent = self.db.scalar(select(IocAgent).where(IocAgent.agent_code == agent_code))
        if agent is None:
            raise NotFoundError(f"Agent '{agent_code}' not registered")
        if not agent.api_key_hash or not secrets.compare_digest(
            _hash_api_key(api_key), agent.api_key_hash
        ):
            raise UnauthorizedError("Invalid agent API key", code="invalid_api_key")
        agent.status = status if status in ("online", "offline") else "online"
        agent.last_seen = _now()
        self.db.commit()
        return self._agent_dict(agent)

    def _agent_dict(self, agent: IocAgent) -> dict:
        return {
            "id": agent.id,
            "agent_code": agent.agent_code,
            "hostname": agent.hostname,
            "ip_address": agent.ip_address,
            "operating_system": agent.operating_system,
            "platform": agent.platform,
            "version": agent.version,
            "status": agent.status,
            "last_seen": _iso(agent.last_seen),
            "enabled": agent.enabled,
            "demo": bool(settings.ioc_demo_mode),
        }

    # ================================================================ indicators
    def sync_indicators(self) -> dict:
        """Refresh the indicator corpus from the bundled offline list.

        Returns counts; never deletes existing indicators so audit history is
        preserved (expired/removed entries are simply deactivated).
        """
        existing = {
            (i.indicator_type, i.value): i
            for i in self.db.execute(select(IocIndicator)).scalars().all()
        }
        added = updated = 0
        now = _now()
        for entry in offline_indicators():
            key = (entry["indicator_type"], entry["value"])
            row = existing.get(key)
            if row is None:
                self.db.add(
                    IocIndicator(
                        indicator_type=entry["indicator_type"],
                        value=entry["value"],
                        source=entry["source"],
                        threat=entry["threat"],
                        severity=entry["severity"],
                        tags=json.dumps(entry.get("tags") or []),
                        reference=entry.get("reference"),
                        active=True,
                    )
                )
                added += 1
            else:
                row.source = entry["source"]
                row.threat = entry["threat"]
                row.severity = entry["severity"]
                row.reference = entry.get("reference")
                row.active = True
                row.expires_at = None
                updated += 1
        # Deactivate indicators no longer present in the list.
        current_keys = {(e["indicator_type"], e["value"]) for e in offline_indicators()}
        for row in self.db.execute(select(IocIndicator)).scalars().all():
            if (row.indicator_type, row.value) not in current_keys:
                row.active = False
        self.db.commit()
        return {"added": added, "updated": updated, "total": len(current_keys), "now": _iso(now)}

    def indicators(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        indicator_type: str | None = None,
        search: str = "",
    ) -> dict:
        query = select(IocIndicator)
        if indicator_type:
            query = query.where(IocIndicator.indicator_type == indicator_type)
        q = search.strip().lower()
        if q:
            query = query.where(
                IocIndicator.value.ilike(f"%{q}%")
                | IocIndicator.threat.ilike(f"%{q}%")
                | IocIndicator.source.ilike(f"%{q}%")
            )
        total = self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        rows = self.db.execute(
            query.order_by(IocIndicator.indicator_type, IocIndicator.value)
            .offset((safe_page - 1) * per_page)
            .limit(per_page)
        ).scalars().all()
        return {
            "items": [self._indicator_dict(i) for i in rows],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
            "demo": bool(settings.ioc_demo_mode),
        }

    def _indicator_dict(self, ind: IocIndicator) -> dict:
        return {
            "id": ind.id,
            "type": ind.indicator_type,
            "value": ind.value,
            "source": ind.source,
            "threat": ind.threat,
            "severity": ind.severity,
            "tags": self._parse_json(ind.tags) or [],
            "reference": ind.reference,
            "active": ind.active,
            "expires_at": _iso(ind.expires_at),
        }

    # ================================================================== lookups
    async def lookup(self, indicator_type: str, value: str) -> dict:
        """Deterministic indicator lookup: offline list, then optional online."""
        indicator_type = indicator_type.strip().lower()
        if indicator_type not in IOC_TYPES:
            raise ValidationError(f"indicator_type must be one of {', '.join(IOC_TYPES)}")
        value = value.strip()
        if not value:
            raise ValidationError("value is required")

        result = lookup_offline(indicator_type, value)
        provider = None
        if result is None:
            from app.services.ioc_data import build_threat_intel

            provider = build_threat_intel()
            if provider is not None:
                from app.services.ioc_providers import lookup_online

                result = await lookup_online(provider, indicator_type, value)
                if result is None:
                    result = LookupUnknown(indicator_type, value)

        if result is None:
            result = LookupUnknown(indicator_type, value)
        data = result.to_dict()
        data["demo"] = bool(settings.ioc_demo_mode)
        data["threat_intel_enabled"] = settings.threat_intel_enabled
        data["provider"] = provider.provider_name if provider else None
        return data

    # ============================================================ observations
    def ingest_observation(
        self,
        *,
        agent_code: str,
        observations: list[dict],
        source_label: str = "real_endpoint",
    ) -> dict:
        """Accept observed indicators from an endpoint agent and compute matches."""
        agent = self.db.scalar(select(IocAgent).where(IocAgent.agent_code == agent_code))
        if agent is None:
            raise NotFoundError(f"Agent '{agent_code}' not registered")

        matched = 0
        unknown = 0
        stored = 0
        now = _now()
        for item in observations or []:
            if not isinstance(item, dict):
                raise ValidationError("observation items must be objects")
            indicator_type = str(item.get("type") or item.get("indicator_type") or "").strip().lower()
            value = str(item.get("value", "")).strip()
            if indicator_type not in IOC_TYPES or not value:
                raise ValidationError("observation requires type in IOC_TYPES and a non-empty value")
            observed_at = item.get("observed_at")
            try:
                observed_dt = (
                    datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
                    if observed_at
                    else now
                )
            except ValueError:
                observed_dt = now

            obs = IocObservation(
                agent_id=agent.id,
                observed_at=observed_dt,
                indicator_type=indicator_type,
                value=value,
                source=str(item.get("source", "telemetry")),
                context=json.dumps(item.get("context") or {}) if item.get("context") else None,
                source_label=source_label,
            )
            self.db.add(obs)
            self.db.flush()

            verdict = self.lookup_sync(indicator_type, value)
            verdict["value"] = value
            verdict["type"] = indicator_type
            match = IocMatch(
                observation_id=obs.id,
                agent_id=agent.id,
                indicator_id=verdict.get("indicator_id"),
                indicator_type=indicator_type,
                value=value,
                verdict=verdict["verdict"],
                severity=verdict.get("severity", "unknown"),
                threat=verdict.get("threat"),
                source=verdict.get("source", "bundled"),
                confidence=verdict.get("confidence", 0.0),
                detail=verdict.get("detail"),
                matched_at=now,
                source_label=source_label,
            )
            self.db.add(match)
            stored += 1
            if verdict["verdict"] == "malicious":
                matched += 1
            elif verdict["verdict"] == "unknown":
                unknown += 1

        self.db.commit()
        return {
            "agent_id": agent.id,
            "stored": stored,
            "matched": matched,
            "unknown": unknown,
            "demo": bool(settings.ioc_demo_mode),
        }

    def lookup_sync(self, indicator_type: str, value: str) -> dict:
        """Offline-only lookup used by ingest (fast, deterministic, no network)."""
        result = lookup_offline(indicator_type, value)
        if result is None:
            return {
                "verdict": "unknown",
                "severity": "unknown",
                "source": "bundled",
                "threat": None,
                "confidence": 0.0,
                "indicator_id": None,
            }
        indicator = self.db.scalar(
            select(IocIndicator).where(
                IocIndicator.indicator_type == indicator_type,
                IocIndicator.value == canonical_value(indicator_type, value),
            )
        )
        return {
            "verdict": result.verdict,
            "severity": result.severity,
            "source": result.source,
            "threat": result.threat,
            "confidence": result.confidence,
            "indicator_id": indicator.id if indicator else None,
        }

    def observations(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        agent_id: str | None = None,
        verdict: str | None = None,
    ) -> dict:
        query = (
            select(IocObservation, IocMatch)
            .join(IocMatch, IocMatch.observation_id == IocObservation.id)
            .order_by(IocObservation.observed_at.desc())
        )
        if agent_id:
            query = query.where(IocObservation.agent_id == agent_id)
        if verdict:
            query = query.where(IocMatch.verdict == verdict)

        total = self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        rows = self.db.execute(
            query.offset((safe_page - 1) * per_page).limit(per_page)
        ).all()
        agent_names = self._agent_names()
        return {
            "items": [
                self._observation_match_dict(obs, m, agent_names=agent_names)
                for obs, m in rows
            ],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
            "demo": bool(settings.ioc_demo_mode),
        }

    def matches(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        verdict: str | None = None,
        agent_id: str | None = None,
    ) -> dict:
        query = select(IocMatch)
        if verdict:
            query = query.where(IocMatch.verdict == verdict)
        if agent_id:
            query = query.where(IocMatch.agent_id == agent_id)
        total = self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        rows = self.db.execute(
            query.order_by(IocMatch.matched_at.desc())
            .offset((safe_page - 1) * per_page)
            .limit(per_page)
        ).scalars().all()
        agent_names = self._agent_names()
        return {
            "items": [self._match_dict(m, agent_names=agent_names) for m in rows],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
            "demo": bool(settings.ioc_demo_mode),
        }

    # ================================================================ dashboard
    def dashboard(self) -> dict:
        indicators = self.db.scalar(select(func.count()).select_from(IocIndicator)) or 0
        matches_total = self.db.scalar(select(func.count()).select_from(IocMatch)) or 0
        malicious = self.db.scalar(
            select(func.count()).select_from(IocMatch).where(IocMatch.verdict == "malicious")
        ) or 0
        suspicious = self.db.scalar(
            select(func.count()).select_from(IocMatch).where(IocMatch.verdict == "suspicious")
        ) or 0
        unknown_matches = self.db.scalar(
            select(func.count()).select_from(IocMatch).where(IocMatch.verdict == "unknown")
        ) or 0
        agents = list(self.db.execute(select(IocAgent)).scalars().all())
        online = sum(1 for a in agents if a.status == "online")
        observations_today = self.db.scalar(
            select(func.count())
            .select_from(IocObservation)
            .where(IocObservation.observed_at >= _now().replace(hour=0, minute=0, second=0, microsecond=0))
        ) or 0

        recent_matches = self.db.execute(
            select(IocMatch).order_by(IocMatch.matched_at.desc()).limit(10)
        ).scalars().all()
        agent_names = self._agent_names()
        by_type = self.db.execute(
            select(IocMatch.indicator_type, func.count())
            .group_by(IocMatch.indicator_type)
        ).all()

        return {
            "demo": bool(settings.ioc_demo_mode),
            "threat_intel_enabled": bool(settings.threat_intel_enabled),
            "providers": [settings.threat_intel_provider] if settings.threat_intel_enabled else [],
            "indicators_total": indicators,
            "matches_total": matches_total,
            "matches_malicious": malicious,
            "matches_suspicious": suspicious,
            "matches_unknown": unknown_matches,
            "agents_total": len(agents),
            "agents_online": online,
            "observations_today": observations_today,
            "by_type": [{"key": t, "count": c} for t, c in by_type],
            "recent_matches": [
                self._match_dict(m, agent_names=agent_names) for m in recent_matches
            ],
        }

    # ============================================================== serializers
    def _agent_names(self) -> dict[str, str]:
        return {
            a.id: f"{a.hostname} ({a.agent_code})"
            for a in self.db.execute(select(IocAgent)).scalars().all()
        }

    @staticmethod
    def _parse_json(value: str | None) -> Any:
        if not value:
            return None
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return value

    def _observation_match_dict(self, obs: IocObservation, match: IocMatch, *, agent_names) -> dict:
        return {
            "id": obs.id,
            "agent_id": obs.agent_id,
            "agent": agent_names.get(obs.agent_id),
            "observed_at": _iso(obs.observed_at),
            "type": obs.indicator_type,
            "value": obs.value,
            "source": obs.source,
            "context": self._parse_json(obs.context),
            "verdict": match.verdict,
            "severity": match.severity,
            "threat": match.threat,
            "confidence": match.confidence,
            "source_label": obs.source_label,
        }

    def _match_dict(self, match: IocMatch, *, agent_names) -> dict:
        return {
            "id": match.id,
            "observation_id": match.observation_id,
            "agent_id": match.agent_id,
            "agent": agent_names.get(match.agent_id),
            "type": match.indicator_type,
            "value": match.value,
            "verdict": match.verdict,
            "severity": match.severity,
            "threat": match.threat,
            "source": match.source,
            "confidence": match.confidence,
            "detail": match.detail,
            "matched_at": _iso(match.matched_at),
            "source_label": match.source_label,
        }


class LookupUnknown:
    """Fallback result when no source can answer - an honest unknown."""

    def __init__(self, indicator_type: str, value: str) -> None:
        self.indicator_type = indicator_type
        self.value = value

    def to_dict(self) -> dict:
        return {
            "verdict": "unknown",
            "type": self.indicator_type,
            "value": self.value,
            "source": "bundled",
            "severity": "unknown",
            "threat": None,
            "reference": None,
            "confidence": 0.0,
            "detail": "not found in any configured threat-intel source",
        }
