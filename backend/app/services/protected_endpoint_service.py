"""Protected endpoint service (single-device enforcement).

The single source of truth for "the one PC this product protects". Every
registration path (telemetry / IOC / SCA / vulnerability / FIM) routes through
:meth:`ensure_single_endpoint`, which:

- creates the first registered machine as the protected endpoint, and
- rejects a second, *different* machine with error code
  ``single_endpoint_limit`` when ``settings.max_protected_endpoints == 1``.

Registration is idempotent for the same machine: re-registering (or a later
subsystem registering from the same device) updates the row instead of failing,
and subsystems are free to keep their own internal agent registries as long as
they reference this device.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import ConflictError
from app.models.protected_endpoint import ProtectedEndpoint

log = logging.getLogger("siem.protected_endpoint")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def _as_json_list(value: Any) -> str | None:
    """Normalize an IP/MAC address set into a JSON list string."""
    if value is None:
        return None
    if isinstance(value, str):
        value = [v.strip() for v in value.split(",") if v.strip()]
    elif not isinstance(value, (list, tuple)):
        value = [str(value)]
    else:
        value = [str(v) for v in value]
    return json.dumps(value) if value else None


class ProtectedEndpointService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # -------------------------------------------------------------- read side
    def get_current_endpoint(self) -> ProtectedEndpoint | None:
        """Return the single protected endpoint (None when not yet registered)."""
        return self.db.execute(select(ProtectedEndpoint).order_by(ProtectedEndpoint.created_at)).scalars().first()

    def endpoint_count(self) -> int:
        return self.db.scalar(select(func.count()).select_from(ProtectedEndpoint)) or 0

    def to_dict(self, endpoint: ProtectedEndpoint) -> dict:
        addresses = json.loads(endpoint.ip_addresses) if endpoint.ip_addresses else []
        macs = json.loads(endpoint.mac_addresses) if endpoint.mac_addresses else []
        return {
            "id": endpoint.id,
            "endpoint_id": endpoint.id,
            "machine_guid": endpoint.machine_guid,
            "hostname": endpoint.hostname,
            "operating_system": endpoint.operating_system,
            "os_version": endpoint.os_version,
            "architecture": endpoint.architecture,
            "agent_version": endpoint.agent_version,
            "ip_address": endpoint.ip_address,
            "ip_addresses": addresses,
            "mac_addresses": macs,
            "status": endpoint.status,
            "last_seen": _iso(endpoint.last_seen),
            "registered_at": _iso(endpoint.registered_at),
            "demo": bool(endpoint.demo),
        }

    def status_payload(self) -> dict:
        """The status response used by ``GET /api/v1/protected-endpoint``."""
        endpoint = self.get_current_endpoint()
        if endpoint is None:
            return {
                "registered": False,
                "endpoint": None,
                "status": "not_registered",
                "max_protected_endpoints": settings.max_protected_endpoints,
            }
        data = self.to_dict(endpoint)
        return {
            "registered": True,
            "endpoint": data,
            "status": endpoint.status,
            "max_protected_endpoints": settings.max_protected_endpoints,
        }

    # --------------------------------------------------------- enforcement
    def ensure_single_endpoint(
        self,
        *,
        machine_guid: str = "",
        hostname: str = "",
        operating_system: str = "",
        os_version: str | None = None,
        architecture: str | None = None,
        agent_version: str | None = None,
        ip_address: str = "",
        ip_addresses: Any = None,
        mac_addresses: Any = None,
    ) -> ProtectedEndpoint | None:
        """Register (or update) the single protected endpoint.

        Raises ``ConflictError(single_endpoint_limit)`` when a *different*
        machine tries to register and the deployment is capped.

        When no ``machine_guid`` is supplied (legacy callers) the protected
        endpoint is left untouched and ``None`` is returned: without a stable
        fingerprint the device cannot be adjudicated, so nothing is enforced.
        The local endpoint agent always derives and sends a fingerprint.
        """
        machine_guid = (machine_guid or "").strip()
        if not machine_guid:
            return None

        endpoint = self.get_current_endpoint()
        if endpoint is None:
            count = self.endpoint_count()
            limit = settings.max_protected_endpoints
            if limit and limit > 0 and count >= limit:
                raise ConflictError(
                    "This deployment protects a single endpoint. A different device "
                    "tried to register and was rejected.",
                    code="single_endpoint_limit",
                )
            endpoint = ProtectedEndpoint(
                machine_guid=machine_guid,
                hostname=hostname or machine_guid,
                operating_system=operating_system or "Windows",
                status="online",
                registered_at=_now(),
                last_seen=_now(),
                demo=False,
            )
            self.db.add(endpoint)
        else:
            if machine_guid != endpoint.machine_guid:
                if endpoint.demo:
                    # A real device supersedes the demo placeholder (demo rows
                    # are never treated as real findings).
                    log.info(
                        "Replacing demo protected endpoint %s with real device %s",
                        endpoint.machine_guid,
                        machine_guid,
                    )
                    endpoint.machine_guid = machine_guid
                    endpoint.demo = False
                else:
                    raise ConflictError(
                        "This deployment protects a single endpoint "
                        f"({endpoint.hostname}). Device '{machine_guid}' tried to "
                        "register and was rejected.",
                        code="single_endpoint_limit",
                    )

        endpoint.hostname = hostname or endpoint.hostname
        endpoint.operating_system = operating_system or endpoint.operating_system
        if os_version:
            endpoint.os_version = os_version
        if architecture:
            endpoint.architecture = architecture
        if agent_version:
            endpoint.agent_version = agent_version
        if ip_address:
            endpoint.ip_address = ip_address
        addresses_json = _as_json_list(ip_addresses)
        if addresses_json:
            endpoint.ip_addresses = addresses_json
        macs_json = _as_json_list(mac_addresses)
        if macs_json:
            endpoint.mac_addresses = macs_json
        endpoint.status = "online"
        endpoint.last_seen = _now()
        self.db.commit()
        self.db.refresh(endpoint)
        return endpoint

    def register_current_endpoint(
        self,
        *,
        machine_guid: str,
        hostname: str = "",
        operating_system: str = "",
        os_version: str | None = None,
        architecture: str | None = None,
        agent_version: str | None = None,
        ip_address: str = "",
        ip_addresses: Any = None,
        mac_addresses: Any = None,
    ) -> dict:
        """Agent-facing registration; returns the protected endpoint payload."""
        endpoint = self.ensure_single_endpoint(
            machine_guid=machine_guid,
            hostname=hostname,
            operating_system=operating_system,
            os_version=os_version,
            architecture=architecture,
            agent_version=agent_version,
            ip_address=ip_address,
            ip_addresses=ip_addresses,
            mac_addresses=mac_addresses,
        )
        return self.to_dict(endpoint)

    # ------------------------------------------------------------ touch / life
    def touch(self, *, status: str = "online") -> None:
        endpoint = self.get_current_endpoint()
        if endpoint is None:
            return
        endpoint.status = status if status in ("online", "offline") else "online"
        endpoint.last_seen = _now()
        self.db.commit()

    # ------------------------------------------------------------ helpers
    def validate_ingest_agent(self, agent: Any) -> None:
        """Reject ingestion from an agent that is not the protected endpoint.

        ``agent`` is any subsystem agent ORM row exposing ``machine_guid``.
        """
        endpoint = self.get_current_endpoint()
        if endpoint is None or not endpoint.machine_guid:
            return
        if not getattr(agent, "machine_guid", None):
            return
        if agent.machine_guid != endpoint.machine_guid:
            raise ConflictError(
                "Ingestion rejected: agent does not belong to the protected endpoint.",
                code="single_endpoint_limit",
            )
