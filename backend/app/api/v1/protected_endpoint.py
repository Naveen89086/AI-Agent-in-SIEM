"""Protected endpoint endpoints (single-device model).

``GET /api/v1/protected-endpoint`` returns the status of the one device this
SIEM protects (registered / not registered, online / offline).

``POST /api/v1/protected-endpoint/register`` is the canonical "register this
machine" flow used by the local endpoint agent. It is idempotent for the same
machine and rejects a second, different machine with ``single_endpoint_limit``
when the deployment is capped at one device.
"""

import json
import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Header, Request

from app.api.deps import AnalystOrAdmin, DbSession
from app.core.config import settings
from app.core.exceptions import ForbiddenError, UnauthorizedError, ValidationError
from app.core.security import decode_access_token
from app.services.auth_service import AuthService
from app.services.protected_endpoint_service import ProtectedEndpointService

router = APIRouter()


def _service(db: DbSession) -> ProtectedEndpointService:
    return ProtectedEndpointService(db)


def _optional_admin(request: Request, db) -> Any:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    payload = decode_access_token(auth.split(" ", 1)[1].strip())
    user = AuthService(db).resolve_token_user(payload["sub"])
    if user.role != "admin":
        raise ForbiddenError("Registration requires an admin account")
    return user


@router.get("", response_model=dict)
def protected_endpoint_status(user: AnalystOrAdmin, db: DbSession) -> dict:
    """Status of the single protected endpoint (registered/online/offline)."""
    return _service(db).status_payload()


@router.get("/identity", response_model=dict)
def protected_endpoint_identity(user: AnalystOrAdmin, db: DbSession) -> dict:
    """Stable identity of the protected endpoint (machine fingerprint only)."""
    endpoint = _service(db).get_current_endpoint()
    if endpoint is None:
        return {"registered": False, "machine_guid": None, "hostname": None}
    return {
        "registered": True,
        "machine_guid": endpoint.machine_guid,
        "hostname": endpoint.hostname,
    }


@router.post("/register", response_model=dict)
def register_protected_endpoint(
    payload: dict,
    db: DbSession,
    request: Request,
    x_registration_token: str | None = Header(default=None),
) -> dict:
    """Register (or update) the local protected endpoint.

    Requires the shared registration token (``protected_endpoint_registration_token``)
    or an admin JWT. Same machine: idempotent update. Different machine when capped:
    ``single_endpoint_limit``.
    """
    if settings.protected_endpoint_registration_token:
        if not x_registration_token or not secrets.compare_digest(
            x_registration_token, settings.protected_endpoint_registration_token
        ):
            raise UnauthorizedError(
                "Invalid registration token", code="invalid_registration_token"
            )
    else:
        _optional_admin(request, db)

    try:
        machine_guid = str(payload["machine_guid"])
    except KeyError:
        raise ValidationError("machine_guid is required")

    # Normalize the address lists from either a list or a JSON/CSV string.
    def _norm(value):
        if isinstance(value, str):
            try:
                return json.loads(value)
            except (ValueError, TypeError):
                return value
        return value

    data = _service(db).register_current_endpoint(
        machine_guid=machine_guid,
        hostname=str(payload.get("hostname", "")),
        operating_system=str(payload.get("operating_system", "")),
        os_version=payload.get("os_version"),
        architecture=payload.get("architecture"),
        agent_version=payload.get("agent_version"),
        ip_address=str(payload.get("ip_address", "")),
        ip_addresses=_norm(payload.get("ip_addresses")),
        mac_addresses=_norm(payload.get("mac_addresses")),
    )
    return {"registered": True, "endpoint": data}
