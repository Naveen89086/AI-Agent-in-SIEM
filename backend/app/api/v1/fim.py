"""File Integrity Monitoring (syscheck) endpoints.

Wazuh-style FIM backend: dashboard breakdowns, 30-minute event timeline,
file inventory and the paginated events table.

Real-mode agent transport (mirrors the SCA agent contract):

- ``POST /api/v1/fim/agents/register`` — enroll a new endpoint agent using the
  shared registration token (or an admin JWT) and receive its API key.
- ``POST /api/v1/fim/agents/{code}/heartbeat`` — agent keep-alive.
- ``POST /api/v1/fim/ingest`` — authenticated SHA-256 evidence submission.
  The server reclassifies every event against its own baseline before storing.
"""

from typing import Any

from fastapi import APIRouter, Header, Query, Request

from app.api.deps import AnalystOrAdmin, DbSession
from app.core.config import settings
from app.core.exceptions import UnauthorizedError, ValidationError
from app.schemas.fim import FimIngestRequest
from app.services.fim_service import FimService
from app.services.protected_endpoint_service import ProtectedEndpointService
from app.services.syscheck_service import SyscheckService

router = APIRouter()


# ------------------------------------------------------------------ query APIs
@router.get("/agents", response_model=list[dict])
def fim_agents(user: AnalystOrAdmin, db: DbSession) -> list[dict]:
    return FimService(db).agents()


@router.get("/summary", response_model=dict)
def fim_summary(
    user: AnalystOrAdmin,
    db: DbSession,
    agent_code: str = Query(default="001"),
) -> dict:
    return SyscheckService(db).summary(agent_code)


@router.get("/timeline", response_model=dict)
def fim_timeline(
    user: AnalystOrAdmin,
    db: DbSession,
    hours: int = Query(default=24, ge=1, le=24 * 7),
    bucket_minutes: int = Query(default=30, ge=1, le=1440),
    agent_code: str = Query(default="001"),
) -> dict:
    return SyscheckService(db).timeline(hours, bucket_minutes, agent_code)


@router.get("/files", response_model=list[dict])
def fim_files(
    user: AnalystOrAdmin,
    db: DbSession,
    search: str = Query(default=""),
    agent_code: str = Query(default="001"),
) -> list[dict]:
    return SyscheckService(db).files(agent_code, search)


@router.get("/events", response_model=dict)
def fim_events(
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=15, ge=1, le=200),
    search: str = Query(default=""),
    agent_code: str = Query(default="001"),
) -> dict:
    return SyscheckService(db).events(page, per_page, search, agent_code)


# ---------------------------------------------------------------- agent transport
@router.post("/agents/register", response_model=dict)
def fim_register_agent(
    payload: dict,
    db: DbSession,
    request: Request,
    x_registration_token: str | None = Header(default=None),
) -> dict:
    """Enroll an endpoint agent; returns a one-time per-agent API key."""
    if settings.fim_registration_token:
        if not x_registration_token or not __import__("secrets").compare_digest(
            x_registration_token, settings.fim_registration_token
        ):
            raise UnauthorizedError(
                "Invalid registration token", code="invalid_registration_token"
            )
        reg_token = x_registration_token
    else:
        _optional_admin(request, db)
        reg_token = None
    try:
        agent_code = str(payload["agent_code"])
    except KeyError:
        raise ValidationError("agent_code is required")
    ProtectedEndpointService(db).ensure_single_endpoint(
        machine_guid=str(payload.get("machine_guid", "")),
        hostname=str(payload.get("hostname", "")),
        operating_system=str(payload.get("os_name", "")),
        ip_address=str(payload.get("ip_address", "")),
        agent_version=str(payload.get("version", "")),
    )
    return FimService(db).register_agent(
        agent_code=agent_code,
        hostname=str(payload.get("hostname", "")),
        ip_address=str(payload.get("ip_address", "")),
        os_name=str(payload.get("os_name", "")),
        platform=str(payload.get("platform", "windows")),
        version=str(payload.get("version", "1.0.0")),
        machine_guid=str(payload.get("machine_guid", "")),
        registration_token=reg_token,
    )


@router.post("/agents/{agent_code}/heartbeat", response_model=dict)
def fim_agent_heartbeat(
    agent_code: str,
    payload: dict,
    db: DbSession,
    x_api_key: str | None = Header(default=None),
) -> dict:
    return FimService(db).heartbeat(
        agent_code,
        api_key=x_api_key or "",
        status=str(payload.get("status", "online")),
    )


@router.post("/ingest", response_model=dict)
def fim_ingest(
    payload: FimIngestRequest,
    db: DbSession,
    x_api_key: str | None = Header(default=None),
) -> dict:
    return FimService(db).ingest(payload.agent_code, x_api_key or "", payload)


def _optional_admin(request: Request, db) -> Any:
    from app.core.security import decode_access_token
    from app.models.user import User, UserRole
    from app.services.auth_service import AuthService

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise UnauthorizedError("Missing registration token or admin JWT")
    payload = decode_access_token(auth.split(" ", 1)[1].strip())
    user = AuthService(db).resolve_token_user(payload["sub"])
    if user.role != UserRole.admin:
        raise UnauthorizedError("Agent registration requires an admin account")
    return user
