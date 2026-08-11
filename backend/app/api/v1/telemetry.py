"""Telemetry agent transport endpoints.

Enrollment (register/heartbeat) and live-state snapshot ingestion for the
network + process/service monitoring modules. The snapshot endpoint accepts
real Windows telemetry from enrolled endpoint agents, upserts the live-state
tables and forwards lifecycle transitions through the generic ingest pipeline
so the correlation/detection engine sees them.
"""

import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Header, Request
from sqlalchemy import select

from app.api.deps import AnalystOrAdmin, DbSession
from app.core.config import settings
from app.core.exceptions import ForbiddenError, UnauthorizedError, ValidationError
from app.core.security import decode_access_token
from app.models.telemetry import TelemetryAgent
from app.pipeline.bus import build_event_bus
from app.schemas.ingest import IngestRequest, IngestResult, RawEventIn
from app.services.auth_service import AuthService
from app.services.ingest_service import IngestService
from app.services.protected_endpoint_service import ProtectedEndpointService
from app.services.telemetry_service import TelemetryService, _hash_api_key

router = APIRouter()


def _service(db: DbSession) -> TelemetryService:
    return TelemetryService(db)


def _bus(request: Request):
    bus = getattr(request.app.state, "event_bus", None)
    if bus is None:
        bus = build_event_bus()
        request.app.state.event_bus = bus
    return bus


def _verify_registration_token(token: str | None) -> None:
    if not token or not secrets.compare_digest(
        token, settings.telemetry_registration_token or ""
    ):
        raise UnauthorizedError(
            "Invalid registration token", code="invalid_registration_token"
        )


def _optional_admin(request: Request, db) -> Any:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    payload = decode_access_token(auth.split(" ", 1)[1].strip())
    user = AuthService(db).resolve_token_user(payload["sub"])
    if user.role != "admin":
        raise ForbiddenError("Agent registration requires an admin account")
    return user


def _verify_agent_api_key(agent_code: str, api_key: str | None, db):
    """Authenticate an agent API key; returns the agent row."""
    if not api_key:
        raise UnauthorizedError("Missing agent API key", code="invalid_api_key")
    agent = db.execute(select(TelemetryAgent).where(TelemetryAgent.agent_code == agent_code)).scalar_one_or_none()
    if agent is None or not agent.api_key_hash or not secrets.compare_digest(
        _hash_api_key(api_key), agent.api_key_hash
    ):
        raise UnauthorizedError("Invalid agent API key", code="invalid_api_key")
    return agent


# ----------------------------------------------------------------------- agents
@router.post("/agents/register", response_model=dict)
def register_agent(
    payload: dict,
    db: DbSession,
    request: Request,
    x_registration_token: str | None = Header(default=None),
) -> dict:
    if settings.telemetry_registration_token:
        _verify_registration_token(x_registration_token)
        reg_token = x_registration_token
    else:
        _optional_admin(request, db)
        reg_token = None
    try:
        agent_code = str(payload["agent_code"])
    except KeyError:
        raise ValidationError("agent_code is required")
    # Single-device enforcement: this deployment protects one endpoint. The
    # registering machine becomes (or must match) the protected endpoint.
    ProtectedEndpointService(db).ensure_single_endpoint(
        machine_guid=str(payload.get("machine_guid", "")),
        hostname=str(payload.get("hostname", "")),
        operating_system=str(payload.get("operating_system", "")),
        ip_address=str(payload.get("ip_address", "")),
        agent_version=str(payload.get("version", "")),
    )
    return _service(db).register_agent(
        agent_code=agent_code,
        hostname=str(payload.get("hostname", "")),
        ip_address=str(payload.get("ip_address", "")),
        operating_system=str(payload.get("operating_system", "")),
        platform=str(payload.get("platform", "windows")),
        version=str(payload.get("version", "1.0.0")),
        machine_guid=str(payload.get("machine_guid", "")),
        registration_token=reg_token,
    )


@router.post("/agents/{agent_code}/heartbeat", response_model=dict)
def agent_heartbeat(
    agent_code: str,
    payload: dict,
    db: DbSession,
    x_api_key: str | None = Header(default=None),
) -> dict:
    agent = _verify_agent_api_key(agent_code, x_api_key, db)
    ProtectedEndpointService(db).validate_ingest_agent(agent)
    return _service(db).heartbeat(
        agent_code,
        api_key=x_api_key or "",
        status=str(payload.get("status", "online")),
    )


@router.get("/agents", response_model=list[dict])
def list_agents(user: AnalystOrAdmin, db: DbSession) -> list[dict]:
    return _service(db).agents()


# ----------------------------------------------------------------------- ingest
@router.post("/ingest", response_model=dict)
async def ingest_snapshot(
    payload: dict,
    request: Request,
    db: DbSession,
    x_api_key: str | None = Header(default=None),
) -> dict:
    """Accept a network/process/service snapshot from an enrolled agent."""
    try:
        agent_code = str(payload["agent_code"])
    except KeyError:
        raise ValidationError("agent_code is required")
    agent = _verify_agent_api_key(agent_code, x_api_key, db)
    ProtectedEndpointService(db).validate_ingest_agent(agent)

    # Demo payloads are labeled demo; the agent is never the final authority,
    # the server tags rows so they cannot be mistaken for real endpoint data.
    demo = bool(payload.get("demo"))
    result = _service(db).ingest_snapshot(
        agent_code=agent_code,
        payload=payload,
        source_label="demo" if demo else "real_endpoint",
    )
    transitions = result.pop("transitions", [])

    if transitions:
        request_payload = IngestRequest(events=[RawEventIn(**event) for event in transitions])
        ingest_result: IngestResult = await IngestService(db, _bus(request)).ingest(request_payload)
        result["events"] = {
            "accepted": ingest_result.accepted,
            "failed": ingest_result.failed,
            "errors": ingest_result.errors,
        }

    result["transitions"] = len(transitions)
    return result
