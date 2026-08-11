"""Indicators of Compromise (IOC) endpoints.

Analyst/admin surfaces (indicator corpus, lookups, observations, matches) plus
the real-mode agent transport (register, heartbeat, ingest observations).

Lookup honesty rules are enforced in the service: ``unknown`` is the default
verdict; online providers are only queried when configured; a lookup never
returns a fabricated reputation.
"""

import secrets
from typing import Any

from fastapi import APIRouter, Header, Query, Request
from sqlalchemy import select

from app.api.deps import AdminUser, AnalystOrAdmin, DbSession
from app.core.config import settings
from app.core.exceptions import ForbiddenError, UnauthorizedError, ValidationError
from app.core.security import decode_access_token
from app.models.ioc import IocAgent
from app.services.auth_service import AuthService
from app.services.ioc_service import IocService, _hash_api_key
from app.services.protected_endpoint_service import ProtectedEndpointService

router = APIRouter()


def _service(db: DbSession) -> IocService:
    return IocService(db)


def _verify_registration_token(token: str | None) -> None:
    if not token or not secrets.compare_digest(token, settings.ioc_registration_token or ""):
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
    agent = db.execute(select(IocAgent).where(IocAgent.agent_code == agent_code)).scalar_one_or_none()
    if agent is None or not agent.api_key_hash or not secrets.compare_digest(
        _hash_api_key(api_key), agent.api_key_hash
    ):
        raise UnauthorizedError("Invalid agent API key", code="invalid_api_key")
    return agent


# ------------------------------------------------------------------- dashboard
@router.get("/dashboard", response_model=dict)
def ioc_dashboard(user: AnalystOrAdmin, db: DbSession) -> dict:
    return _service(db).dashboard()


# ----------------------------------------------------------------------- agents
@router.get("/agents", response_model=list[dict])
def list_agents(user: AnalystOrAdmin, db: DbSession) -> list[dict]:
    return _service(db).agents()


@router.post("/agents/register", response_model=dict)
def register_agent(
    payload: dict,
    db: DbSession,
    request: Request,
    x_registration_token: str | None = Header(default=None),
) -> dict:
    if settings.ioc_registration_token:
        _verify_registration_token(x_registration_token)
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


# ---------------------------------------------------------------- indicators
@router.post("/indicators/sync", response_model=dict)
def sync_indicators(user: AdminUser, db: DbSession) -> dict:
    return _service(db).sync_indicators()


@router.get("/indicators", response_model=dict)
def list_indicators(
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    indicator_type: str | None = Query(default=None),
    search: str = Query(default=""),
) -> dict:
    return _service(db).indicators(
        page=page,
        per_page=per_page,
        indicator_type=indicator_type,
        search=search,
    )


@router.get("/lookup", response_model=dict)
async def lookup_indicator(
    user: AnalystOrAdmin,
    db: DbSession,
    type: str = Query(..., description="ipv4|ipv6|domain|url|filehash|email|registry"),
    value: str = Query(..., max_length=512),
) -> dict:
    return await _service(db).lookup(type, value)


# -------------------------------------------------------------- observations
@router.post("/ingest", response_model=dict)
def ingest_observations(
    payload: dict,
    db: DbSession,
    x_api_key: str | None = Header(default=None),
) -> dict:
    """Accept observed indicators from an endpoint agent.

    The agent authenticates with its per-agent API key; the server computes
    every verdict deterministically and stores the observations + matches.
    """
    try:
        agent_code = str(payload["agent_code"])
        observations = list(payload["observations"])
    except KeyError:
        raise ValidationError("agent_code and observations are required")
    agent = _verify_agent_api_key(agent_code, x_api_key, db)
    ProtectedEndpointService(db).validate_ingest_agent(agent)
    return _service(db).ingest_observation(
        agent_code=agent_code,
        observations=observations,
        source_label="real_endpoint",
    )


@router.get("/observations", response_model=dict)
def list_observations(
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    agent_id: str | None = Query(default=None),
    verdict: str | None = Query(default=None),
) -> dict:
    return _service(db).observations(page=page, per_page=per_page, agent_id=agent_id, verdict=verdict)


@router.get("/matches", response_model=dict)
def list_matches(
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    verdict: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
) -> dict:
    return _service(db).matches(page=page, per_page=per_page, verdict=verdict, agent_id=agent_id)
