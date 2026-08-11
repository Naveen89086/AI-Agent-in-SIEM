"""Vulnerability detection endpoints.

Analyst/admin surfaces (inventory, scans, findings, dashboard) plus the
real-mode agent transport (register, heartbeat, submit inventory).

Scan statuses are always honest: findings that the local CVE database cannot
adjudicate are ``unknown``, and the dashboard exposes ``database_missing`` so
the UI can show "unable to determine" instead of "0 vulnerabilities".
"""

import secrets
from typing import Any

from fastapi import APIRouter, Header, Query, Request
from sqlalchemy import select

from app.api.deps import AdminUser, AnalystOrAdmin, DbSession
from app.core.config import settings
from app.core.exceptions import ForbiddenError, UnauthorizedError, ValidationError
from app.core.security import decode_access_token
from app.models.vulnerability import VulnAgent
from app.services.auth_service import AuthService
from app.services.protected_endpoint_service import ProtectedEndpointService
from app.services.vulnerability_service import VulnerabilityService, _hash_api_key

router = APIRouter()


def _service(db: DbSession) -> VulnerabilityService:
    return VulnerabilityService(db)


def _verify_registration_token(token: str | None) -> None:
    if not token or not secrets.compare_digest(
        token, settings.vulnerability_registration_token or ""
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
    agent = db.execute(select(VulnAgent).where(VulnAgent.agent_code == agent_code)).scalar_one_or_none()
    if agent is None or not agent.api_key_hash or not secrets.compare_digest(
        _hash_api_key(api_key), agent.api_key_hash
    ):
        raise UnauthorizedError("Invalid agent API key", code="invalid_api_key")
    return agent


# ------------------------------------------------------------------- dashboard
@router.get("/dashboard", response_model=dict)
def vuln_dashboard(user: AnalystOrAdmin, db: DbSession) -> dict:
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
    if settings.vulnerability_registration_token:
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


# ---------------------------------------------------------------- inventory
@router.post("/inventory", response_model=dict)
def submit_inventory(
    payload: dict,
    db: DbSession,
    x_api_key: str | None = Header(default=None),
) -> dict:
    """Accept installed-software inventory from an enrolled endpoint agent."""
    try:
        agent_code = str(payload["agent_code"])
        items = list(payload["items"])
    except KeyError:
        raise ValidationError("agent_code and items are required")
    agent = _verify_agent_api_key(agent_code, x_api_key, db)
    ProtectedEndpointService(db).validate_ingest_agent(agent)
    return _service(db).submit_inventory(
        agent_code=agent_code,
        items=items,
        source_label="real_endpoint",
    )


@router.get("/inventory", response_model=list[dict])
def list_inventory(
    user: AnalystOrAdmin,
    db: DbSession,
    agent_id: str | None = Query(default=None),
    search: str = Query(default=""),
    status: str | None = Query(default=None),
) -> list[dict]:
    return _service(db).inventory(agent_id=agent_id, search=search, status=status)


# ---------------------------------------------------------------------- scans
@router.post("/scans", response_model=dict)
def create_scan(
    payload: dict,
    db: DbSession,
    user: AnalystOrAdmin,
) -> dict:
    try:
        agent_id = str(payload["agent_id"])
    except KeyError:
        raise ValidationError("agent_id is required")
    return _service(db).run_scan(agent_id=agent_id, source_label="real_endpoint")


@router.get("/scans", response_model=dict)
def list_scans(
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    agent_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> dict:
    return _service(db).scans(page=page, per_page=per_page, agent_id=agent_id, status=status)


@router.get("/scans/{scan_id}", response_model=dict)
def scan_detail(scan_id: str, user: AnalystOrAdmin, db: DbSession) -> dict:
    return _service(db).scan_detail(scan_id)


@router.get("/scans/{scan_id}/findings", response_model=dict)
def scan_findings(
    scan_id: str,
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    status: str | None = Query(default=None),
    search: str = Query(default=""),
) -> dict:
    return _service(db).scan_findings(
        scan_id=scan_id, page=page, per_page=per_page, status=status, search=search
    )
