"""Security Configuration Assessment (SCA) endpoints.

Agents registry + heartbeat (agent transport), scan lifecycle, scan history,
events, drift, AI analysis and the human-approved remediation workflow.
"""

import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Header, Query, Request
from sqlalchemy import select

from app.api.deps import AdminUser, AnalystOrAdmin, DbSession
from app.core.config import settings
from app.core.exceptions import ForbiddenError, UnauthorizedError, ValidationError
from app.core.security import decode_access_token
from app.models.sca import Agent
from app.services.auth_service import AuthService
from app.services.sca_service import ScaService, _hash_api_key

router = APIRouter()


def _service(db: DbSession) -> ScaService:
    return ScaService(db)


def _verify_registration_token(token: str | None) -> None:
    if not token or not secrets.compare_digest(token, settings.sca_registration_token or ""):
        raise UnauthorizedError(
            "Invalid registration token", code="invalid_registration_token"
        )


def _optional_admin(request: Request, db) -> Any:
    """Return the admin user from a JWT, or None when no token is present."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    payload = decode_access_token(auth.split(" ", 1)[1].strip())
    user = AuthService(db).resolve_token_user(payload["sub"])
    if user.role != "admin":
        raise ForbiddenError("Agent registration requires an admin account")
    return user


def _verify_agent_api_key(agent_code: str, api_key: str | None, db) -> None:
    if not api_key:
        raise UnauthorizedError("Missing agent API key", code="invalid_api_key")
    agent = db.execute(select(Agent).where(Agent.agent_code == agent_code)).scalar_one_or_none()
    if agent is None or not agent.api_key_hash or not secrets.compare_digest(
        _hash_api_key(api_key), agent.api_key_hash
    ):
        raise UnauthorizedError("Invalid agent API key", code="invalid_api_key")


# --------------------------------------------------------------------- agents
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
    """Register a new agent using the shared registration token (or an admin JWT)."""
    if settings.sca_registration_token:
        _verify_registration_token(x_registration_token)
        reg_token = x_registration_token
    else:
        _optional_admin(request, db)
        reg_token = None
    try:
        agent_code = str(payload["agent_code"])
    except KeyError:
        raise ValidationError("agent_code is required")
    return _service(db).register_agent(
        agent_code=agent_code,
        hostname=str(payload.get("hostname", "")),
        operating_system=str(payload.get("operating_system", "")),
        platform=str(payload.get("platform", "windows")),
        version=str(payload.get("version", "1.0.0")),
        registration_token=reg_token,
    )


@router.post("/agents/{agent_code}/heartbeat", response_model=dict)
def agent_heartbeat(
    agent_code: str,
    payload: dict,
    db: DbSession,
    x_api_key: str | None = Header(default=None),
) -> dict:
    _verify_agent_api_key(agent_code, x_api_key, db)
    return _service(db).heartbeat(
        agent_code,
        api_key=x_api_key or "",
        status=str(payload.get("status", "online")),
    )


@router.get("/agents/{agent_code}/jobs", response_model=dict)
def agent_jobs(
    agent_code: str,
    db: DbSession,
    x_api_key: str | None = Header(default=None),
) -> dict:
    """Return the next evidence-collection job waiting for an endpoint agent."""
    _verify_agent_api_key(agent_code, x_api_key, db)
    return _service(db).pending_job(agent_code)


@router.post("/scans/{scan_id}/evidence", response_model=dict)
def submit_evidence(
    scan_id: str,
    payload: dict,
    db: DbSession,
    x_api_key: str | None = Header(default=None),
) -> dict:
    """Accept collected evidence from an endpoint agent and finalize the scan."""
    try:
        agent_code = str(payload["agent_code"])
        items = list(payload["items"])
    except KeyError:
        raise ValidationError("agent_code and items are required")
    _verify_agent_api_key(agent_code, x_api_key, db)
    return _service(db).submit_evidence(
        scan_id=scan_id, agent_code=agent_code, items=items
    )


# ---------------------------------------------------------------------- scans
@router.post("/scans", response_model=dict)
def create_scan(
    payload: dict,
    user: AnalystOrAdmin,
    db: DbSession,
) -> dict:
    try:
        policy_id = str(payload["policy_id"])
        agent_id = str(payload["agent_id"])
    except KeyError:
        raise ValidationError("policy_id and agent_id are required")
    return _service(db).create_scan(policy_id=policy_id, agent_id=agent_id)


@router.get("/scans", response_model=dict)
def list_scans(
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    agent_id: str | None = Query(default=None),
    policy_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> dict:
    return _service(db).scans(
        page=page, per_page=per_page, agent_id=agent_id, policy_id=policy_id, status=status
    )


@router.get("/scans/{scan_id}", response_model=dict)
def scan_detail(scan_id: str, user: AnalystOrAdmin, db: DbSession) -> dict:
    return _service(db).scan_detail(scan_id)


@router.get("/scans/{scan_id}/results", response_model=dict)
def scan_results(
    scan_id: str,
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    result: str | None = Query(default=None),
    search: str = Query(default=""),
) -> dict:
    return _service(db).scan_results(
        scan_id=scan_id, page=page, per_page=per_page, result=result, search=search
    )


# -------------------------------------------------------------- events/drifts
@router.get("/events", response_model=dict)
def list_events(
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    agent_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
) -> dict:
    return _service(db).events(
        page=page, per_page=per_page, agent_id=agent_id, event_type=event_type
    )


@router.get("/drifts", response_model=dict)
def list_drifts(
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    agent_id: str | None = Query(default=None),
    policy_id: str | None = Query(default=None),
) -> dict:
    return _service(db).drifts(
        page=page, per_page=per_page, agent_id=agent_id, policy_id=policy_id
    )


@router.get("/dashboard", response_model=dict)
def sca_dashboard(user: AnalystOrAdmin, db: DbSession) -> dict:
    return _service(db).dashboard()


# ------------------------------------------------------------------ analysis
@router.post("/checks/{check_result_id}/analysis", response_model=dict)
async def analyze_check(
    check_result_id: str,
    user: AnalystOrAdmin,
    db: DbSession,
    force: bool = Query(default=False),
) -> dict:
    return await _service(db).analyze_check(check_result_id, force=force)


@router.get("/analyses", response_model=list[dict])
def list_sca_analyses(
    user: AnalystOrAdmin,
    db: DbSession,
    check_result_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    return _service(db).list_analyses(check_result_id=check_result_id, limit=limit)


# --------------------------------------------------------------- remediation
@router.get("/remediation", response_model=dict)
def list_remediation(
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    status: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
) -> dict:
    return _service(db).remediations(
        page=page, per_page=per_page, status=status, agent_id=agent_id
    )


@router.post("/remediation", response_model=dict)
def request_remediation(
    payload: dict,
    user: AnalystOrAdmin,
    db: DbSession,
) -> dict:
    try:
        check_result_id = str(payload["check_result_id"])
    except KeyError:
        raise ValidationError("check_result_id is required")
    return _service(db).request_remediation(
        check_result_id=check_result_id,
        description=payload.get("description"),
        user=user,
    )


@router.post("/remediation/{remediation_id}/approve", response_model=dict)
def approve_remediation(
    remediation_id: str,
    user: AdminUser,
    db: DbSession,
) -> dict:
    return _service(db).approve_remediation(remediation_id, user)


@router.post("/remediation/{remediation_id}/reject", response_model=dict)
def reject_remediation(
    remediation_id: str,
    user: AdminUser,
    db: DbSession,
) -> dict:
    return _service(db).reject_remediation(remediation_id, user)


@router.post("/remediation/{remediation_id}/execute", response_model=dict)
def execute_remediation(
    remediation_id: str,
    user: AdminUser,
    db: DbSession,
) -> dict:
    return _service(db).execute_remediation(remediation_id, user)
