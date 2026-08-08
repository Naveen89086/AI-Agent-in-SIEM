"""Configuration Assessment (CIS benchmark) endpoints.

Wazuh-style SCAP backend: policy list, per-agent scan summary and the
paginated checks table with search.
"""

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, DbSession
from app.services.policy_service import PolicyService

router = APIRouter()


@router.get("", response_model=list[dict])
def policy_list(user: AnalystOrAdmin, db: DbSession) -> list[dict]:
    return PolicyService(db).policies()


@router.get("/{policy_id}", response_model=dict)
def policy_detail(user: AnalystOrAdmin, db: DbSession, policy_id: str) -> dict:
    return PolicyService(db).policy_detail(policy_id)


@router.get("/{policy_id}/summary", response_model=dict)
def policy_summary(
    user: AnalystOrAdmin,
    db: DbSession,
    policy_id: str,
    agent_code: str = Query(default="001"),
) -> dict:
    return PolicyService(db).policy_summary(policy_id, agent_code)


@router.get("/{policy_id}/checks", response_model=dict)
def policy_checks(
    user: AnalystOrAdmin,
    db: DbSession,
    policy_id: str,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=10, ge=1, le=200),
    search: str = Query(default=""),
) -> dict:
    return PolicyService(db).policy_checks(policy_id, page, per_page, search)
