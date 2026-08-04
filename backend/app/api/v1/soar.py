"""SOAR endpoints (function 10 - automated response)."""

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, DbSession
from app.api.responses import Page, paginate
from app.core.config import settings
from app.pipeline.playbooks import load_playbook_set
from app.schemas.soar import SoarActionRead
from app.services.soar_service import SoarService

router = APIRouter()


def _service(db):
    return SoarService(db)


def _playbook_out(playbook) -> dict:
    return {
        "id": playbook.id,
        "name": playbook.name,
        "description": playbook.description,
        "trigger": playbook.trigger,
        "actions": playbook.actions,
        "enabled": playbook.enabled,
    }


@router.get("/playbooks", response_model=list[dict])
def list_playbooks(user: AnalystOrAdmin, db: DbSession) -> list[dict]:
    return [_playbook_out(p) for p in _service(db).playbooks.list_playbooks()]


@router.post("/playbooks/{playbook_id}/execute", response_model=dict)
async def execute_playbook(
    playbook_id: str,
    payload: dict,
    user: AnalystOrAdmin,
    db: DbSession,
) -> dict:
    records = await _service(db).execute(playbook_id, payload.get("alert", {}))
    statuses = [r.status for r in records]
    return {
        "playbook_id": playbook_id,
        "actions": len(records),
        "success": statuses.count("success"),
        "failed": statuses.count("failed"),
        "skipped": statuses.count("skipped"),
        "last_action_id": records[-1].id if records else None,
    }


@router.get("/actions", response_model=Page[SoarActionRead])
def list_actions(
    user: AnalystOrAdmin,
    db: DbSession,
    playbook_id: str | None = Query(default=None),
    alert_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    rows, total = _service(db).list_actions(
        playbook_id=playbook_id, alert_id=alert_id, status=status, limit=limit
    )
    return paginate(rows[offset:], total, offset, limit)


@router.get("/status", response_model=dict)
def soar_status(user: AnalystOrAdmin) -> dict:
    return {
        "destructive_actions_enabled": settings.soar_allow_destructive,
        "playbooks_dir": settings.soar_playbooks_dir,
        "playbook_count": len(load_playbook_set().list_playbooks()),
    }
