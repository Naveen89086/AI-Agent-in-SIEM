"""Process + Service monitoring endpoints.

Live process table (with tree relationships) and Windows service state from
enrolled endpoint agents, plus the combined summary for the dashboard.
"""

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, DbSession
from app.services.telemetry_service import TelemetryService

router = APIRouter()


def _service(db: DbSession) -> TelemetryService:
    return TelemetryService(db)


@router.get("/summary", response_model=dict)
def process_summary(user: AnalystOrAdmin, db: DbSession) -> dict:
    return _service(db).process_summary()


@router.get("", response_model=list[dict])
def list_processes(
    user: AnalystOrAdmin,
    db: DbSession,
    agent_id: str | None = Query(default=None),
    search: str = Query(default=""),
    status: str = Query(default="running"),
) -> list[dict]:
    return _service(db).processes(agent_id=agent_id, search=search, status=status)


@router.get("/{pid}", response_model=dict)
def process_detail(
    pid: int,
    user: AnalystOrAdmin,
    db: DbSession,
    agent_id: str | None = Query(default=None),
) -> dict:
    return _service(db).process_detail(pid, agent_id=agent_id)


@router.get("/{pid}/tree", response_model=list[dict])
def process_tree(
    pid: int,
    user: AnalystOrAdmin,
    db: DbSession,
    agent_id: str | None = Query(default=None),
) -> list[dict]:
    return _service(db).process_tree(pid, agent_id=agent_id)
