"""Service monitoring endpoints (live Windows service state)."""

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, DbSession
from app.services.telemetry_service import TelemetryService

router = APIRouter()


def _service(db: DbSession) -> TelemetryService:
    return TelemetryService(db)


@router.get("", response_model=list[dict])
def list_services(
    user: AnalystOrAdmin,
    db: DbSession,
    agent_id: str | None = Query(default=None),
    search: str = Query(default=""),
    state: str | None = Query(default=None),
) -> list[dict]:
    return _service(db).services(agent_id=agent_id, search=search, state=state)


@router.get("/{name}", response_model=dict)
def service_detail(
    name: str,
    user: AnalystOrAdmin,
    db: DbSession,
    agent_id: str | None = Query(default=None),
) -> dict:
    return _service(db).service_detail(name, agent_id=agent_id)
