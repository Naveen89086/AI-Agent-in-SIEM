"""Network monitoring endpoints (read surfaces for the dashboard).

Live network state collected from enrolled endpoint agents: active
connections, listening sockets, interfaces and aggregate statistics.
"""

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, DbSession
from app.services.telemetry_service import TelemetryService

router = APIRouter()


def _service(db: DbSession) -> TelemetryService:
    return TelemetryService(db)


@router.get("/dashboard", response_model=dict)
def network_dashboard(user: AnalystOrAdmin, db: DbSession) -> dict:
    return _service(db).network_dashboard()


@router.get("/connections", response_model=list[dict])
def network_connections(
    user: AnalystOrAdmin,
    db: DbSession,
    agent_id: str | None = Query(default=None),
    state: str | None = Query(default=None),
    search: str = Query(default=""),
) -> list[dict]:
    return _service(db).network_connections(agent_id=agent_id, state=state, search=search)


@router.get("/listening", response_model=list[dict])
def network_listening(
    user: AnalystOrAdmin,
    db: DbSession,
    agent_id: str | None = Query(default=None),
    search: str = Query(default=""),
) -> list[dict]:
    return _service(db).network_listening(agent_id=agent_id, search=search)


@router.get("/interfaces", response_model=list[dict])
def network_interfaces(
    user: AnalystOrAdmin,
    db: DbSession,
    agent_id: str | None = Query(default=None),
) -> list[dict]:
    return _service(db).network_interfaces(agent_id=agent_id)


@router.get("/statistics", response_model=list[dict])
def network_statistics(
    user: AnalystOrAdmin,
    db: DbSession,
    agent_id: str | None = Query(default=None),
) -> list[dict]:
    return _service(db).network_statistics(agent_id=agent_id)
