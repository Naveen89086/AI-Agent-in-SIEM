"""Threat hunting endpoints.

Built-in hunt definitions, executed hunt history with persisted match
snapshots, and AI analysis of hunt results.
"""

from datetime import datetime

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, DbSession
from app.services.threat_hunting_service import ThreatHuntingService

router = APIRouter()


def _service(db: DbSession) -> ThreatHuntingService:
    return ThreatHuntingService(db)


@router.get("/definitions", response_model=list[dict])
def hunt_definitions(user: AnalystOrAdmin, db: DbSession) -> list[dict]:
    return _service(db).definitions()


@router.get("/definitions/{hunt_id}", response_model=dict)
def hunt_definition(hunt_id: str, user: AnalystOrAdmin, db: DbSession) -> dict:
    return _service(db).definition(hunt_id)


@router.get("/queries", response_model=dict)
def hunt_queries(
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
    hunt_id: str | None = Query(default=None),
) -> dict:
    return _service(db).queries(page=page, per_page=per_page, hunt_id=hunt_id)


@router.get("/queries/{query_id}", response_model=dict)
def hunt_query_detail(query_id: str, user: AnalystOrAdmin, db: DbSession) -> dict:
    return _service(db).query_detail(query_id)


@router.get("/queries/{query_id}/results", response_model=dict)
def hunt_query_results(
    query_id: str,
    user: AnalystOrAdmin,
    db: DbSession,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=200),
) -> dict:
    return _service(db).query_results(query_id=query_id, page=page, per_page=per_page)


@router.post("/queries/{hunt_id}/run", response_model=dict)
async def run_hunt(
    hunt_id: str,
    user: AnalystOrAdmin,
    db: DbSession,
    time_from: datetime | None = Query(default=None),
    time_to: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    return await _service(db).run_hunt(
        hunt_id=hunt_id,
        time_from=time_from,
        time_to=time_to,
        created_by=user.username,
        limit=limit,
    )


@router.post("/queries/{query_id}/analyze", response_model=dict)
async def analyze_hunt(
    query_id: str,
    user: AnalystOrAdmin,
    db: DbSession,
    force: bool = Query(default=False),
) -> dict:
    return await _service(db).analyze(query_id, force=force)
