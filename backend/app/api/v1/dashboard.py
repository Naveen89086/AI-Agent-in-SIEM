"""Dashboard endpoints (M8 backend support).

Aggregated telemetry for the React overview page: KPIs, event/alert time
series, severity distribution, top rules and top sources.
"""

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, DbSession
from app.services.dashboard_service import DashboardService

router = APIRouter()


@router.get("/summary", response_model=dict)
def dashboard_summary(user: AnalystOrAdmin, db: DbSession) -> dict:
    return DashboardService(db).summary()


@router.get("/timeseries", response_model=dict)
def dashboard_timeseries(
    user: AnalystOrAdmin,
    db: DbSession,
    hours: int = Query(default=24, ge=1, le=24 * 30),
    bucket_minutes: int = Query(default=60, ge=1, le=1440),
) -> dict:
    return DashboardService(db).timeseries(hours=hours, bucket_minutes=bucket_minutes)


@router.get("/top-rules", response_model=list[dict])
def dashboard_top_rules(
    user: AnalystOrAdmin,
    db: DbSession,
    limit: int = Query(default=10, ge=1, le=50),
) -> list[dict]:
    return DashboardService(db).top_rules(limit)


@router.get("/top-sources", response_model=list[dict])
def dashboard_top_sources(
    user: AnalystOrAdmin,
    db: DbSession,
    limit: int = Query(default=10, ge=1, le=50),
) -> list[dict]:
    return DashboardService(db).top_sources(limit)


@router.get("/recent-alerts", response_model=list[dict])
def dashboard_recent_alerts(
    user: AnalystOrAdmin,
    db: DbSession,
    limit: int = Query(default=10, ge=1, le=50),
) -> list[dict]:
    return DashboardService(db).recent_alerts(limit)
