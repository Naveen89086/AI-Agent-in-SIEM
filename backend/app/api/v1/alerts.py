"""Alert management endpoints (function 5)."""

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, DbSession
from app.models.alert import Alert
from app.schemas.alert import AlertList, AlertRead, AlertSummary, AlertUpdate
from app.services.alert_service import AlertService

router = APIRouter()


@router.get("", response_model=AlertList)
def list_alerts(
    user: AnalystOrAdmin,
    db: DbSession,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> AlertList:
    items, total = AlertService(db).list(
        status=status, severity=severity, rule_id=rule_id, offset=offset, limit=limit
    )
    return AlertList(items=items, total=total, offset=offset, limit=limit)


@router.get("/summary", response_model=AlertSummary)
def alert_summary(user: AnalystOrAdmin, db: DbSession) -> dict:
    return AlertService(db).summary()


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(alert_id: str, user: AnalystOrAdmin, db: DbSession) -> Alert:
    return AlertService(db).get(alert_id)


@router.patch("/{alert_id}", response_model=AlertRead)
def update_alert(alert_id: str, payload: AlertUpdate, user: AnalystOrAdmin, db: DbSession) -> Alert:
    service = AlertService(db)
    return service.update(
        alert_id,
        status=payload.status,
        assignee=payload.assignee,
        notes=payload.notes,
    )
