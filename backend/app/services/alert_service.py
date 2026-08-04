"""Alert service (function 5 - real-time alerting).

Consumes detections and consolidates them into managed alerts:

  - dedup:      same rule + grouping -> one alert, count incremented
  - escalation: repeated detections raise severity (and trigger re-notify)
  - lifecycle:  open -> acknowledged -> resolved | false_positive
  - channels:   webhook / email notified on new or escalated alerts
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, ValidationError
from app.models.alert import Alert, AlertStatus
from app.pipeline.bus import EventBus, Topics
from app.pipeline.detection import Detection
from app.services.notifications import SEVERITY_RANK, Notifier, build_notifiers

log = logging.getLogger("siem.alerts")

ESCALATION_STEPS = ((3, 1), (8, 2))  # (count, rank steps above base)


def _escalate(base_severity: str, count: int) -> str:
    rank = SEVERITY_RANK.get(base_severity, 2)
    steps = 0
    for threshold, step in ESCALATION_STEPS:
        if count >= threshold:
            steps = max(steps, step)
    return _RANK_TO_SEVERITY[min(rank + steps, SEVERITY_RANK["critical"])]


_RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}


class AlertService:
    def __init__(
        self,
        db: Session,
        bus: EventBus | None = None,
        notifiers: list[Notifier] | None = None,
    ) -> None:
        self.db = db
        self.bus = bus
        self.notifiers = notifiers if notifiers is not None else build_notifiers()

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def dedup_key(rule_id: str, grouping: dict[str, Any] | None) -> str:
        raw = json.dumps(grouping or {}, sort_keys=True)
        digest = hashlib.sha256(f"{rule_id}:{raw}".encode("utf-8")).hexdigest()[:24]
        return f"{rule_id}:{digest}"

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    # --------------------------------------------------------------- creation
    def ingest_detection(self, detection: Detection) -> tuple[Alert, bool]:
        """Create-or-update the alert for a detection.

        Returns (alert, escalated) where escalated indicates the alert's
        severity crossed a threshold on this update.
        """
        grouping = detection.grouping or {}
        key = self.dedup_key(detection.rule_id, grouping)
        existing = self.db.execute(
            select(Alert).where(
                Alert.dedup_key == key,
                Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
            )
        ).scalars().first()

        now = self._now()
        if existing is not None:
            previous_severity = existing.severity
            existing.count += 1
            existing.last_seen_at = now
            existing.severity = _escalate(detection.severity, existing.count)
            if existing.events and detection.events:
                try:
                    events = json.loads(existing.events)
                except json.JSONDecodeError:
                    events = []
                events[:1] = detection.events[:1]  # keep most recent, cap at 10
                existing.events = json.dumps(events[:10])
            self.db.commit()
            self.db.refresh(existing)
            log.info(
                "Alert %s incremented to count=%d severity=%s",
                existing.id, existing.count, existing.severity,
            )
            escalated = (
                SEVERITY_RANK.get(previous_severity, 2)
                != SEVERITY_RANK.get(existing.severity, 2)
            )
            return existing, escalated

        alert = Alert(
            rule_id=detection.rule_id,
            rule_title=detection.rule_title,
            detector=detection.detector,
            dedup_key=key,
            count=1,
            severity=detection.severity,
            status=AlertStatus.OPEN,
            first_seen_at=now,
            last_seen_at=now,
            description=detection.description,
            grouping=json.dumps(grouping),
            mitre=json.dumps(detection.mitre) if detection.mitre else None,
            tags=json.dumps(detection.tags) if detection.tags else None,
            events=json.dumps(detection.events[:10]) if detection.events else None,
            meta=json.dumps(detection.metadata or {}, default=str),
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        log.info("Created alert %s (%s/%s)", alert.id, alert.rule_title, alert.severity)
        return alert, False

    async def process_detection(self, detection: Detection) -> Alert:
        """Sync DB ingest + async notifications + bus publication."""
        alert, escalated = self.ingest_detection(detection)
        is_new = alert.count == 1
        if is_new or escalated:
            for notifier in self.notifiers:
                if notifier.enabled:
                    await notifier.notify(_to_dict(alert), is_new=is_new)
        if self.bus is not None:
            payload = _to_dict(alert)
            payload["event"] = "alert.new" if is_new else "alert.updated"
            await self.bus.publish(Topics.ALERTS, payload)
        return alert

    # ------------------------------------------------------------------- CRUD
    def list(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[Alert], int]:
        query = select(Alert)
        count_query = select(func.count(Alert.id))
        if status:
            query = query.where(Alert.status == status)
            count_query = count_query.where(Alert.status == status)
        if severity:
            query = query.where(Alert.severity == severity)
            count_query = count_query.where(Alert.severity == severity)
        if rule_id:
            query = query.where(Alert.rule_id == rule_id)
            count_query = count_query.where(Alert.rule_id == rule_id)
        total = self.db.execute(count_query).scalar_one()
        rows = (
            self.db.execute(
                query.order_by(Alert.last_seen_at.desc()).offset(offset).limit(limit)
            )
            .scalars()
            .all()
        )
        return list(rows), int(total)

    def get(self, alert_id: str) -> Alert:
        alert = self.db.get(Alert, alert_id)
        if alert is None:
            raise NotFoundError(f"Alert {alert_id} not found")
        return alert

    def update(self, alert_id: str, status: str | None = None,
               assignee: str | None = None, notes: str | None = None) -> Alert:
        alert = self.get(alert_id)
        if status is not None:
            if status not in AlertStatus.CHOICES:
                raise ValidationError(f"Invalid status: {status}")
            alert.status = status
        if assignee is not None:
            alert.assignee = assignee or None
        if notes is not None:
            alert.notes = notes or None
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def summary(self) -> dict[str, Any]:
        rows = self.db.execute(
            select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
        ).all()
        counts = {status: 0 for status in AlertStatus.CHOICES}
        counts.update({status: count for status, count in rows})
        sev_rows = self.db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]))
            .group_by(Alert.severity)
        ).all()
        by_severity = {"informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        by_severity.update({sev: count for sev, count in sev_rows})
        return {
            "open_count": counts[AlertStatus.OPEN],
            "acknowledged_count": counts[AlertStatus.ACKNOWLEDGED],
            "resolved_count": counts[AlertStatus.RESOLVED],
            "false_positive_count": counts[AlertStatus.FALSE_POSITIVE],
            "total_open": counts[AlertStatus.OPEN] + counts[AlertStatus.ACKNOWLEDGED],
            "by_severity": by_severity,
        }


def _to_dict(alert: Alert) -> dict[str, Any]:
    def _load(raw: str | None) -> Any:
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    return {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "rule_title": alert.rule_title,
        "detector": alert.detector,
        "count": alert.count,
        "severity": alert.severity,
        "status": alert.status,
        "assignee": alert.assignee,
        "description": alert.description,
        "grouping": _load(alert.grouping),
        "mitre": _load(alert.mitre),
        "tags": _load(alert.tags),
        "events": _load(alert.events),
        "meta": _load(alert.meta),
        "notes": alert.notes,
        "first_seen_at": alert.first_seen_at,
        "last_seen_at": alert.last_seen_at,
        "created_at": alert.created_at,
    }
