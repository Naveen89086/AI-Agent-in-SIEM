"""Dashboard aggregation service (function 6 / M8 support).

Pulls telemetry from the metadata DB (alerts, cases, sources) and the log
store (event volume, source breakdown) into a single payload the React
dashboard renders without making many round trips.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus
from app.models.case import Case, CaseStatus
from app.models.data_source import DataSource
from app.storage.base import SearchQuery, build_log_store

log = logging.getLogger("siem.dashboard")

SEVERITIES = ["critical", "high", "medium", "low", "informational"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DashboardService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------ KPIs
    def summary(self) -> dict:
        import asyncio

        store = build_log_store()

        async def _counts() -> tuple[int, int]:
            total = await store.count(SearchQuery())
            since = _utcnow() - timedelta(hours=24)
            last24 = await store.count(
                SearchQuery(time_from=since, time_to=_utcnow())
            )
            return total, last24

        try:
            total_events, events_24h = asyncio.run(_counts())
        except Exception:  # store failures must not break the dashboard
            log.exception("Log store stats unavailable")
            total_events, events_24h = 0, 0

        alert_counts = self.db.execute(
            select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
        ).all()
        status_counts = {s: 0 for s in AlertStatus.CHOICES}
        status_counts.update({status: count for status, count in alert_counts})

        sev_rows = self.db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]))
            .group_by(Alert.severity)
        ).all()
        by_severity = {s: 0 for s in SEVERITIES}
        by_severity.update({sev: count for sev, count in sev_rows})

        case_counts = self.db.execute(
            select(Case.status, func.count(Case.id)).group_by(Case.status)
        ).all()
        case_by_status = {s: 0 for s in CaseStatus.CHOICES}
        case_by_status.update({status: count for status, count in case_counts})

        source_count = self.db.scalar(select(func.count(DataSource.id))) or 0

        return {
            "events_total": total_events,
            "events_last_24h": events_24h,
            "alerts_open": status_counts[AlertStatus.OPEN],
            "alerts_acknowledged": status_counts[AlertStatus.ACKNOWLEDGED],
            "alerts_resolved": status_counts[AlertStatus.RESOLVED],
            "alerts_false_positive": status_counts[AlertStatus.FALSE_POSITIVE],
            "alerts_active": status_counts[AlertStatus.OPEN]
            + status_counts[AlertStatus.ACKNOWLEDGED],
            "alerts_by_severity": by_severity,
            "cases_open": case_by_status[CaseStatus.OPEN]
            + case_by_status[CaseStatus.IN_PROGRESS],
            "cases_resolved": case_by_status[CaseStatus.RESOLVED],
            "sources_total": source_count,
            "generated_at": _utcnow().isoformat(),
        }

    # ----------------------------------------------------------- time series
    def timeseries(self, hours: int = 24, bucket_minutes: int = 60) -> dict:
        import asyncio

        store = build_log_store()
        interval_seconds = max(60, bucket_minutes * 60)
        since = _utcnow() - timedelta(hours=hours)

        async def _events() -> list[dict]:
            buckets = await store.histogram(
                interval_seconds,
                query=SearchQuery(time_from=since, time_to=_utcnow()),
            )
            return [{"key": b.key, "count": b.count} for b in buckets]

        try:
            events = asyncio.run(_events())
        except Exception:
            log.exception("Event histogram unavailable")
            events = []

        # Alert volume per bucket, derived from the metadata DB.
        rows = self.db.execute(
            select(Alert.last_seen_at, func.count(Alert.id))
            .where(Alert.last_seen_at >= since)
            .group_by(Alert.last_seen_at)
        ).all()
        alert_map: dict[int, int] = {}
        for ts, count in rows:
            bucket = int(ts.timestamp() // interval_seconds) * interval_seconds
            alert_map[bucket] = alert_map.get(bucket, 0) + count

        # Bucketize the (already bucketed) event series into the same axis.
        merged: dict[str, dict] = {}
        for point in events:
            try:
                key_ts = datetime.fromisoformat(point["key"]).timestamp()
            except ValueError:
                continue
            slot = int(key_ts // interval_seconds) * interval_seconds
            merged[slot] = {"key": point["key"], "events": point["count"], "alerts": 0}

        for bucket_ts, count in alert_map.items():
            slot = bucket_ts
            merged.setdefault(slot, {
                "key": datetime.fromtimestamp(slot, tz=timezone.utc).isoformat(),
                "events": 0,
                "alerts": 0,
            })["alerts"] = count

        return {
            "interval_seconds": interval_seconds,
            "points": [
                merged[k]
                for k in sorted(merged)
            ],
        }

    # ------------------------------------------------------------- top lists
    def top_rules(self, limit: int = 10) -> list[dict]:
        rows = self.db.execute(
            select(Alert.rule_id, Alert.rule_title, func.count(Alert.id))
            .where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]))
            .group_by(Alert.rule_id, Alert.rule_title)
            .order_by(func.count(Alert.id).desc())
            .limit(limit)
        ).all()
        return [
            {"rule_id": rid, "rule_title": title, "count": count}
            for rid, title, count in rows
        ]

    def top_sources(self, limit: int = 10) -> list[dict]:
        import asyncio

        store = build_log_store()

        async def _sources() -> list[dict]:
            buckets = await store.aggregation("source_name", query=SearchQuery(), size=limit)
            return [{"source_name": b.key, "count": b.count} for b in buckets]

        try:
            return asyncio.run(_sources())
        except Exception:
            log.exception("Source aggregation unavailable")
            return []

    def recent_alerts(self, limit: int = 10) -> list[dict]:
        import json

        rows = self.db.scalars(
            select(Alert)
            .order_by(Alert.last_seen_at.desc())
            .limit(limit)
        ).all()
        return [
            {
                "id": a.id,
                "rule_title": a.rule_title,
                "severity": a.severity,
                "status": a.status,
                "count": a.count,
                "last_seen_at": a.last_seen_at,
                "mitre": (json.loads(a.mitre) if a.mitre else None),
            }
            for a in rows
        ]
