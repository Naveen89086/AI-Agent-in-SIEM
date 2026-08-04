"""Log collection service: validates and publishes raw events to the bus."""

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.data_source import DataSource
from app.pipeline.bus import EventBus, Topics, stamp
from app.schemas.ingest import IngestRequest, IngestResult, RawEventIn

log = logging.getLogger("siem.ingest")


class IngestService:
    """Ingests raw events, tracks source statistics, and publishes to the bus."""

    def __init__(self, db: Session, bus: EventBus) -> None:
        self.db = db
        self.bus = bus

    async def ingest(self, request: IngestRequest) -> IngestResult:
        accepted = 0
        failed = 0
        errors: list[str] = []
        raw_events: list[dict[str, Any]] = []

        for idx, event in enumerate(request.events):
            try:
                raw = self._to_raw(event)
                raw_events.append(raw)
                accepted += 1
            except ValueError as exc:
                failed += 1
                errors.append(f"event[{idx}]: {exc}")

        if raw_events:
            await self.bus.publish_many(Topics.RAW_EVENTS, raw_events)
            self._record_source_stats(request.events, accepted)

        return IngestResult(accepted=accepted, failed=failed, errors=errors)

    def _to_raw(self, event: RawEventIn) -> dict[str, Any]:
        message = event.message.strip()
        if not message:
            raise ValueError("empty message")
        now = datetime.now(timezone.utc)
        return stamp(
            {
                "raw": message,
                "source_type": event.source_type,
                "source_name": event.source_name,
                "host": event.host,
                "received_at": now.isoformat(),
                "extra": event.extra,
                "tags": event.tags,
                "pipeline": {"ingested": True, "normalized": False},
            }
        )

    def _record_source_stats(self, events: list[RawEventIn], count: int) -> None:
        """Increment per-source counters (best-effort, cheap)."""
        try:
            names = {e.source_name for e in events}
            for name in names:
                source = self.db.scalar(
                    select(DataSource).where(DataSource.name == name)
                )
                if source is None:
                    source = DataSource(
                        name=name,
                        source_type=events[0].source_type,
                        format="syslog" if events[0].source_type in ("syslog",) else "json",
                        host=events[0].host,
                        enabled=True,
                        received_count=0,
                    )
                    self.db.add(source)
                source.received_count += sum(1 for e in events if e.source_name == name)
                source.last_seen_at = datetime.now(timezone.utc)
            self.db.commit()
        except Exception:  # stats must never break ingestion
            log.exception("Failed to update data source stats")
            self.db.rollback()
