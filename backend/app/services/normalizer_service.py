"""Normalization service (function 2).

Consumes raw events, applies the best matching parser, produces an
ECS-aligned event, persists it to the log store and forwards it on the
`normalized.events` topic for correlation and detection.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from app.pipeline.bus import EventBus, Topics
from app.pipeline.parsers import resolve_parser
from app.storage.base import LogStore

log = logging.getLogger("siem.normalizer")


class NormalizerService:
    def __init__(self, bus: EventBus, store: LogStore) -> None:
        self.bus = bus
        self.store = store

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        """Turn a raw event into a normalized ECS event."""
        source_type = raw.get("source_type")
        format_ = raw.get("format")
        hint = (raw.get("extra") or {}).get("parser") or raw.get("parser_hint")
        parser = resolve_parser(source_type, format_, hint)

        parsed = parser.parse(raw)
        if parsed is None:
            # No parser matched: emit a minimal syslog-style normalized event.
            parsed = {
                "event": {
                    "kind": "event",
                    "category": ["unknown"],
                    "type": ["info"],
                },
                "message": raw.get("message") or raw.get("raw", ""),
                "pipeline": {"parsed": False, "parser": "none"},
            }

        # Merge ingestion metadata on top of parsed fields.
        event: dict[str, Any] = {
            "event_id": raw.get("event_id"),
            "@timestamp": parsed.get("@timestamp")
            or raw.get("timestamp")
            or raw.get("received_at")
            or datetime.now(timezone.utc).isoformat(),
            "received_at": raw.get("received_at"),
            "source_type": source_type,
            "source_name": raw.get("source_name"),
            "host": parsed.get("host") or {"name": raw.get("host")},
            "message": parsed.get("message") or raw.get("message") or raw.get("raw", ""),
            "raw": raw.get("raw", ""),
            "tags": list(dict.fromkeys(raw.get("tags", []) + parsed.get("tags", []))),
            "extra": raw.get("extra", {}),
        }
        for key in (
            "event",
            "source",
            "destination",
            "user",
            "process",
            "file",
            "network",
            "url",
            "http",
            "registry",
            "labels",
            "severity",
            "pipeline",
        ):
            if parsed.get(key) is not None:
                event[key] = parsed[key]
        event.setdefault("event", {"kind": "event", "category": ["unknown"], "type": ["info"]})
        event["pipeline"]["normalized"] = True
        return event

    async def process(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        """Normalize, persist and forward one raw event."""
        normalized = self.normalize(raw)
        if normalized is None:
            return None
        try:
            await self.store.index_event(normalized)
        except Exception:
            log.exception("Failed to persist normalized event")
        await self.bus.publish(Topics.NORMALIZED_EVENTS, normalized)
        return normalized
