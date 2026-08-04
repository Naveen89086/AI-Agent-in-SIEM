"""Local JSON-file log store (development / tests / offline demo).

Appends normalized events to per-day JSONL files and keeps a bounded
in-memory index for fast search. Retention is handled by file cleanup
(see M11 for the Elasticsearch ILM path).
"""

import asyncio
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.storage.base import (
    AggregationBucket,
    FilterField,
    LogStore,
    SearchHit,
    SearchQuery,
    SearchResponse,
)

_MAX_MEMORY_EVENTS = 200_000


class LocalJsonStore(LogStore):
    def __init__(self, base_dir: str | None = None) -> None:
        self.base_dir = Path(base_dir or self._default_dir())
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._events: list[dict[str, Any]] = []
        self._loaded = False
        self._lock = asyncio.Lock()

    @staticmethod
    def _default_dir() -> str:
        url = settings.log_store_url
        if url.startswith("local://"):
            return url.split("local://", 1)[1] or "./data/events"
        return "./data/events"

    def _reload(self) -> None:
        """Load persisted JSONL files into the in-memory index (once)."""
        if self._loaded:
            return
        self._loaded = True
        loaded: list[dict[str, Any]] = []
        for file in sorted(self.base_dir.glob("events-*.jsonl")):
            try:
                with file.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            loaded.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except OSError:
                continue
        if len(loaded) > _MAX_MEMORY_EVENTS:
            loaded = loaded[-_MAX_MEMORY_EVENTS:]
        self._events.extend(loaded)

    def _ensure_index(self) -> None:
        if not self._events and not self._loaded:
            self._reload()

    def _today_file(self, ts: datetime | None = None) -> Path:
        day = (ts or datetime.now(timezone.utc)).strftime("%Y.%m.%d")
        return self.base_dir / f"events-{day}.jsonl"

    def _doc_id(self, event: dict[str, Any]) -> str:
        return str(event.get("event_id") or event.get("id") or "")

    async def index_event(self, event: dict[str, Any]) -> str:
        async with self._lock:
            return await self._index_one_locked(event)

    async def index_many(self, events: list[dict[str, Any]]) -> int:
        async with self._lock:
            for event in events:
                await self._index_one_locked(event)
            return len(events)

    async def _index_one_locked(self, event: dict[str, Any]) -> str:
        doc = dict(event)
        doc.setdefault("@timestamp", datetime.now(timezone.utc).isoformat())
        doc["_storage"] = {"stored_at": datetime.now(timezone.utc).isoformat()}
        self._events.append(doc)
        if len(self._events) > _MAX_MEMORY_EVENTS:
            self._events = self._events[-_MAX_MEMORY_EVENTS:]
        try:
            file = self._today_file()
            file.parent.mkdir(parents=True, exist_ok=True)
            with file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(doc, default=str) + "\n")
        except Exception:
            pass
        return self._doc_id(doc)

    # ------------------------------------------------------------------ search
    def _matches(self, event: dict[str, Any], query: SearchQuery) -> bool:
        if query.time_from or query.time_to:
            ts = event.get("@timestamp")
            if ts:
                try:
                    ts_dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                    if ts_dt.tzinfo is None:
                        ts_dt = ts_dt.replace(tzinfo=timezone.utc)
                    if query.time_from and ts_dt < query.time_from:
                        return False
                    if query.time_to and ts_dt > query.time_to:
                        return False
                except ValueError:
                    pass
        if query.text:
            haystack = json.dumps(event, default=str).lower()
            if query.text.lower() not in haystack:
                return False
        for filt in query.filters:
            value = self._get_path(event, filt.field)
            if value != filt.value and not self._value_matches(filt.value, value):
                return False
        return True

    @staticmethod
    def _value_matches(needle: Any, value: Any) -> bool:
        if needle is None:
            return value is None
        if isinstance(needle, str) and isinstance(value, str):
            return needle.lower() == value.lower()
        return needle == value

    @staticmethod
    def _get_path(event: dict[str, Any], dotted: str) -> Any:
        node: Any = event
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    async def search(self, query: SearchQuery) -> SearchResponse:
        self._ensure_index()
        matches = [e for e in self._events if self._matches(e, query)]
        matches.sort(
            key=lambda e: str(e.get(query.sort_field, "")),
            reverse=query.sort_order == "desc",
        )
        page = matches[query.from_ : query.from_ + query.size]
        hits = [
            SearchHit(id=self._doc_id(e), score=1.0, source=e) for e in page
        ]
        return SearchResponse(total=len(matches), hits=hits, took_ms=0)

    async def count(self, query: SearchQuery) -> int:
        self._ensure_index()
        return sum(1 for e in self._events if self._matches(e, query))

    async def aggregation(
        self,
        field: str,
        *,
        query: SearchQuery | None = None,
        size: int = 20,
    ) -> list[AggregationBucket]:
        counts: dict[str, int] = defaultdict(int)
        self._ensure_index()
        for e in self._events:
            if query is not None and not self._matches(e, query):
                continue
            key = self._get_path(e, field)
            counts[str(key if key is not None else "null")] += 1
        return [
            AggregationBucket(key=k, count=c)
            for k, c in sorted(counts.items(), key=lambda kv: -kv[1])[:size]
        ]

    async def histogram(
        self,
        interval_seconds: int,
        *,
        query: SearchQuery | None = None,
        field: str = "@timestamp",
    ) -> list[AggregationBucket]:
        buckets: dict[int, int] = defaultdict(int)
        self._ensure_index()
        for e in self._events:
            if query is not None and not self._matches(e, query):
                continue
            raw = e.get(field)
            if not raw:
                continue
            try:
                ts = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            except ValueError:
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            bucket = int(ts.timestamp() // interval_seconds)
            buckets[bucket] += 1
        ordered = sorted(buckets.items())
        return [
            AggregationBucket(
                key=datetime.fromtimestamp(b * interval_seconds, tz=timezone.utc).isoformat(),
                count=c,
            )
            for b, c in ordered
        ]

    async def health(self) -> bool:
        return True
