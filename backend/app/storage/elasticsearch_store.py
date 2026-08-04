"""Elasticsearch log store (production backend).

Creates the SIEM index template and ILM lifecycle on startup, rolls indices
daily, and implements search/aggregations with the Query DSL.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.storage.base import (
    AggregationBucket,
    LogStore,
    SearchHit,
    SearchQuery,
    SearchResponse,
)

log = logging.getLogger("siem.storage.es")

_LIFECYCLE_NAME = "siem-lifecycle"

_INDEX_TEMPLATE = {
    "index_patterns": ["siem-events-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.lifecycle.name": _LIFECYCLE_NAME,
            "index.lifecycle.rollover_alias": "siem-events",
            "index.mapping.total_fields.limit": 5000,
            "index.query.default_field": ["message", "raw", "labels.*"],
        },
        "mappings": {
            "dynamic": True,
            "properties": {
                "@timestamp": {"type": "date"},
                "received_at": {"type": "date"},
                "event_id": {"type": "keyword"},
                "message": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
                "raw": {"type": "text"},
                "source_type": {"type": "keyword"},
                "source_name": {"type": "keyword"},
                "host.name": {"type": "keyword"},
                "host.ip": {"type": "ip"},
                "source.ip": {"type": "ip"},
                "source.port": {"type": "long"},
                "destination.ip": {"type": "ip"},
                "destination.port": {"type": "long"},
                "user.name": {"type": "keyword"},
                "process.name": {"type": "keyword"},
                "process.executable": {"type": "keyword"},
                "process.command_line": {"type": "text"},
                "event.category": {"type": "keyword"},
                "event.type": {"type": "keyword"},
                "event.action": {"type": "keyword"},
                "event.outcome": {"type": "keyword"},
                "event.code": {"type": "keyword"},
                "event.module": {"type": "keyword"},
                "network.protocol": {"type": "keyword"},
                "url.path": {"type": "keyword"},
                "url.full": {"type": "text"},
                "http.request.method": {"type": "keyword"},
                "http.response.status_code": {"type": "long"},
                "file.path": {"type": "keyword"},
                "registry.path": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "pipeline.parsed": {"type": "boolean"},
                "pipeline.parser": {"type": "keyword"},
                "tags": {"type": "keyword"},
            },
        },
    },
}

_LIFECYCLE = {
    "policy": {
        "phases": {
            "hot": {
                "min_age": "0ms",
                "actions": {"rollover": {"max_age": "1d"}, "set_priority": {"priority": 100}},
            },
            "delete": {
                "min_age": f"{settings.retention_delete_days}d",
                "actions": {"delete": {}},
            },
        }
    }
}


class ElasticsearchStore(LogStore):
    def __init__(self) -> None:
        from elasticsearch import AsyncElasticsearch

        kwargs: dict[str, Any] = {"verify_certs": settings.elasticsearch_verify_tls}
        if settings.elasticsearch_username:
            kwargs["basic_auth"] = (
                settings.elasticsearch_username,
                settings.elasticsearch_password or "",
            )
        self._client = AsyncElasticsearch(
            settings.log_store_url.replace("elasticsearch://", "http://"),
            **kwargs,
        )
        self.prefix = settings.log_store_index_prefix
        self._init_lock = asyncio.Lock()
        self._initialized = False

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        async with self._init_lock:
            if self._initialized:
                return
            try:
                await self._client.ilm.put_lifecycle(
                    name=_LIFECYCLE_NAME, policy=_LIFECYCLE
                )
                await self._client.indices.put_index_template(
                    name="siem-events-template", body=_INDEX_TEMPLATE
                )
                await self._client.indices.create_alias(
                    index=f"{self.prefix}-000001",
                    name="siem-events",
                    is_write_index=True,
                    error_status=400,  # ignore resource_already_exists_exception
                )
                log.info("Elasticsearch index template and lifecycle configured")
            except Exception:
                log.warning("Elasticsearch init skipped (cluster may be starting)")
            self._initialized = True

    def _index_name(self, dt: datetime) -> str:
        return f"{self.prefix}-{dt.strftime('%Y.%m.%d')}"

    async def index_event(self, event: dict[str, Any]) -> str:
        await self._ensure_initialized()
        doc = dict(event)
        doc["@timestamp"] = self._ts(doc)
        try:
            resp = await self._client.index(
                index=self._index_name(datetime.now(timezone.utc)),
                id=str(doc.get("event_id") or doc.get("id") or ""),
                document=doc,
                refresh=False,
            )
            return str(resp.get("_id", ""))
        except Exception:
            log.exception("ES index_event failed")
            return ""

    async def index_many(self, events: list[dict[str, Any]]) -> int:
        await self._ensure_initialized()
        index = self._index_name(datetime.now(timezone.utc))
        operations: list[dict[str, Any]] = []
        for event in events:
            doc = dict(event)
            doc["@timestamp"] = self._ts(doc)
            operations.append({"index": {"_index": index}})
            operations.append(doc)
        if not operations:
            return 0
        try:
            resp = await self._client.bulk(operations=operations, refresh=False)
            return int(resp.get("items") and len(resp.get("items") or []))
        except Exception:
            log.exception("ES index_many failed")
            return 0

    @staticmethod
    def _ts(event: dict[str, Any]) -> str:
        raw = event.get("@timestamp") or event.get("received_at")
        if raw:
            return raw
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------- query
    @staticmethod
    def _query_dsl(query: SearchQuery) -> dict[str, Any]:
        must: list[dict[str, Any]] = []
        if query.text:
            must.append(
                {"multi_match": {"query": query.text, "fields": ["message^3", "raw", "labels.*", "*"]}}
            )
        for filt in query.filters:
            must.append({"term": {filt.field: filt.value}})
        range_q: dict[str, Any] = {}
        if query.time_from:
            range_q["gte"] = query.time_from.astimezone(timezone.utc).isoformat()
        if query.time_to:
            range_q["lte"] = query.time_to.astimezone(timezone.utc).isoformat()
        if range_q:
            must.append({"range": {"@timestamp": range_q}})
        return {"bool": {"must": must}} if must else {"match_all": {}}

    async def search(self, query: SearchQuery) -> SearchResponse:
        await self._ensure_initialized()
        body: dict[str, Any] = {
            "query": self._query_dsl(query),
            "from": query.from_,
            "size": query.size,
            "sort": [{query.sort_field: {"order": query.sort_order}}],
            "track_total_hits": True,
        }
        try:
            resp = await self._client.search(index=f"{self.prefix}-*", body=body)
            hits = [
                SearchHit(
                    id=str(h.get("_id", "")),
                    score=float(h.get("_score") or 0.0),
                    source=h.get("_source", {}),
                )
                for h in resp.get("hits", {}).get("hits", [])
            ]
            return SearchResponse(
                total=int(resp.get("hits", {}).get("total", {}).get("value", 0)),
                hits=hits,
                took_ms=int(resp.get("took", 0)),
            )
        except Exception:
            log.exception("ES search failed")
            return SearchResponse(total=0, hits=[], took_ms=0)

    async def count(self, query: SearchQuery) -> int:
        await self._ensure_initialized()
        try:
            resp = await self._client.count(
                index=f"{self.prefix}-*", query=self._query_dsl(query)
            )
            return int(resp.get("count", 0))
        except Exception:
            log.exception("ES count failed")
            return 0

    async def aggregation(
        self,
        field: str,
        *,
        query: SearchQuery | None = None,
        size: int = 20,
    ) -> list[AggregationBucket]:
        await self._ensure_initialized()
        agg_name = "agg"
        body: dict[str, Any] = {
            "query": self._query_dsl(query) if query else {"match_all": {}},
            "size": 0,
            "aggs": {agg_name: {"terms": {"field": field, "size": size}}},
        }
        try:
            resp = await self._client.search(index=f"{self.prefix}-*", body=body)
            buckets = (
                resp.get("aggregations", {}).get(agg_name, {}).get("buckets", [])
            )
            return [
                AggregationBucket(key=str(b.get("key", "null")), count=int(b.get("doc_count", 0)))
                for b in buckets
            ]
        except Exception:
            log.exception("ES aggregation failed")
            return []

    async def histogram(
        self,
        interval_seconds: int,
        *,
        query: SearchQuery | None = None,
        field: str = "@timestamp",
    ) -> list[AggregationBucket]:
        await self._ensure_initialized()
        agg_name = "hist"
        body: dict[str, Any] = {
            "query": self._query_dsl(query) if query else {"match_all": {}},
            "size": 0,
            "aggs": {
                agg_name: {
                    "date_histogram": {
                        "field": field,
                        "fixed_interval": f"{interval_seconds}s",
                    }
                }
            },
        }
        try:
            resp = await self._client.search(index=f"{self.prefix}-*", body=body)
            buckets = (
                resp.get("aggregations", {}).get(agg_name, {}).get("buckets", [])
            )
            return [
                AggregationBucket(
                    key=datetime.fromtimestamp(
                        b.get("key", 0) / 1000, tz=timezone.utc
                    ).isoformat(),
                    count=int(b.get("doc_count", 0)),
                )
                for b in buckets
            ]
        except Exception:
            log.exception("ES histogram failed")
            return []

    async def health(self) -> bool:
        try:
            return bool(await self._client.ping())
        except Exception:
            return False
