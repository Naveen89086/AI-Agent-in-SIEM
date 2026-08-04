"""LogStore interface: abstraction over log search/index backends.

Production uses Elasticsearch (ILM, full-text, aggregations). Development and
tests use a local JSON-file store. The interface is intentionally small so
detectors, dashboards and investigations never depend on a concrete backend.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class FilterField:
    """A single field filter (must be present with given value)."""

    field: str
    value: Any


@dataclass
class SearchQuery:
    text: str | None = None
    filters: list[FilterField] = field(default_factory=list)
    time_from: datetime | None = None
    time_to: datetime | None = None
    size: int = 50
    from_: int = 0
    sort_field: str = "@timestamp"
    sort_order: str = "desc"


@dataclass
class SearchHit:
    id: str
    score: float
    source: dict[str, Any]


@dataclass
class SearchResponse:
    total: int
    hits: list[SearchHit]
    took_ms: int


@dataclass
class AggregationBucket:
    key: str
    count: int


class LogStore(ABC):
    @abstractmethod
    async def index_event(self, event: dict[str, Any]) -> str:
        """Persist one normalized event; returns the document id."""

    @abstractmethod
    async def index_many(self, events: list[dict[str, Any]]) -> int:
        """Persist many events; returns number persisted."""

    @abstractmethod
    async def search(self, query: SearchQuery) -> SearchResponse:
        """Full-text + filter search with paging."""

    @abstractmethod
    async def count(self, query: SearchQuery) -> int:
        """Count matching events."""

    @abstractmethod
    async def aggregation(
        self,
        field: str,
        *,
        query: SearchQuery | None = None,
        size: int = 20,
    ) -> list[AggregationBucket]:
        """Group-by aggregation over a field."""

    @abstractmethod
    async def histogram(
        self,
        interval_seconds: int,
        *,
        query: SearchQuery | None = None,
        field: str = "@timestamp",
    ) -> list[AggregationBucket]:
        """Time-bucket histogram."""

    @abstractmethod
    async def health(self) -> bool:
        """Backend reachable?"""


def build_log_store(url: str | None = None) -> "LogStore":
    from app.core.config import settings

    url = url or settings.log_store_url
    if url.startswith("elasticsearch"):
        from app.storage.elasticsearch_store import ElasticsearchStore

        return ElasticsearchStore()
    from app.storage.local_store import LocalJsonStore

    return LocalJsonStore()
