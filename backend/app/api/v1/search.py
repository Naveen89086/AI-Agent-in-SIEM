"""Event search endpoints (function 7 - investigation & forensics).

Full-text + field-filter search over the log store, plus aggregations used
by dashboards and pivoting.
"""

from datetime import datetime

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin
from app.storage.base import FilterField, SearchQuery, build_log_store

router = APIRouter()


def _parse_filters(raw: str | None) -> list[FilterField]:
    filters: list[FilterField] = []
    if not raw:
        return filters
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            continue
        field, _, value = part.partition(":")
        filters.append(FilterField(field=field.strip(), value=value.strip()))
    return filters


@router.get("", tags=["Investigation"])
async def search_events(
    user: AnalystOrAdmin,
    q: str | None = Query(default=None, max_length=500),
    filters: str | None = Query(default=None, description="comma list of field:value"),
    time_from: datetime | None = Query(default=None),
    time_to: datetime | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    sort_field: str = Query(default="@timestamp"),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> dict:
    store = build_log_store()
    query = SearchQuery(
        text=q,
        filters=_parse_filters(filters),
        time_from=time_from,
        time_to=time_to,
        size=limit,
        from_=offset,
        sort_field=sort_field,
        sort_order=sort_order,
    )
    response = await store.search(query)
    return {
        "items": [hit.source for hit in response.hits],
        "total": response.total,
        "offset": offset,
        "limit": limit,
        "took_ms": response.took_ms,
    }


@router.get("/aggregate", tags=["Investigation"])
async def aggregate_events(
    user: AnalystOrAdmin,
    field: str = Query(...),
    q: str | None = Query(default=None, max_length=500),
    filters: str | None = Query(default=None),
    size: int = Query(default=20, ge=1, le=100),
) -> dict:
    store = build_log_store()
    query = SearchQuery(text=q, filters=_parse_filters(filters))
    buckets = await store.aggregation(field, query=query, size=size)
    return {"field": field, "buckets": [{"key": b.key, "count": b.count} for b in buckets]}


@router.get("/histogram", tags=["Investigation"])
async def histogram_events(
    user: AnalystOrAdmin,
    interval_seconds: int = Query(default=3600, ge=60, le=86400 * 30),
    q: str | None = Query(default=None, max_length=500),
    filters: str | None = Query(default=None),
    time_from: datetime | None = Query(default=None),
    time_to: datetime | None = Query(default=None),
) -> dict:
    store = build_log_store()
    query = SearchQuery(
        text=q,
        filters=_parse_filters(filters),
        time_from=time_from,
        time_to=time_to,
    )
    buckets = await store.histogram(interval_seconds, query=query)
    return {
        "interval_seconds": interval_seconds,
        "buckets": [{"key": b.key, "count": b.count} for b in buckets],
    }
