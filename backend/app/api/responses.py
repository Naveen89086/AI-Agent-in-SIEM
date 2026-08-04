"""Shared API response helpers (module 7).

Standardizes list endpoints on a paginated envelope:
    {"items": [...], "total": N, "offset": 0, "limit": 50}
"""

from typing import Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    offset: int
    limit: int


def paginate(
    items: list[Any], total: int, offset: int = 0, limit: int = 50
) -> dict[str, Any]:
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
    }
