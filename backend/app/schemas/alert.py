"""Alert schemas (function 5 - real-time alerting)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.alert import AlertStatus


def _load_json(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    import json

    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return value


class AlertUpdate(BaseModel):
    status: str | None = Field(
        default=None,
        description="one of: open, acknowledged, resolved, false_positive",
    )
    assignee: str | None = Field(default=None, max_length=128)
    notes: str | None = Field(default=None)

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str | None) -> str | None:
        if value is not None and value not in AlertStatus.CHOICES:
            raise ValueError(f"Invalid status: {value}")
        return value


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_id: str
    rule_title: str
    detector: str
    count: int
    severity: str
    status: str
    assignee: str | None
    description: str | None
    grouping: dict[str, Any] | None
    mitre: list[dict[str, str]] | None
    tags: list[str] | None
    events: list[dict[str, Any]] | None
    meta: dict[str, Any] | None
    notes: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime

    _parse_grouping = field_validator("grouping", mode="before")(_load_json)
    _parse_mitre = field_validator("mitre", mode="before")(_load_json)
    _parse_tags = field_validator("tags", mode="before")(_load_json)
    _parse_events = field_validator("events", mode="before")(_load_json)
    _parse_meta = field_validator("meta", mode="before")(_load_json)


class AlertSummary(BaseModel):
    open_count: int
    acknowledged_count: int
    resolved_count: int
    false_positive_count: int
    total_open: int
    by_severity: dict[str, int]


class AlertList(BaseModel):
    items: list[AlertRead]
    total: int
    offset: int
    limit: int
