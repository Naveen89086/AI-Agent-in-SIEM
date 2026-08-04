"""Ingestion (log collection) schemas."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class RawEventIn(BaseModel):
    """A single raw event submitted by a collector or agent."""

    message: str = Field(..., description="Raw log line or message body", max_length=100000)
    source_type: str = Field(default="syslog", max_length=32, description="syslog|http|file|endpoint|windows|linux")
    source_name: str = Field(default="default", max_length=128)
    host: str | None = Field(default=None, max_length=255)
    timestamp: datetime | None = Field(default=None)
    extra: dict[str, Any] = Field(default_factory=dict, description="Source-specific structured fields")
    tags: list[str] = Field(default_factory=list)


class IngestRequest(BaseModel):
    """Batch ingestion payload."""

    events: list[RawEventIn] = Field(..., min_length=1, max_length=1000)

    @field_validator("events")
    @classmethod
    def _non_empty(cls, events: list[RawEventIn]) -> list[RawEventIn]:
        if not events:
            raise ValueError("At least one event is required")
        return events


class IngestResult(BaseModel):
    accepted: int
    failed: int
    errors: list[str] = Field(default_factory=list)


class DataSourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    source_type: str = Field(default="http", max_length=32)
    format: str = Field(default="json", max_length=32)
    parser: str | None = Field(default=None, max_length=64)
    host: str | None = Field(default=None, max_length=255)
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class DataSourceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    source_type: str
    format: str
    parser: str | None
    host: str | None
    enabled: bool
    received_count: int
    last_seen_at: datetime | None
    created_at: datetime
