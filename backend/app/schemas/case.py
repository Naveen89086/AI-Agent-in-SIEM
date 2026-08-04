"""Investigation case schemas (function 7)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10000)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    assignee: str | None = Field(default=None, max_length=128)
    tags: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=10000)
    status: str | None = Field(default=None, pattern="^(open|in_progress|resolved|closed)$")
    severity: str | None = Field(default=None, pattern="^(low|medium|high|critical)$")
    assignee: str | None = Field(default=None, max_length=128)
    tags: list[str] | None = None
    alert_ids: list[str] | None = None


class CaseNoteCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=20000)


class CaseArtifactCreate(BaseModel):
    artifact_type: str = Field(..., pattern="^(host|ip|hash|file|log)$")
    value: str = Field(..., min_length=1, max_length=512)
    source: str | None = Field(default=None, max_length=128)
    note: str | None = Field(default=None, max_length=10000)


class CaseRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: str | None
    status: str
    severity: str
    assignee: str | None
    tags: list[str] | None
    alert_ids: list[str] | None
    opened_at: datetime
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    _parse_tags = field_validator("tags", mode="before")(_load_json)
    _parse_alert_ids = field_validator("alert_ids", mode="before")(_load_json)


class CaseNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    author: str
    content: str
    created_at: datetime


class CaseArtifactRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    artifact_type: str
    value: str
    source: str | None
    note: str | None
    created_at: datetime
