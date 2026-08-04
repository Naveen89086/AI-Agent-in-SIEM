"""AI agent schemas (function 6)."""

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


class AnalyzeAlertRequest(BaseModel):
    alert_id: str = Field(..., description="Alert id to analyze")


class SummarizeIncidentRequest(BaseModel):
    alert_ids: list[str] = Field(..., min_length=1, max_length=200)
    context: str | None = Field(default=None, max_length=5000)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)
    alert_id: str | None = Field(default=None)


class AgentResponseOut(BaseModel):
    analysis: str
    summary: str
    mitre: list[dict[str, str]]
    recommended_actions: list[str]
    risk_score: float
    confidence: float
    provider: str


class AnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    alert_id: str | None
    provider: str
    analysis: str | None
    summary: str | None
    mitre: list[dict[str, str]] | None
    recommended_actions: list[str] | None
    risk_score: float | None
    confidence: float | None
    created_at: datetime

    _parse_mitre = field_validator("mitre", mode="before")(_load_json)
    _parse_actions = field_validator("recommended_actions", mode="before")(_load_json)
