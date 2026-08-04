"""SOAR schemas (function 10)."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SoarActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    playbook_id: str
    playbook_name: str
    alert_id: str | None
    rule_id: str | None
    action_type: str
    status: str
    target: str | None
    detail: str | None
    created_at: datetime
