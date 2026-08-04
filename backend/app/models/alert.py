"""Alert model (function 5 - real-time alerting)."""

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AlertStatus:
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

    CHOICES = (OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE)


class Alert(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A consolidated, user-manageable alert derived from one or more detections."""

    __tablename__ = "alerts"

    # identity
    rule_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    rule_title: Mapped[str] = mapped_column(String(255), nullable=False)
    detector: Mapped[str] = mapped_column(String(32), default="correlation", nullable=False)

    # dedup
    dedup_key: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # state
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), default=AlertStatus.OPEN, nullable=False, index=True)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # content
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    grouping: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON dict
    mitre: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON list
    tags: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON list
    events: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON list of summaries
    meta: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON dict
    notes: Mapped[str | None] = mapped_column(String, nullable=True)

    def __repr__(self) -> str:
        return f"<Alert {self.rule_title} {self.status}/{self.severity} x{self.count}>"


def _json_dumps(value: Any) -> str | None:
    import json

    return json.dumps(value) if value is not None else None
