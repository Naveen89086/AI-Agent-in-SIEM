"""SCA drift and event models.

``ConfigurationDrift`` records a meaningful state change (PASS -> FAIL or
FAIL -> PASS) between two scans of the same check. ``ScaEvent`` is the SCA
activity feed (scan_completed, configuration_changed, agent_offline, ...).
"""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

DRIFT_EVENT_TYPES = (
    "configuration_changed",
    "scan_completed",
    "scan_failed",
    "critical_check_failed",
    "policy_updated",
    "agent_offline",
    "agent_online",
)


class ConfigurationDrift(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A meaningful configuration change detected between two scans."""

    __tablename__ = "configuration_drifts"

    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    policy_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    check_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)  # PolicyCheck uuid
    previous_result: Mapped[str] = mapped_column(String(16), nullable=False)
    current_result: Mapped[str] = mapped_column(String(16), nullable=False)
    previous_value: Mapped[str | None] = mapped_column(String, nullable=True)
    current_value: Mapped[str | None] = mapped_column(String, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)

    def __repr__(self) -> str:
        return f"<ConfigurationDrift {self.previous_result}->{self.current_result} check={self.check_id}>"


class ScaEvent(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A configuration-assessment event surfaced in the Events feed."""

    __tablename__ = "sca_events"

    event_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    scan_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    check_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info", nullable=False)
    message: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON dict
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    def __repr__(self) -> str:
        return f"<ScaEvent {self.event_type} {self.occurred_at}>"
