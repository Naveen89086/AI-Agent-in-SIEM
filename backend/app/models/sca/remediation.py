"""Human-approved SCA remediation model.

Remediation always requires a human approval step. Only predefined, trusted
action types (mapped to agent-side allowlisted collectors) can be executed.
"""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RemediationStatus:
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"

    CHOICES = (PENDING, APPROVED, REJECTED, EXECUTING, COMPLETED, FAILED)


class RemediationAction(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A requested (and possibly approved) remediation for a failed check."""

    __tablename__ = "remediation_actions"

    check_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)  # PolicyCheck uuid
    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(
        String(16), default=RemediationStatus.PENDING, nullable=False
    )
    result: Mapped[str | None] = mapped_column(String, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<RemediationAction {self.action_type} {self.status}>"
