"""SOAR action execution record (function 10 - automated response)."""

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class SoarAction(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """Audit trail entry for one automated response step."""

    __tablename__ = "soar_actions"

    playbook_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    playbook_name: Mapped[str] = mapped_column(String(255), nullable=False)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)  # pending|success|failed|skipped
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<SoarAction {self.action_type} {self.status} ({self.playbook_id})>"
