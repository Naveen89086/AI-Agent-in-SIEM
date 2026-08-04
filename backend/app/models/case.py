"""Investigation case models (function 7 - investigation & forensics)."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class CaseStatus:
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"

    CHOICES = (OPEN, IN_PROGRESS, RESOLVED, CLOSED)


class CaseSeverity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    CHOICES = (LOW, MEDIUM, HIGH, CRITICAL)


class Case(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A security investigation that groups alerts and artifacts."""

    __tablename__ = "cases"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default=CaseStatus.OPEN, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), default=CaseSeverity.MEDIUM, nullable=False, index=True)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON list
    alert_ids: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON list
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<Case {self.title} {self.status}/{self.severity}>"


class CaseNote(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A free-text analyst note attached to a case (timeline entry)."""

    __tablename__ = "case_notes"

    case_id: Mapped[str] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False
    )
    author: Mapped[str] = mapped_column(String(128), default="analyst", nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)


class CaseArtifact(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """An investigative artifact (host, IP, file hash, log id) linked to a case."""

    __tablename__ = "case_artifacts"

    case_id: Mapped[str] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False
    )
    artifact_type: Mapped[str] = mapped_column(String(32), nullable=False)  # host | ip | hash | file | log
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
