"""AI analysis records model (function 6)."""

from sqlalchemy import DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Analysis(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A stored AI analysis (alert analysis, incident summary or chat turn)."""

    __tablename__ = "analyses"

    kind: Mapped[str] = mapped_column(String(32), default="alert_analysis", nullable=False, index=True)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), default="heuristic", nullable=False)
    prompt: Mapped[str | None] = mapped_column(String, nullable=True)
    analysis: Mapped[str | None] = mapped_column(String, nullable=True)
    summary: Mapped[str | None] = mapped_column(String, nullable=True)
    mitre: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON list
    recommended_actions: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON list
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    response: Mapped[str | None] = mapped_column(String, nullable=True)

    def __repr__(self) -> str:
        return f"<Analysis {self.kind} by {self.provider} ({self.created_at})>"
