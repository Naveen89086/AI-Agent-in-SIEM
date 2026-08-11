"""Threat hunting ORM models.

``HuntQuery`` stores one executed hunt (the built-in hunt id, the time range,
the field filters and the resulting counts) so analysts get a durable, auditable
history of every hunt they run. ``HuntResult`` snapshots the matched events
(the authoritative copies stay in the log store; the snapshot is for display
and AI analysis).

Built-in hunt definitions live in ``data/hunts/*.yaml`` and are loaded by the
service; they are not duplicated in the database.
"""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class HuntQuery(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """One executed hunt against the event store."""

    __tablename__ = "hunt_queries"

    hunt_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # JSON list of MITRE ATT&CK technique ids.
    mitre_techniques: Mapped[str | None] = mapped_column(Text, nullable=True)
    time_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    time_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # JSON dict of the field filters used for the search.
    filters: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running", nullable=False)  # running|completed|failed
    matched_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # JSON summary (per-host / per-source breakdowns).
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<HuntQuery {self.hunt_id} {self.status} matched={self.matched_events}>"


class HuntResult(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A snapshot of one event matched by a hunt."""

    __tablename__ = "hunt_results"

    hunt_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    # JSON snapshot of the normalized event fields.
    event_fields: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<HuntResult {self.event_id} {self.reason}>"
