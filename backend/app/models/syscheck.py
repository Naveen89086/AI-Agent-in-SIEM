"""Syscheck (File Integrity Monitoring) ORM models.

Mirrors Wazuh FIM modules: monitored agents, the file inventory (the
server-side baseline) and the syscheck event stream (added / modified /
deleted / renamed) that powers the FIM dashboard, inventory and events views.

In real mode the inventory rows are the authoritative baseline that the
server compares incoming agent evidence against - the server, never the agent,
is the final authority for event classification.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class SyscheckAgent(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """An endpoint monitored by the syscheck FIM module."""

    __tablename__ = "syscheck_agents"

    code: Mapped[str] = mapped_column(String(16), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), default="windows", nullable=False)
    os_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)
    registry_entries: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # --- enrollment / authentication (real mode) ---
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Hash of the agent's API key (never stored in plaintext).
    api_key_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Stable machine fingerprint of the protected endpoint this agent belongs to.
    machine_guid: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)

    def __repr__(self) -> str:
        return f"<SyscheckAgent {self.name} ({self.code})>"


class SyscheckFile(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A single monitored file in the FIM inventory (server-side baseline)."""

    __tablename__ = "syscheck_files"

    agent_id: Mapped[str] = mapped_column(
        ForeignKey("syscheck_agents.id"), index=True, nullable=False
    )
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    last_modified: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    user: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)

    # --- real-mode baseline fields (nullable for backward compatibility) ---
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    permissions: Mapped[str | None] = mapped_column(String(32), nullable=True)
    file_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # active | deleted (deleted rows are kept for audit/history)
    status: Mapped[str | None] = mapped_column(String(16), nullable=True)


class SyscheckEvent(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A FIM event (added / modified / deleted / renamed) captured by syscheck."""

    __tablename__ = "syscheck_events"

    agent_id: Mapped[str] = mapped_column(
        ForeignKey("syscheck_agents.id"), index=True, nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    event: Mapped[str] = mapped_column(String(16), index=True, nullable=False)  # added|modified|deleted
    user: Mapped[str] = mapped_column(String(64), nullable=False)
    rule: Mapped[str] = mapped_column(String(128), nullable=False)
    level: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_id: Mapped[int] = mapped_column(Integer, nullable=False)
    manager_name: Mapped[str] = mapped_column(String(64), default="kaliinux", nullable=False)

    # --- real-mode fields (nullable for backward compatibility) ---
    event_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    event_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    old_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    old_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    new_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
