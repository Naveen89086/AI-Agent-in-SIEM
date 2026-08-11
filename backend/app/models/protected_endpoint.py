"""Protected endpoint ORM model.

Represents the single device this SIEM protects (the PC it runs on). Under the
default single-device model (``MAX_PROTECTED_ENDPOINTS=1``) at most one row can
exist and it is the canonical identity every subsystem agent belongs to.

The row is created/updated automatically when the endpoint agent registers
(any subsystem) or via ``POST /api/v1/protected-endpoint/register``. Its
``machine_guid`` is the stable, per-machine fingerprint (Windows MachineGuid)
the agent derives at runtime - never a random ID that changes across restarts.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ProtectedEndpoint(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """The one protected device (``id`` doubles as the endpoint_id)."""

    __tablename__ = "protected_endpoints"

    # Stable machine fingerprint (Windows MachineGuid / hashed identity). Unique:
    # one machine => one endpoint row.
    machine_guid: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    operating_system: Mapped[str] = mapped_column(String(255), default="Windows", nullable=False)
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Primary/latest IPv4 address reported by the local agent.
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # JSON lists of all addresses / MACs observed on the device.
    ip_addresses: Mapped[str | None] = mapped_column(Text, nullable=True)
    mac_addresses: Mapped[str | None] = mapped_column(Text, nullable=True)
    # online | offline | unknown | not_registered
    status: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # True when the row was created by a demo seed (never a real device).
    demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"<ProtectedEndpoint {self.hostname} ({self.machine_guid}) {self.status}>"
