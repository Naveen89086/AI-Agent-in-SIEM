"""SCA endpoint agent model.

Represents a real monitored endpoint that runs the lightweight agent process
(see the top-level ``agent/`` package). Agents register themselves, send
heartbeats and collect configuration evidence for scan jobs.
"""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Agent(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A monitored endpoint registered with the SCA subsystem."""

    __tablename__ = "sca_agents"

    agent_code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operating_system: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), default="windows", nullable=False)  # windows|linux|...
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)  # online|offline|unknown
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # URL the manager uses to push scan jobs / remediation actions to the agent.
    transport_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Hash of the agent's API key (never stored in plaintext).
    api_key_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    # Stable machine fingerprint of the protected endpoint this agent belongs to.
    machine_guid: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)

    def __repr__(self) -> str:
        return f"<Agent {self.agent_code} ({self.hostname}) {self.status}>"
