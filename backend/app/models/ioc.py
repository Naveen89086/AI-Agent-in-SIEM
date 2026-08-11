"""Indicators of Compromise (IOC) ORM models.

Three layers, mirroring the SCA/FIM real-mode agent contract:

- ``IocAgent``: an endpoint agent that observes indicators (network
  connections, file hashes, registry keys, e-mail addresses) and submits them
  through the authenticated ingest API.
- ``IocIndicator``: the threat-intelligence corpus. Seeded from the bundled
  offline list (``data/ioc/iocs.yaml``); online provider data is never stored
  without an explicit enrichment step.
- ``IocObservation`` / ``IocMatch``: the telemetry an agent reports and the
  deterministic verdict the server computes by looking the observation up in
  the indicator corpus. The server is the final authority: agents never
  declare an indicator malicious.
"""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

# Indicator types accepted by the lookup + ingest APIs.
IOC_TYPES = ("ipv4", "ipv6", "domain", "url", "filehash", "email", "registry")


class IocAgent(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """An endpoint agent that reports observed indicators."""

    __tablename__ = "ioc_agents"

    agent_code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operating_system: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[str] = mapped_column(String(32), default="windows", nullable=False)
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)  # online|offline|unknown
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Hash of the agent's API key (never stored in plaintext).
    api_key_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Stable machine fingerprint of the protected endpoint this agent belongs to.
    machine_guid: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)

    def __repr__(self) -> str:
        return f"<IocAgent {self.agent_code} ({self.hostname}) {self.status}>"


class IocIndicator(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """One indicator in the threat-intelligence corpus."""

    __tablename__ = "ioc_indicators"

    indicator_type: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    value: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(128), default="bundled", nullable=False)
    threat: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<IocIndicator {self.indicator_type}:{self.value} {self.severity}>"


class IocObservation(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """An indicator value an agent reports observing on an endpoint."""

    __tablename__ = "ioc_observations"

    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    # Where on the endpoint it was seen, e.g. "network.connection" or "file.hash".
    source: Mapped[str] = mapped_column(String(128), default="telemetry", nullable=False)
    # JSON context: process, path, user, ports, etc.
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_label: Mapped[str] = mapped_column(String(16), default="real_endpoint", nullable=False)

    def __repr__(self) -> str:
        return f"<IocObservation {self.indicator_type}:{self.value}>"


class IocMatch(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """The server-computed verdict for an observed indicator."""

    __tablename__ = "ioc_matches"

    observation_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    indicator_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    # malicious | suspicious | unknown  (never fabricated)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False)
    threat: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(128), default="bundled", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    source_label: Mapped[str] = mapped_column(String(16), default="real_endpoint", nullable=False)

    def __repr__(self) -> str:
        return f"<IocMatch {self.verdict} {self.indicator_type}:{self.value}>"
