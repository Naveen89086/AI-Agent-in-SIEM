"""Network + Process/Service telemetry ORM models.

Mirrors the SCA/FIM/IOC/VULN real-mode agent contract. A single enrolled
``TelemetryAgent`` submits bounded snapshots through the authenticated ingest
API; the server upserts the live state so the dashboards always reflect the
current endpoint reality:

- ``TelemetryAgent``: the endpoint that reports telemetry (one API key shared
  by the network, process and service collectors).
- ``NetworkConnection`` / ``NetworkListener`` / ``NetworkInterface`` /
  ``NetworkStatistic``: the live network state (connections, listening
  sockets, interfaces, counters).
- ``ProcessRecord``: the live process table including tree relationships
  (parent pid), owners, CPU/memory usage and command lines.
- ``ServiceRecord``: the live Windows service table with state transitions.

Lifecycle transitions (connection NEW/CLOSED, process CREATED/TERMINATED,
service STARTED/STOPPED) are emitted as structured events through the generic
ingest pipeline so the correlation/detection engine can reason about them.
Live-state rows here are the *current snapshot*; the event store keeps the
history.
"""

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class TelemetryAgent(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """An endpoint agent that reports network/process/service telemetry."""

    __tablename__ = "telemetry_agents"

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
    # True when the row was seeded for development (never a real finding).
    demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Stable machine fingerprint of the protected endpoint this agent belongs to
    # (Windows MachineGuid). Guards ingestion so foreign devices cannot submit.
    machine_guid: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)

    def __repr__(self) -> str:
        return f"<TelemetryAgent {self.agent_code} ({self.hostname}) {self.status}>"


class NetworkConnection(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """One live network connection reported by an agent (upsert per conn_key)."""

    __tablename__ = "network_connections"

    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    # Stable fingerprint: proto|local_ip|local_port|foreign_ip|foreign_port.
    conn_key: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    proto: Mapped[str] = mapped_column(String(8), nullable=False)  # tcp|udp
    local_ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    local_port: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    foreign_ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    foreign_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    state: Mapped[str] = mapped_column(String(32), default="", nullable=False)  # ESTABLISHED, ...
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    executable: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # active | closed (closed rows are retained briefly for history/audit).
    status: Mapped[str] = mapped_column(String(16), default="active", index=True, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_label: Mapped[str] = mapped_column(String(16), default="real_endpoint", nullable=False)

    def __repr__(self) -> str:
        return f"<NetworkConnection {self.proto} {self.foreign_ip}:{self.foreign_port} {self.state}>"


class NetworkListener(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A listening socket reported by an agent (upsert per listen_key)."""

    __tablename__ = "network_listeners"

    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    listen_key: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    proto: Mapped[str] = mapped_column(String(8), nullable=False)  # tcp|udp
    ip: Mapped[str] = mapped_column(String(64), default="0.0.0.0", nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    executable: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="active", index=True, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_label: Mapped[str] = mapped_column(String(16), default="real_endpoint", nullable=False)

    def __repr__(self) -> str:
        return f"<NetworkListener {self.proto} {self.ip}:{self.port}>"


class NetworkInterface(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """One network interface (adapter) reported by an agent."""

    __tablename__ = "network_interfaces"

    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    mac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # JSON list of IP addresses assigned to the interface.
    addresses: Mapped[str | None] = mapped_column(Text, nullable=True)
    mtu: Mapped[int | None] = mapped_column(Integer, nullable=True)
    speed_mbps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="up", nullable=False)  # up|down
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_label: Mapped[str] = mapped_column(String(16), default="real_endpoint", nullable=False)

    def __repr__(self) -> str:
        return f"<NetworkInterface {self.name} {self.mac}>"


class NetworkStatistic(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """Latest cumulative network counters (rate computed on ingest delta)."""

    __tablename__ = "network_statistics"

    agent_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    bytes_sent: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    bytes_recv: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    packets_sent: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    packets_recv: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    # Bytes/second rates computed from the delta since the previous snapshot.
    tx_kbps: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    rx_kbps: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    connections_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    listeners_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_label: Mapped[str] = mapped_column(String(16), default="real_endpoint", nullable=False)

    def __repr__(self) -> str:
        return f"<NetworkStatistic agent={self.agent_id} rx={self.rx_kbps:.1f}kbps tx={self.tx_kbps:.1f}kbps>"


class ProcessRecord(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """One live process reported by an agent (upsert per (agent, pid))."""

    __tablename__ = "process_records"

    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    pid: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    executable: Mapped[str | None] = mapped_column(String(512), nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parent_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    memory_rss_mb: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    threads: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # running | terminated (terminated rows retained briefly for audit).
    status: Mapped[str] = mapped_column(String(16), default="running", index=True, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    terminated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_label: Mapped[str] = mapped_column(String(16), default="real_endpoint", nullable=False)

    def __repr__(self) -> str:
        return f"<ProcessRecord pid={self.pid} {self.name} {self.status}>"


class ServiceRecord(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """One Windows service reported by an agent (upsert per (agent, name))."""

    __tablename__ = "service_records"

    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # running | stopped | paused | start_pending | stop_pending ...
    state: Mapped[str] = mapped_column(String(32), default="stopped", nullable=False)
    start_type: Mapped[str | None] = mapped_column(String(32), nullable=True)  # auto|manual|disabled
    account: Mapped[str | None] = mapped_column(String(255), nullable=True)
    binary_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # started | stopped | created | deleted | changed ...
    last_event: Mapped[str | None] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_label: Mapped[str] = mapped_column(String(16), default="real_endpoint", nullable=False)

    def __repr__(self) -> str:
        return f"<ServiceRecord {self.name} {self.state}>"
