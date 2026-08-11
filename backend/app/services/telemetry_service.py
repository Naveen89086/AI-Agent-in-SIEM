"""Network + Process/Service telemetry service.

A single enrolled ``TelemetryAgent`` submits bounded snapshots through the
authenticated ingest API (``/api/v1/telemetry/ingest``). The service:

- upserts the live-state tables (connections/listeners/interfaces/statistics,
  processes, services) so the dashboards always show the current endpoint
  reality, and
- emits lifecycle transitions (connection NEW/CLOSED, listener added/removed,
  process CREATED/TERMINATED, service created/state-change/deleted) as
  structured events that the router forwards through the generic ingest
  pipeline so the correlation/detection engine can reason about them.

The server never fabricates a verdict: transitions are observations, and any
severity/wording lives in the detection rules + AI analysis, not here.
"""

import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)
from app.models.telemetry import (
    NetworkConnection,
    NetworkInterface,
    NetworkListener,
    NetworkStatistic,
    ProcessRecord,
    ServiceRecord,
    TelemetryAgent,
)

log = logging.getLogger("siem.telemetry")

_PRIVATE_SUFFIXES = ()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _ts(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def conn_key(proto: str, local_ip: str, local_port: int, foreign_ip: str, foreign_port) -> str:
    return f"{proto}|{local_ip}|{local_port}|{foreign_ip}|{foreign_port or 0}"


def listen_key(proto: str, ip: str, port: int) -> str:
    return f"{proto}|{ip}|{port}"


class TelemetryService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # =================================================================== agents
    def agents(self) -> list[dict]:
        rows = self.db.execute(select(TelemetryAgent).order_by(TelemetryAgent.agent_code)).scalars().all()
        return [self._agent_dict(a) for a in rows]

    def register_agent(
        self,
        *,
        agent_code: str,
        hostname: str = "",
        ip_address: str = "",
        operating_system: str = "",
        platform: str = "windows",
        version: str = "1.0.0",
        machine_guid: str | None = None,
        registration_token: str | None = None,
    ) -> dict:
        if settings.telemetry_registration_token:
            if not registration_token or not secrets.compare_digest(
                registration_token, settings.telemetry_registration_token
            ):
                raise UnauthorizedError(
                    "Invalid registration token", code="invalid_registration_token"
                )
        agent_code = agent_code.strip()
        if not agent_code or len(agent_code) > 64:
            raise ValidationError("agent_code is required (max 64 chars)")

        existing = self.db.scalar(select(TelemetryAgent).where(TelemetryAgent.agent_code == agent_code))
        if existing is not None:
            raise ConflictError(f"Agent '{agent_code}' already registered")

        api_key = secrets.token_urlsafe(32)
        agent = TelemetryAgent(
            agent_code=agent_code,
            hostname=hostname or agent_code,
            ip_address=ip_address or None,
            operating_system=operating_system or "Windows",
            platform=platform or "windows",
            version=version or "1.0.0",
            status="online",
            last_seen=_now(),
            api_key_hash=_hash_api_key(api_key),
            enabled=True,
            demo=False,
            machine_guid=machine_guid or None,
        )
        self.db.add(agent)
        self.db.commit()
        self.db.refresh(agent)
        data = self._agent_dict(agent)
        data["api_key"] = api_key
        return data

    def heartbeat(self, agent_code: str, api_key: str, status: str = "online") -> dict:
        agent = self.db.scalar(select(TelemetryAgent).where(TelemetryAgent.agent_code == agent_code))
        if agent is None:
            raise NotFoundError(f"Agent '{agent_code}' not registered")
        if not agent.api_key_hash or not secrets.compare_digest(
            _hash_api_key(api_key), agent.api_key_hash
        ):
            raise UnauthorizedError("Invalid agent API key", code="invalid_api_key")
        agent.status = status if status in ("online", "offline") else "online"
        agent.last_seen = _now()
        self.db.commit()
        return self._agent_dict(agent)

    def _agent_dict(self, agent: TelemetryAgent) -> dict:
        return {
            "id": agent.id,
            "agent_code": agent.agent_code,
            "hostname": agent.hostname,
            "ip_address": agent.ip_address,
            "operating_system": agent.operating_system,
            "platform": agent.platform,
            "version": agent.version,
            "status": agent.status,
            "last_seen": _iso(agent.last_seen),
            "enabled": agent.enabled,
            "demo": bool(agent.demo),
        }

    # ================================================================== ingest
    def ingest_snapshot(
        self,
        *,
        agent_code: str,
        payload: dict,
        source_label: str = "real_endpoint",
    ) -> dict:
        """Accept a network/process/service snapshot and emit transitions.

        Returns ``{accepted, connections, listeners, processes, services,
        transitions}`` where ``transitions`` are structured events the caller
        forwards through the ingest pipeline.
        """
        agent = self.db.scalar(select(TelemetryAgent).where(TelemetryAgent.agent_code == agent_code))
        if agent is None:
            raise NotFoundError(f"Agent '{agent_code}' not registered")
        agent.status = "online"
        agent.last_seen = _now()

        transitions: list[dict] = []
        network = payload.get("network") or {}
        processes = payload.get("processes") or []
        services = payload.get("services") or []

        if not isinstance(network, dict) or not isinstance(processes, list) or not isinstance(services, list):
            raise ValidationError("payload must contain network: {}, processes: [], services: []")

        conn_counts = self._ingest_network(agent, network, source_label, transitions)
        proc_count = self._ingest_processes(agent, processes, source_label, transitions)
        serv_count = self._ingest_services(agent, services, source_label, transitions)

        self.db.commit()
        return {
            "agent_id": agent.id,
            "connections": conn_counts,
            "processes": proc_count,
            "services": serv_count,
            "transitions": transitions,
            "demo": bool(settings.network_demo_mode or settings.process_demo_mode),
        }

    # --------------------------------------------------------------- network
    def _ingest_network(
        self,
        agent: TelemetryAgent,
        network: dict,
        source_label: str,
        transitions: list[dict],
    ) -> dict:
        now = _now()
        result = {"new": 0, "closed": 0, "active": 0, "listeners": 0}

        # ---- connections
        incoming_keys: set[str] = set()
        for item in network.get("connections") or []:
            if not isinstance(item, dict):
                continue
            proto = str(item.get("proto", "tcp")).lower()
            local_ip = str(item.get("local_ip", ""))
            local_port = int(item.get("local_port") or 0)
            foreign_ip = str(item.get("foreign_ip", ""))
            foreign_port = item.get("foreign_port")
            key = conn_key(proto, local_ip, local_port, foreign_ip, foreign_port)
            incoming_keys.add(key)
            row = self.db.scalar(
                select(NetworkConnection).where(
                    NetworkConnection.agent_id == agent.id,
                    NetworkConnection.conn_key == key,
                )
            )
            if row is None:
                row = NetworkConnection(
                    agent_id=agent.id,
                    conn_key=key,
                    proto=proto,
                    local_ip=local_ip,
                    local_port=local_port,
                    foreign_ip=foreign_ip,
                    foreign_port=foreign_port,
                    state=str(item.get("state", "")),
                    pid=item.get("pid"),
                    process_name=item.get("process_name"),
                    user=item.get("user"),
                    executable=item.get("executable"),
                    is_private=bool(item.get("is_private", False)),
                    status="active",
                    first_seen=now,
                    last_seen=now,
                    source_label=source_label,
                )
                self.db.add(row)
                result["new"] += 1
                transitions.append(
                    self._transition(
                        agent,
                        action="connection_new",
                        category="network",
                        message=(
                            f"New {proto.upper()} connection from {local_ip}:{local_port} "
                            f"to {foreign_ip}:{foreign_port} ({item.get('process_name') or 'unknown'})"
                        ),
                        extra={
                            "event_action": "connection_new",
                            "direction": "outbound" if not row.is_private else "inbound",
                            "network": {
                                "transport": proto,
                                "protocol": proto,
                                "direction": "outbound" if not row.is_private else "inbound",
                            },
                            "source": {"ip": local_ip, "port": local_port},
                            "destination": {"ip": foreign_ip, "port": foreign_port},
                            "process": {
                                "name": item.get("process_name"),
                                "pid": item.get("pid"),
                                "executable": item.get("executable"),
                            },
                            "user": {"name": item.get("user")},
                        },
                        tags=["network", "connection", "observed"],
                    )
                )
            else:
                row.state = str(item.get("state", row.state))
                row.pid = item.get("pid")
                row.process_name = item.get("process_name")
                row.user = item.get("user")
                row.executable = item.get("executable")
                row.is_private = bool(item.get("is_private", row.is_private))
                row.status = "active"
                row.last_seen = now
                result["active"] += 1

        # ---- close vanished connections
        active_rows = self.db.execute(
            select(NetworkConnection).where(
                NetworkConnection.agent_id == agent.id,
                NetworkConnection.status == "active",
            )
        ).scalars().all()
        for row in active_rows:
            if row.conn_key not in incoming_keys:
                row.status = "closed"
                row.closed_at = now
                result["closed"] += 1
                transitions.append(
                    self._transition(
                        agent,
                        action="connection_closed",
                        category="network",
                        message=f"{row.proto.upper()} connection to {row.foreign_ip}:{row.foreign_port} closed",
                        extra={
                            "event_action": "connection_closed",
                            "network": {"transport": row.proto, "protocol": row.proto},
                            "source": {"ip": row.local_ip, "port": row.local_port},
                            "destination": {"ip": row.foreign_ip, "port": row.foreign_port},
                            "process": {"name": row.process_name, "pid": row.pid},
                        },
                        tags=["network", "connection", "observed"],
                    )
                )

        # ---- listeners
        incoming_listeners: set[str] = set()
        for item in network.get("listeners") or []:
            if not isinstance(item, dict):
                continue
            proto = str(item.get("proto", "tcp")).lower()
            ip = str(item.get("ip", "0.0.0.0"))
            port = int(item.get("port") or 0)
            key = listen_key(proto, ip, port)
            incoming_listeners.add(key)
            row = self.db.scalar(
                select(NetworkListener).where(
                    NetworkListener.agent_id == agent.id,
                    NetworkListener.listen_key == key,
                )
            )
            if row is None:
                row = NetworkListener(
                    agent_id=agent.id,
                    listen_key=key,
                    proto=proto,
                    ip=ip,
                    port=port,
                    pid=item.get("pid"),
                    process_name=item.get("process_name"),
                    user=item.get("user"),
                    executable=item.get("executable"),
                    status="active",
                    first_seen=now,
                    last_seen=now,
                    source_label=source_label,
                )
                self.db.add(row)
                result["listeners"] += 1
                transitions.append(
                    self._transition(
                        agent,
                        action="listener_added",
                        category="network",
                        message=f"{proto.upper()} listening on {ip}:{port} ({item.get('process_name') or 'unknown'})",
                        extra={
                            "event_action": "listener_added",
                            "network": {"transport": proto, "protocol": proto},
                            "destination": {"ip": ip, "port": port},
                            "process": {"name": item.get("process_name"), "pid": item.get("pid")},
                        },
                        tags=["network", "listening", "observed"],
                    )
                )
            else:
                row.pid = item.get("pid")
                row.process_name = item.get("process_name")
                row.user = item.get("user")
                row.executable = item.get("executable")
                row.status = "active"
                row.last_seen = now
        vanished = self.db.execute(
            select(NetworkListener).where(
                NetworkListener.agent_id == agent.id,
                NetworkListener.status == "active",
            )
        ).scalars().all()
        for row in vanished:
            if row.listen_key not in incoming_listeners:
                row.status = "removed"

        # ---- interfaces
        for item in network.get("interfaces") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            row = self.db.scalar(
                select(NetworkInterface).where(
                    NetworkInterface.agent_id == agent.id,
                    NetworkInterface.name == name,
                )
            )
            addresses = json.dumps(item.get("addresses") or [])
            if row is None:
                self.db.add(
                    NetworkInterface(
                        agent_id=agent.id,
                        name=name,
                        mac=item.get("mac"),
                        addresses=addresses,
                        mtu=item.get("mtu"),
                        speed_mbps=item.get("speed_mbps"),
                        status=str(item.get("status", "up")),
                        first_seen=now,
                        last_seen=now,
                        source_label=source_label,
                    )
                )
            else:
                row.mac = item.get("mac")
                row.addresses = addresses
                row.mtu = item.get("mtu")
                row.speed_mbps = item.get("speed_mbps")
                row.status = str(item.get("status", row.status))
                row.last_seen = now

        # ---- statistics
        self._ingest_statistics(agent, network.get("statistics"), source_label, now)
        return result

    def _ingest_statistics(self, agent: TelemetryAgent, stats: dict | None, source_label: str, now: datetime) -> None:
        if not isinstance(stats, dict):
            return
        row = self.db.scalar(select(NetworkStatistic).where(NetworkStatistic.agent_id == agent.id))
        bytes_sent = int(stats.get("bytes_sent") or 0)
        bytes_recv = int(stats.get("bytes_recv") or 0)
        packets_sent = int(stats.get("packets_sent") or 0)
        packets_recv = int(stats.get("packets_recv") or 0)
        connections = int(stats.get("connections_total") or 0)
        listeners = int(stats.get("listeners_total") or 0)
        tx_kbps = 0.0
        rx_kbps = 0.0
        if row is not None and row.observed_at:
            observed = row.observed_at
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            elapsed = max((now - observed).total_seconds(), 1.0)
            tx_kbps = max(0.0, (bytes_sent - row.bytes_sent) * 8 / 1000 / elapsed)
            rx_kbps = max(0.0, (bytes_recv - row.bytes_recv) * 8 / 1000 / elapsed)
            row.bytes_sent = bytes_sent
            row.bytes_recv = bytes_recv
            row.packets_sent = packets_sent
            row.packets_recv = packets_recv
            row.tx_kbps = tx_kbps
            row.rx_kbps = rx_kbps
            row.connections_total = connections
            row.listeners_total = listeners
            row.observed_at = now
            row.source_label = source_label
        else:
            self.db.add(
                NetworkStatistic(
                    agent_id=agent.id,
                    bytes_sent=bytes_sent,
                    bytes_recv=bytes_recv,
                    packets_sent=packets_sent,
                    packets_recv=packets_recv,
                    tx_kbps=0.0,
                    rx_kbps=0.0,
                    connections_total=connections,
                    listeners_total=listeners,
                    observed_at=now,
                    source_label=source_label,
                )
            )

    # -------------------------------------------------------------- processes
    def _ingest_processes(
        self,
        agent: TelemetryAgent,
        processes: list[dict],
        source_label: str,
        transitions: list[dict],
    ) -> dict:
        now = _now()
        incoming_pids: set[int] = set()
        created = 0
        terminated = 0
        for item in processes:
            if not isinstance(item, dict):
                continue
            try:
                pid = int(item.get("pid"))
            except (TypeError, ValueError):
                continue
            incoming_pids.add(pid)
            row = self.db.scalar(
                select(ProcessRecord).where(
                    ProcessRecord.agent_id == agent.id,
                    ProcessRecord.pid == pid,
                )
            )
            started_at = _ts(item.get("started_at"))
            if row is None:
                row = ProcessRecord(
                    agent_id=agent.id,
                    pid=pid,
                    name=str(item.get("name") or f"pid-{pid}"),
                    executable=item.get("executable"),
                    command_line=item.get("command_line"),
                    parent_pid=item.get("parent_pid"),
                    parent_name=item.get("parent_name"),
                    user=item.get("user"),
                    cpu_percent=float(item.get("cpu_percent") or 0.0),
                    memory_rss_mb=float(item.get("memory_rss_mb") or 0.0),
                    threads=int(item.get("threads") or 0),
                    started_at=started_at,
                    status="running",
                    first_seen=now,
                    last_seen=now,
                    source_label=source_label,
                )
                self.db.add(row)
                created += 1
                transitions.append(
                    self._transition(
                        agent,
                        action="process_created",
                        category="process",
                        message=f"Process created: {item.get('name')} (pid {pid}, parent {item.get('parent_name') or 'unknown'})",
                        extra={
                            "event_action": "process_created",
                            "process": {
                                "name": item.get("name"),
                                "pid": pid,
                                "executable": item.get("executable"),
                                "command_line": item.get("command_line"),
                                "parent": {
                                    "pid": item.get("parent_pid"),
                                    "name": item.get("parent_name"),
                                },
                            },
                            "user": {"name": item.get("user")},
                        },
                        tags=["process", "creation", "observed"],
                    )
                )
            else:
                row.name = str(item.get("name") or row.name)
                row.executable = item.get("executable")
                row.command_line = item.get("command_line")
                row.parent_pid = item.get("parent_pid")
                row.parent_name = item.get("parent_name")
                row.user = item.get("user")
                row.cpu_percent = float(item.get("cpu_percent") or 0.0)
                row.memory_rss_mb = float(item.get("memory_rss_mb") or 0.0)
                row.threads = int(item.get("threads") or 0)
                row.started_at = started_at or row.started_at
                row.status = "running"
                row.last_seen = now

        running = self.db.execute(
            select(ProcessRecord).where(
                ProcessRecord.agent_id == agent.id,
                ProcessRecord.status == "running",
            )
        ).scalars().all()
        for row in running:
            if row.pid not in incoming_pids:
                row.status = "terminated"
                row.terminated_at = now
                terminated += 1
                transitions.append(
                    self._transition(
                        agent,
                        action="process_terminated",
                        category="process",
                        message=f"Process terminated: {row.name} (pid {row.pid})",
                        extra={
                            "event_action": "process_terminated",
                            "process": {"name": row.name, "pid": row.pid},
                        },
                        tags=["process", "termination", "observed"],
                    )
                )
        return {"created": created, "terminated": terminated, "active": len(incoming_pids)}

    # ---------------------------------------------------------------- services
    def _ingest_services(
        self,
        agent: TelemetryAgent,
        services: list[dict],
        source_label: str,
        transitions: list[dict],
    ) -> dict:
        now = _now()
        incoming_names: set[str] = set()
        created = 0
        changed = 0
        deleted = 0
        for item in services:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            incoming_names.add(name)
            state = str(item.get("state") or "stopped")
            row = self.db.scalar(
                select(ServiceRecord).where(
                    ServiceRecord.agent_id == agent.id,
                    ServiceRecord.name == name,
                )
            )
            if row is None:
                row = ServiceRecord(
                    agent_id=agent.id,
                    name=name,
                    display_name=item.get("display_name"),
                    state=state,
                    start_type=item.get("start_type"),
                    account=item.get("account"),
                    binary_path=item.get("binary_path"),
                    pid=item.get("pid"),
                    last_event="created",
                    first_seen=now,
                    last_seen=now,
                    changed_at=now,
                    source_label=source_label,
                )
                self.db.add(row)
                created += 1
                transitions.append(
                    self._transition(
                        agent,
                        action="service_created",
                        category="application",
                        message=f"Service created: {name} ({item.get('display_name') or 'no display name'})",
                        extra={
                            "event_action": "service_created",
                            "service": {
                                "name": name,
                                "display_name": item.get("display_name"),
                                "state": state,
                                "start_type": item.get("start_type"),
                                "account": item.get("account"),
                            },
                            "process": {"pid": item.get("pid")},
                        },
                        tags=["service", "creation", "observed"],
                    )
                )
            else:
                old_state = row.state
                row.display_name = item.get("display_name") or row.display_name
                row.state = state
                row.start_type = item.get("start_type") or row.start_type
                row.account = item.get("account") or row.account
                row.binary_path = item.get("binary_path") or row.binary_path
                row.pid = item.get("pid")
                row.last_seen = now
                if old_state != state:
                    row.changed_at = now
                    changed += 1
                    action = "service_started" if state == "running" else "service_stopped"
                    transitions.append(
                        self._transition(
                            agent,
                            action=action,
                            category="application",
                            message=f"Service state change: {name} {old_state} -> {state}",
                            extra={
                                "event_action": action,
                                "service": {
                                    "name": name,
                                    "state": state,
                                    "previous_state": old_state,
                                    "start_type": row.start_type,
                                    "account": row.account,
                                },
                                "process": {"pid": item.get("pid")},
                            },
                            tags=["service", "state-change", "observed"],
                        )
                    )

        existing = self.db.execute(
            select(ServiceRecord).where(ServiceRecord.agent_id == agent.id)
        ).scalars().all()
        for row in existing:
            if row.name not in incoming_names:
                deleted += 1
                transitions.append(
                    self._transition(
                        agent,
                        action="service_deleted",
                        category="application",
                        message=f"Service no longer present: {row.name}",
                        extra={
                            "event_action": "service_deleted",
                            "service": {"name": row.name, "state": row.state},
                        },
                        tags=["service", "removal", "observed"],
                    )
                )
                self.db.delete(row)
        return {"created": created, "changed": changed, "deleted": deleted, "active": len(incoming_names)}

    # ============================================================ serialization
    def _transition(self, agent: TelemetryAgent, *, action: str, category: str, message: str, extra: dict, tags: list[str]) -> dict:
        """A structured event the ingest pipeline consumes (RawEventIn-shaped)."""
        return {
            "message": message,
            "source_type": "endpoint",
            "source_name": "endpoint-agent",
            "host": agent.hostname,
            "extra": {
                "parser": "endpoint_telemetry",
                "event_action": action,
                "event_category": category,
                "agent_code": agent.agent_code,
                **extra,
            },
            "tags": tags,
        }

    # ================================================================== queries
    def _agent_names(self) -> dict[str, str]:
        return {
            a.id: f"{a.hostname} ({a.agent_code})"
            for a in self.db.execute(select(TelemetryAgent)).scalars().all()
        }

    def network_dashboard(self) -> dict:
        agents = list(self.db.execute(select(TelemetryAgent)).scalars().all())
        agent_names = self._agent_names()
        connections = self.db.execute(
            select(NetworkConnection).where(NetworkConnection.status == "active")
        ).scalars().all()
        listeners = self.db.execute(
            select(NetworkListener).where(NetworkListener.status == "active")
        ).scalars().all()
        interfaces = self.db.execute(select(NetworkInterface)).scalars().all()
        stats = self.db.execute(select(NetworkStatistic)).scalars().all()

        tx = sum(s.tx_kbps for s in stats)
        rx = sum(s.rx_kbps for s in stats)
        total_sent = sum(s.bytes_sent for s in stats)
        total_recv = sum(s.bytes_recv for s in stats)

        top_processes: dict[str, dict] = {}
        for c in connections:
            key = c.process_name or "unknown"
            entry = top_processes.setdefault(key, {"name": key, "count": 0})
            entry["count"] += 1
        top = sorted(top_processes.values(), key=lambda e: e["count"], reverse=True)[:10]

        return {
            "demo": bool(settings.network_demo_mode),
            "agents_total": len(agents),
            "agents_online": sum(1 for a in agents if a.status == "online"),
            "connections_total": len(connections),
            "listeners_total": len(listeners),
            "interfaces_total": len(interfaces),
            "tx_kbps": round(tx, 1),
            "rx_kbps": round(rx, 1),
            "bytes_sent": total_sent,
            "bytes_recv": total_recv,
            "top_processes": top,
            "interfaces": [self._interface_dict(i, agent_names) for i in interfaces],
        }

    def network_connections(
        self,
        *,
        agent_id: str | None = None,
        state: str | None = None,
        search: str = "",
    ) -> list[dict]:
        query = select(NetworkConnection).where(NetworkConnection.status == "active")
        if agent_id:
            query = query.where(NetworkConnection.agent_id == agent_id)
        if state:
            query = query.where(NetworkConnection.state == state)
        q = search.strip().lower()
        if q:
            query = query.where(
                NetworkConnection.foreign_ip.ilike(f"%{q}%")
                | NetworkConnection.process_name.ilike(f"%{q}%")
                | NetworkConnection.user.ilike(f"%{q}%")
            )
        rows = self.db.execute(
            query.order_by(NetworkConnection.last_seen.desc())
        ).scalars().all()
        agent_names = self._agent_names()
        return [self._connection_dict(c, agent_names) for c in rows]

    def network_listening(
        self,
        *,
        agent_id: str | None = None,
        search: str = "",
    ) -> list[dict]:
        query = select(NetworkListener).where(NetworkListener.status == "active")
        if agent_id:
            query = query.where(NetworkListener.agent_id == agent_id)
        q = search.strip().lower()
        if q:
            query = query.where(
                NetworkListener.process_name.ilike(f"%{q}%")
                | NetworkListener.ip.ilike(f"%{q}%")
            )
        rows = self.db.execute(
            query.order_by(NetworkListener.port)
        ).scalars().all()
        agent_names = self._agent_names()
        return [self._listener_dict(l, agent_names) for l in rows]

    def network_interfaces(self, *, agent_id: str | None = None) -> list[dict]:
        query = select(NetworkInterface)
        if agent_id:
            query = query.where(NetworkInterface.agent_id == agent_id)
        rows = self.db.execute(query.order_by(NetworkInterface.name)).scalars().all()
        agent_names = self._agent_names()
        return [self._interface_dict(i, agent_names) for i in rows]

    def network_statistics(self, *, agent_id: str | None = None) -> list[dict]:
        query = select(NetworkStatistic)
        if agent_id:
            query = query.where(NetworkStatistic.agent_id == agent_id)
        rows = self.db.execute(query).scalars().all()
        agent_names = self._agent_names()
        return [self._statistics_dict(s, agent_names) for s in rows]

    def process_summary(self) -> dict:
        agents = list(self.db.execute(select(TelemetryAgent)).scalars().all())
        running = self.db.execute(
            select(func.count()).select_from(ProcessRecord).where(ProcessRecord.status == "running")
        ).scalar() or 0
        services = self.db.execute(
            select(func.count()).select_from(ServiceRecord)
        ).scalar() or 0
        services_running = self.db.execute(
            select(func.count()).select_from(ServiceRecord).where(ServiceRecord.state == "running")
        ).scalar() or 0
        service_changes = self.db.execute(
            select(func.count()).select_from(ServiceRecord).where(ServiceRecord.changed_at.is_not(None))
        ).scalar() or 0
        return {
            "demo": bool(settings.process_demo_mode),
            "agents_total": len(agents),
            "processes_running": running,
            "services_total": services,
            "services_running": services_running,
            "service_changes": service_changes,
            "top_cpu": self._top_processes(limit=10, order_by=ProcessRecord.cpu_percent),
            "top_memory": self._top_processes(limit=10, order_by=ProcessRecord.memory_rss_mb),
        }

    def _top_processes(self, *, limit: int, order_by) -> list[dict]:
        rows = self.db.execute(
            select(ProcessRecord)
            .where(ProcessRecord.status == "running")
            .order_by(order_by.desc())
            .limit(limit)
        ).scalars().all()
        agent_names = self._agent_names()
        return [self._process_dict(p, agent_names) for p in rows]

    def processes(
        self,
        *,
        agent_id: str | None = None,
        search: str = "",
        status: str = "running",
    ) -> list[dict]:
        query = select(ProcessRecord)
        if agent_id:
            query = query.where(ProcessRecord.agent_id == agent_id)
        if status:
            query = query.where(ProcessRecord.status == status)
        q = search.strip().lower()
        if q:
            query = query.where(
                ProcessRecord.name.ilike(f"%{q}%")
                | ProcessRecord.executable.ilike(f"%{q}%")
                | ProcessRecord.user.ilike(f"%{q}%")
            )
        rows = self.db.execute(query.order_by(ProcessRecord.cpu_percent.desc())).scalars().all()
        agent_names = self._agent_names()
        return [self._process_dict(p, agent_names) for p in rows]

    def process_detail(self, pid: int, *, agent_id: str | None = None) -> dict:
        query = select(ProcessRecord).where(ProcessRecord.pid == pid)
        if agent_id:
            query = query.where(ProcessRecord.agent_id == agent_id)
        rows = self.db.execute(query.order_by(ProcessRecord.last_seen.desc())).scalars().all()
        if not rows:
            raise NotFoundError(f"Process pid {pid} not found")
        agent_names = self._agent_names()
        return self._process_dict(rows[0], agent_names)

    def process_tree(self, pid: int, *, agent_id: str | None = None) -> list[dict]:
        """Return the process tree rooted at ``pid`` (children via parent_pid)."""
        query = select(ProcessRecord).where(ProcessRecord.status == "running")
        if agent_id:
            query = query.where(ProcessRecord.agent_id == agent_id)
        rows = self.db.execute(query).scalars().all()
        by_pid = {p.pid: p for p in rows}
        root = by_pid.get(pid)
        if root is None:
            raise NotFoundError(f"Process pid {pid} not found")
        agent_names = self._agent_names()
        children: dict[int, list[int]] = {}
        for p in rows:
            if p.parent_pid in by_pid and p.parent_pid != p.pid:
                children.setdefault(p.parent_pid, []).append(p.pid)
        out: list[dict] = []
        seen: set[int] = set()

        def walk(node_pid: int, depth: int) -> None:
            node = by_pid.get(node_pid)
            if node is None or node_pid in seen:
                return
            seen.add(node_pid)
            out.append({**self._process_dict(node, agent_names), "depth": depth})
            for child in sorted(children.get(node_pid, [])):
                walk(child, depth + 1)

        walk(pid, 0)
        return out

    def services(
        self,
        *,
        agent_id: str | None = None,
        search: str = "",
        state: str | None = None,
    ) -> list[dict]:
        query = select(ServiceRecord)
        if agent_id:
            query = query.where(ServiceRecord.agent_id == agent_id)
        if state:
            query = query.where(ServiceRecord.state == state)
        q = search.strip().lower()
        if q:
            query = query.where(
                ServiceRecord.name.ilike(f"%{q}%")
                | ServiceRecord.display_name.ilike(f"%{q}%")
                | ServiceRecord.account.ilike(f"%{q}%")
            )
        rows = self.db.execute(query.order_by(ServiceRecord.name)).scalars().all()
        agent_names = self._agent_names()
        return [self._service_dict(s, agent_names) for s in rows]

    def service_detail(self, name: str, *, agent_id: str | None = None) -> dict:
        query = select(ServiceRecord).where(ServiceRecord.name == name)
        if agent_id:
            query = query.where(ServiceRecord.agent_id == agent_id)
        rows = self.db.execute(query.order_by(ServiceRecord.last_seen.desc())).scalars().all()
        if not rows:
            raise NotFoundError(f"Service '{name}' not found")
        agent_names = self._agent_names()
        return self._service_dict(rows[0], agent_names)

    # ============================================================== serializers
    def _connection_dict(self, row: NetworkConnection, agent_names) -> dict:
        return {
            "id": row.id,
            "agent_id": row.agent_id,
            "agent": agent_names.get(row.agent_id),
            "proto": row.proto,
            "local_ip": row.local_ip,
            "local_port": row.local_port,
            "foreign_ip": row.foreign_ip,
            "foreign_port": row.foreign_port,
            "state": row.state,
            "pid": row.pid,
            "process_name": row.process_name,
            "user": row.user,
            "executable": row.executable,
            "is_private": row.is_private,
            "first_seen": _iso(row.first_seen),
            "last_seen": _iso(row.last_seen),
            "source_label": row.source_label,
            "demo": bool(settings.network_demo_mode),
        }

    def _listener_dict(self, row: NetworkListener, agent_names) -> dict:
        return {
            "id": row.id,
            "agent_id": row.agent_id,
            "agent": agent_names.get(row.agent_id),
            "proto": row.proto,
            "ip": row.ip,
            "port": row.port,
            "pid": row.pid,
            "process_name": row.process_name,
            "user": row.user,
            "executable": row.executable,
            "first_seen": _iso(row.first_seen),
            "last_seen": _iso(row.last_seen),
            "source_label": row.source_label,
            "demo": bool(settings.network_demo_mode),
        }

    def _interface_dict(self, row: NetworkInterface, agent_names) -> dict:
        return {
            "id": row.id,
            "agent_id": row.agent_id,
            "agent": agent_names.get(row.agent_id),
            "name": row.name,
            "mac": row.mac,
            "addresses": json.loads(row.addresses) if row.addresses else [],
            "mtu": row.mtu,
            "speed_mbps": row.speed_mbps,
            "status": row.status,
            "first_seen": _iso(row.first_seen),
            "last_seen": _iso(row.last_seen),
            "source_label": row.source_label,
            "demo": bool(settings.network_demo_mode),
        }

    def _statistics_dict(self, row: NetworkStatistic, agent_names) -> dict:
        return {
            "id": row.id,
            "agent_id": row.agent_id,
            "agent": agent_names.get(row.agent_id),
            "bytes_sent": row.bytes_sent,
            "bytes_recv": row.bytes_recv,
            "packets_sent": row.packets_sent,
            "packets_recv": row.packets_recv,
            "tx_kbps": round(row.tx_kbps, 1),
            "rx_kbps": round(row.rx_kbps, 1),
            "connections_total": row.connections_total,
            "listeners_total": row.listeners_total,
            "observed_at": _iso(row.observed_at),
            "source_label": row.source_label,
            "demo": bool(settings.network_demo_mode),
        }

    def _process_dict(self, row: ProcessRecord, agent_names) -> dict:
        return {
            "id": row.id,
            "agent_id": row.agent_id,
            "agent": agent_names.get(row.agent_id),
            "pid": row.pid,
            "name": row.name,
            "executable": row.executable,
            "command_line": row.command_line,
            "parent_pid": row.parent_pid,
            "parent_name": row.parent_name,
            "user": row.user,
            "cpu_percent": round(row.cpu_percent, 1),
            "memory_rss_mb": round(row.memory_rss_mb, 1),
            "threads": row.threads,
            "started_at": _iso(row.started_at),
            "status": row.status,
            "first_seen": _iso(row.first_seen),
            "last_seen": _iso(row.last_seen),
            "terminated_at": _iso(row.terminated_at),
            "source_label": row.source_label,
            "demo": bool(settings.process_demo_mode),
        }

    def _service_dict(self, row: ServiceRecord, agent_names) -> dict:
        return {
            "id": row.id,
            "agent_id": row.agent_id,
            "agent": agent_names.get(row.agent_id),
            "name": row.name,
            "display_name": row.display_name,
            "state": row.state,
            "start_type": row.start_type,
            "account": row.account,
            "binary_path": row.binary_path,
            "pid": row.pid,
            "last_event": row.last_event,
            "first_seen": _iso(row.first_seen),
            "last_seen": _iso(row.last_seen),
            "changed_at": _iso(row.changed_at),
            "source_label": row.source_label,
            "demo": bool(settings.process_demo_mode),
        }
