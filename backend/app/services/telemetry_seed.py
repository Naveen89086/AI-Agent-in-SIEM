"""Deterministic demo seed for the network + process/service monitoring modules.

Demo mode only (``NETWORK_DEMO_MODE`` / ``PROCESS_DEMO_MODE``). Seeded once on
startup when the tables are empty so the monitoring dashboards are fully backed
by the database. Every row carries ``source_label="demo"`` and the agent
``demo=True`` so it can never be mistaken for a real endpoint finding.

When demo mode is disabled, no demo rows are generated and data comes only from
enrolled endpoint agents through the authenticated telemetry ingest API.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.telemetry import (
    NetworkConnection,
    NetworkInterface,
    NetworkListener,
    NetworkStatistic,
    ProcessRecord,
    ServiceRecord,
    TelemetryAgent,
)
from app.services.telemetry_service import conn_key, listen_key

log = logging.getLogger("siem.telemetry_seed")

# Single-device model: demo telemetry reflects ONE protected endpoint.
DEMO_TELEMETRY_AGENTS = [
    {"agent_code": "telemetry-win-001", "hostname": "WORKSTATION-01", "ip_address": "10.10.10.31"},
]

# Demo network state (clearly labeled demo; nothing claims to be a real finding).
DEMO_CONNECTIONS = {
    "telemetry-win-001": [
        {"proto": "tcp", "local_ip": "10.10.10.31", "local_port": 51234, "foreign_ip": "142.250.191.14", "foreign_port": 443, "state": "ESTABLISHED", "pid": 4212, "process_name": "chrome.exe", "user": "analyst", "executable": r"C:\Program Files\Google\Chrome\Application\chrome.exe"},
        {"proto": "tcp", "local_ip": "10.10.10.31", "local_port": 51235, "foreign_ip": "40.77.226.42", "foreign_port": 80, "state": "ESTABLISHED", "pid": 3456, "process_name": "MsMpEng.exe", "user": "SYSTEM", "executable": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.22000.5\MsMpEng.exe"},
        {"proto": "tcp", "local_ip": "10.10.10.31", "local_port": 49872, "foreign_ip": "10.10.10.20", "foreign_port": 445, "state": "ESTABLISHED", "pid": 812, "process_name": "svchost.exe", "user": "NETWORK SERVICE", "executable": r"C:\Windows\System32\svchost.exe"},
        {"proto": "tcp", "local_ip": "10.10.10.31", "local_port": 60123, "foreign_ip": "45.83.193.105", "foreign_port": 4444, "state": "ESTABLISHED", "pid": 9988, "process_name": "update.exe", "user": "analyst", "executable": r"C:\Users\analyst\AppData\Local\Temp\update.exe"},
    ],
    "telemetry-win-002": [
        {"proto": "tcp", "local_ip": "10.10.10.11", "local_port": 443, "foreign_ip": "10.10.10.31", "foreign_port": 52110, "state": "ESTABLISHED", "pid": 5678, "process_name": "java.exe", "user": "svc-app", "executable": r"C:\Program Files\Java\jre1.8.0_401\bin\java.exe"},
    ],
}

DEMO_LISTENERS = {
    "telemetry-win-001": [
        {"proto": "tcp", "ip": "0.0.0.0", "port": 135, "pid": 812, "process_name": "svchost.exe", "user": "NETWORK SERVICE"},
        {"proto": "tcp", "ip": "0.0.0.0", "port": 445, "pid": 4, "process_name": "System", "user": "SYSTEM"},
        {"proto": "tcp", "ip": "0.0.0.0", "port": 3389, "pid": 1092, "process_name": "svchost.exe", "user": "NETWORK SERVICE"},
        {"proto": "tcp", "ip": "127.0.0.1", "port": 8000, "pid": 5678, "process_name": "java.exe", "user": "svc-app"},
    ],
    "telemetry-win-002": [
        {"proto": "tcp", "ip": "0.0.0.0", "port": 443, "pid": 5678, "process_name": "java.exe", "user": "svc-app"},
        {"proto": "tcp", "ip": "0.0.0.0", "port": 3389, "pid": 1092, "process_name": "svchost.exe", "user": "NETWORK SERVICE"},
    ],
}

DEMO_INTERFACES = {
    "telemetry-win-001": [
        {"name": "Ethernet", "mac": "00:15:5d:01:aa:01", "addresses": ["10.10.10.31", "fe80::1111:2222:3333:4444%5"], "mtu": 1500, "speed_mbps": 1000, "status": "up"},
        {"name": "Loopback Pseudo-Interface 1", "mac": None, "addresses": ["127.0.0.1", "::1"], "mtu": 65536, "speed_mbps": None, "status": "up"},
    ],
    "telemetry-win-002": [
        {"name": "Ethernet0", "mac": "00:15:5d:01:bb:02", "addresses": ["10.10.10.11", "fe80::9999:aaaa:bbbb:cccc%4"], "mtu": 1500, "speed_mbps": 1000, "status": "up"},
    ],
}

DEMO_STATISTICS = {
    "telemetry-win-001": {
        "bytes_sent": 3_847_221_055,
        "bytes_recv": 12_842_994_100,
        "packets_sent": 8_421_198,
        "packets_recv": 22_190_442,
        "tx_kbps": 42.0,
        "rx_kbps": 128.5,
        "connections_total": 4,
        "listeners_total": 4,
    },
    "telemetry-win-002": {
        "bytes_sent": 22_912_045_000,
        "bytes_recv": 9_104_221_000,
        "packets_sent": 41_220_014,
        "packets_recv": 17_884_033,
        "tx_kbps": 812.0,
        "rx_kbps": 340.2,
        "connections_total": 1,
        "listeners_total": 2,
    },
}

# Demo process table (includes a parent/child tree).
DEMO_PROCESSES = {
    "telemetry-win-001": [
        {"pid": 4, "name": "System", "executable": r"C:\Windows\System32\ntoskrnl.exe", "command_line": "", "parent_pid": 0, "parent_name": None, "user": "SYSTEM", "cpu_percent": 0.1, "memory_rss_mb": 24.0, "threads": 204, "started_at_days": 42},
        {"pid": 812, "name": "svchost.exe", "executable": r"C:\Windows\System32\svchost.exe", "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", "parent_pid": 4, "parent_name": "System", "user": "SYSTEM", "cpu_percent": 0.4, "memory_rss_mb": 91.3, "threads": 31, "started_at_days": 42},
        {"pid": 4211, "name": "explorer.exe", "executable": r"C:\Windows\explorer.exe", "command_line": "C:\\Windows\\explorer.exe", "parent_pid": 812, "parent_name": "svchost.exe", "user": "analyst", "cpu_percent": 0.8, "memory_rss_mb": 214.7, "threads": 86, "started_at_days": 9},
        {"pid": 4212, "name": "chrome.exe", "executable": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "command_line": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe --type=renderer", "parent_pid": 4211, "parent_name": "explorer.exe", "user": "analyst", "cpu_percent": 3.2, "memory_rss_mb": 412.9, "threads": 24, "started_at_days": 0},
        {"pid": 3456, "name": "MsMpEng.exe", "executable": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.22000.5\MsMpEng.exe", "command_line": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.22000.5\\MsMpEng.exe", "parent_pid": 812, "parent_name": "svchost.exe", "user": "SYSTEM", "cpu_percent": 1.1, "memory_rss_mb": 302.5, "threads": 18, "started_at_days": 3},
        {"pid": 5678, "name": "java.exe", "executable": r"C:\Program Files\Java\jre1.8.0_401\bin\java.exe", "command_line": "java -jar C:\\apps\\webapp\\app.jar --server.port=8000", "parent_pid": 812, "parent_name": "svchost.exe", "user": "svc-app", "cpu_percent": 6.4, "memory_rss_mb": 1024.0, "threads": 47, "started_at_days": 21},
        {"pid": 9988, "name": "update.exe", "executable": r"C:\Users\analyst\AppData\Local\Temp\update.exe", "command_line": "C:\\Users\\analyst\\AppData\\Local\\Temp\\update.exe -silent", "parent_pid": 4211, "parent_name": "explorer.exe", "user": "analyst", "cpu_percent": 12.5, "memory_rss_mb": 88.1, "threads": 6, "started_at_days": 0},
    ],
    "telemetry-win-002": [
        {"pid": 4, "name": "System", "executable": r"C:\Windows\System32\ntoskrnl.exe", "command_line": "", "parent_pid": 0, "parent_name": None, "user": "SYSTEM", "cpu_percent": 0.0, "memory_rss_mb": 20.0, "threads": 198, "started_at_days": 120},
        {"pid": 5678, "name": "java.exe", "executable": r"C:\Program Files\Java\jre1.8.0_401\bin\java.exe", "command_line": "java -jar C:\\apps\\webapp\\app.jar --server.port=443", "parent_pid": 4, "parent_name": "System", "user": "svc-app", "cpu_percent": 4.9, "memory_rss_mb": 2048.0, "threads": 61, "started_at_days": 90},
    ],
}

DEMO_SERVICES = {
    "telemetry-win-001": [
        {"name": "RpcSs", "display_name": "Remote Procedure Call (RPC)", "state": "running", "start_type": "auto", "account": "NT AUTHORITY\\NetworkService", "binary_path": r"C:\Windows\system32\svchost.exe -k rpcss", "pid": 812, "last_event": "started", "changed_days": 42},
        {"name": "Spooler", "display_name": "Print Spooler", "state": "running", "start_type": "auto", "account": "LocalSystem", "binary_path": r"C:\Windows\System32\spoolsv.exe", "pid": 2411, "last_event": "started", "changed_days": 9},
        {"name": "WSearch", "display_name": "Windows Search", "state": "stopped", "start_type": "manual", "account": "LocalSystem", "binary_path": r"C:\Windows\system32\SearchIndexer.exe /Embedding", "pid": None, "last_event": "stopped", "changed_days": 1},
        {"name": "WinDefend", "display_name": "Windows Defender Antivirus Service", "state": "running", "start_type": "auto", "account": "LocalSystem", "binary_path": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.22000.5\MsMpEng.exe", "pid": 3456, "last_event": "started", "changed_days": 3},
        {"name": "svc-updater", "display_name": "Software Updater Service", "state": "running", "start_type": "auto", "account": "NT AUTHORITY\\LocalService", "binary_path": r"C:\Users\analyst\AppData\Local\Temp\svc-updater.exe", "pid": 9988, "last_event": "created", "changed_days": 0},
    ],
    "telemetry-win-002": [
        {"name": "webapp", "display_name": "Web Application Service", "state": "running", "start_type": "auto", "account": "NT AUTHORITY\\NetworkService", "binary_path": r"C:\apps\webapp\run.cmd", "pid": 5678, "last_event": "started", "changed_days": 90},
    ],
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _days_ago(days: float) -> datetime:
    return _now() - timedelta(days=days)


def seed_telemetry_demo(db: Session) -> None:
    """Seed network + process/service demo data (demo mode only)."""
    if not settings.network_demo_mode and not settings.process_demo_mode:
        return
    existing = db.scalar(select(func.count()).select_from(TelemetryAgent))
    if existing:
        return

    agents: dict[str, TelemetryAgent] = {}
    for spec in DEMO_TELEMETRY_AGENTS:
        agent = TelemetryAgent(
            agent_code=spec["agent_code"],
            hostname=spec["hostname"],
            ip_address=spec["ip_address"],
            operating_system="Windows 10 Pro 22H2",
            platform="windows",
            version="1.0.0",
            status="online",
            last_seen=_now() - timedelta(minutes=1),
            enabled=True,
            demo=True,
            machine_guid="demo-local-device",
        )
        db.add(agent)
        db.flush()
        agents[spec["agent_code"]] = agent

    now = _now()
    # ---- network connections / listeners / interfaces / statistics
    for code, agent in agents.items():
        for item in DEMO_CONNECTIONS.get(code, []):
            is_private = _is_private(str(item["foreign_ip"]))
            db.add(
                NetworkConnection(
                    agent_id=agent.id,
                    conn_key=conn_key(
                        item["proto"], item["local_ip"], item["local_port"],
                        item["foreign_ip"], item["foreign_port"],
                    ),
                    proto=item["proto"],
                    local_ip=item["local_ip"],
                    local_port=item["local_port"],
                    foreign_ip=item["foreign_ip"],
                    foreign_port=item["foreign_port"],
                    state=item["state"],
                    pid=item["pid"],
                    process_name=item["process_name"],
                    user=item["user"],
                    executable=item["executable"],
                    is_private=is_private,
                    status="active",
                    first_seen=now - timedelta(minutes=30),
                    last_seen=now - timedelta(seconds=12),
                    source_label="demo",
                )
            )
        for item in DEMO_LISTENERS.get(code, []):
            db.add(
                NetworkListener(
                    agent_id=agent.id,
                    listen_key=listen_key(item["proto"], item["ip"], item["port"]),
                    proto=item["proto"],
                    ip=item["ip"],
                    port=item["port"],
                    pid=item["pid"],
                    process_name=item["process_name"],
                    user=item["user"],
                    executable=item.get("executable"),
                    status="active",
                    first_seen=now - timedelta(days=120),
                    last_seen=now - timedelta(seconds=12),
                    source_label="demo",
                )
            )
        for item in DEMO_INTERFACES.get(code, []):
            db.add(
                NetworkInterface(
                    agent_id=agent.id,
                    name=item["name"],
                    mac=item["mac"],
                    addresses=json.dumps(item["addresses"]),
                    mtu=item["mtu"],
                    speed_mbps=item["speed_mbps"],
                    status=item["status"],
                    first_seen=now - timedelta(days=120),
                    last_seen=now - timedelta(seconds=12),
                    source_label="demo",
                )
            )
        stats = DEMO_STATISTICS.get(code)
        if stats:
            db.add(
                NetworkStatistic(
                    agent_id=agent.id,
                    bytes_sent=stats["bytes_sent"],
                    bytes_recv=stats["bytes_recv"],
                    packets_sent=stats["packets_sent"],
                    packets_recv=stats["packets_recv"],
                    tx_kbps=stats["tx_kbps"],
                    rx_kbps=stats["rx_kbps"],
                    connections_total=stats["connections_total"],
                    listeners_total=stats["listeners_total"],
                    observed_at=now - timedelta(seconds=12),
                    source_label="demo",
                )
            )
    db.flush()

    # ---- processes
    for code, agent in agents.items():
        for item in DEMO_PROCESSES.get(code, []):
            started = _days_ago(item["started_at_days"]) if item["started_at_days"] else None
            db.add(
                ProcessRecord(
                    agent_id=agent.id,
                    pid=item["pid"],
                    name=item["name"],
                    executable=item["executable"],
                    command_line=item["command_line"],
                    parent_pid=item["parent_pid"],
                    parent_name=item["parent_name"],
                    user=item["user"],
                    cpu_percent=item["cpu_percent"],
                    memory_rss_mb=item["memory_rss_mb"],
                    threads=item["threads"],
                    started_at=started,
                    status="running",
                    first_seen=started or now,
                    last_seen=now - timedelta(seconds=5),
                    source_label="demo",
                )
            )

    # ---- services
    for code, agent in agents.items():
        for item in DEMO_SERVICES.get(code, []):
            changed = _days_ago(item["changed_days"])
            db.add(
                ServiceRecord(
                    agent_id=agent.id,
                    name=item["name"],
                    display_name=item["display_name"],
                    state=item["state"],
                    start_type=item["start_type"],
                    account=item["account"],
                    binary_path=item["binary_path"],
                    pid=item["pid"],
                    last_event=item["last_event"],
                    first_seen=changed,
                    last_seen=now - timedelta(seconds=5),
                    changed_at=changed if item["changed_days"] == 0 else None,
                    source_label="demo",
                )
            )
    db.commit()
    log.info(
        "Seeded telemetry demo data (%s agents: network, process + service)",
        len(DEMO_TELEMETRY_AGENTS),
    )


def _is_private(ip: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
