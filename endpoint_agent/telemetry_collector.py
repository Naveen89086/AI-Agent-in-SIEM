"""Endpoint telemetry collectors (network / processes / services).

psutil is used when installed (rich CPU/memory/owner/tree metadata); every
collector falls back to stdlib commands (``netstat -ano``, ``tasklist`` /
``ps``, ``wmic service`` / ``sc query``) so the agent keeps working on hosts
without psutil.

Snapshot payload shape (what ``POST /api/v1/telemetry/ingest`` accepts)::

    {
      "network": {
        "connections": [...],
        "listeners": [...],
        "interfaces": [...],
        "statistics": {...},
      },
      "processes": [...],
      "services": [...],
    }

Demo snapshots are only produced when the config explicitly opts in and are
labeled by the transport with ``demo=true`` so the server stores them with
``source_label="demo"``.
"""

import ipaddress
import json
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

try:  # optional dependency - the agent works without it
    import psutil
except ImportError:  # pragma: no cover - exercised on non-psutil hosts
    psutil = None  # type: ignore[assignment]

TIMEOUT_SECONDS = 15

_DEMO_CONNECTIONS = [
    {"proto": "tcp", "local_ip": "10.10.10.31", "local_port": 51234, "foreign_ip": "142.250.191.14", "foreign_port": 443, "state": "ESTABLISHED", "pid": 4212, "process_name": "chrome.exe", "user": "analyst", "executable": r"C:\Program Files\Google\Chrome\Application\chrome.exe"},
    {"proto": "tcp", "local_ip": "10.10.10.31", "local_port": 49872, "foreign_ip": "10.10.10.20", "foreign_port": 445, "state": "ESTABLISHED", "pid": 812, "process_name": "svchost.exe", "user": "NETWORK SERVICE", "executable": r"C:\Windows\System32\svchost.exe"},
    {"proto": "tcp", "local_ip": "10.10.10.31", "local_port": 60123, "foreign_ip": "45.83.193.105", "foreign_port": 4444, "state": "ESTABLISHED", "pid": 9988, "process_name": "update.exe", "user": "analyst", "executable": r"C:\Users\analyst\AppData\Local\Temp\update.exe"},
]

_DEMO_LISTENERS = [
    {"proto": "tcp", "ip": "0.0.0.0", "port": 135, "pid": 812, "process_name": "svchost.exe", "user": "NETWORK SERVICE"},
    {"proto": "tcp", "ip": "0.0.0.0", "port": 445, "pid": 4, "process_name": "System", "user": "SYSTEM"},
    {"proto": "tcp", "ip": "0.0.0.0", "port": 3389, "pid": 1092, "process_name": "svchost.exe", "user": "NETWORK SERVICE"},
]

_DEMO_INTERFACES = [
    {"name": "Ethernet", "mac": "00:15:5d:01:aa:01", "addresses": ["10.10.10.31"], "mtu": 1500, "speed_mbps": 1000, "status": "up"},
    {"name": "Loopback Pseudo-Interface 1", "mac": None, "addresses": ["127.0.0.1"], "mtu": 65536, "speed_mbps": None, "status": "up"},
]

_DEMO_PROCESSES = [
    {"pid": 4, "name": "System", "executable": r"C:\Windows\System32\ntoskrnl.exe", "command_line": "", "parent_pid": 0, "parent_name": None, "user": "SYSTEM", "cpu_percent": 0.1, "memory_rss_mb": 24.0, "threads": 204, "started_at": None},
    {"pid": 812, "name": "svchost.exe", "executable": r"C:\Windows\System32\svchost.exe", "command_line": r"C:\Windows\System32\svchost.exe -k netsvcs -p", "parent_pid": 4, "parent_name": "System", "user": "SYSTEM", "cpu_percent": 0.4, "memory_rss_mb": 91.3, "threads": 31, "started_at": None},
    {"pid": 4212, "name": "chrome.exe", "executable": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "command_line": "chrome.exe --type=renderer", "parent_pid": 4211, "parent_name": "explorer.exe", "user": "analyst", "cpu_percent": 3.2, "memory_rss_mb": 412.9, "threads": 24, "started_at": None},
    {"pid": 9988, "name": "update.exe", "executable": r"C:\Users\analyst\AppData\Local\Temp\update.exe", "command_line": "update.exe -silent", "parent_pid": 4211, "parent_name": "explorer.exe", "user": "analyst", "cpu_percent": 12.5, "memory_rss_mb": 88.1, "threads": 6, "started_at": None},
]

_DEMO_SERVICES = [
    {"name": "RpcSs", "display_name": "Remote Procedure Call (RPC)", "state": "running", "start_type": "auto", "account": r"NT AUTHORITY\NetworkService", "binary_path": r"C:\Windows\system32\svchost.exe -k rpcss", "pid": 812},
    {"name": "Spooler", "display_name": "Print Spooler", "state": "running", "start_type": "auto", "account": "LocalSystem", "binary_path": r"C:\Windows\System32\spoolsv.exe", "pid": 2411},
    {"name": "WSearch", "display_name": "Windows Search", "state": "stopped", "start_type": "manual", "account": "LocalSystem", "binary_path": r"C:\Windows\system32\SearchIndexer.exe /Embedding", "pid": None},
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _run(cmd: list[str]) -> str:
    kwargs: dict[str, Any] = {"capture_output": True, "text": True, "timeout": TIMEOUT_SECONDS}
    if sys.platform == "win32":  # don't flash a console window for the collector
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    proc = subprocess.run(cmd, **kwargs)
    return proc.stdout or ""


def snapshot_fingerprint(snapshot: dict[str, Any]) -> str:
    """Stable hash of a snapshot (used by the CLI for change detection)."""
    import hashlib

    payload = json.dumps(snapshot, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ================================================================== network
def _psutil_process_lookup() -> dict[int, dict[str, Any]]:
    """pid -> {name, executable, user, parent_pid} best-effort cache."""
    lookup: dict[int, dict[str, Any]] = {}
    if psutil is None:
        return lookup
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "ppid"]):
        try:
            info = proc.info
            pid = int(info["pid"])
            lookup[pid] = {
                "name": info.get("name"),
                "executable": info.get("exe"),
                "user": info.get("username"),
                "parent_pid": info.get("ppid"),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):  # type: ignore[attr-defined]
            continue
    return lookup


def _psutil_network_snapshot(*, max_connections: int = 1000, max_listeners: int = 500) -> dict[str, Any]:
    if psutil is None:
        return {"connections": [], "listeners": []}
    conns: list[dict[str, Any]] = []
    listeners: list[dict[str, Any]] = []
    lookup = _psutil_process_lookup()
    try:
        raw = psutil.net_connections(kind="all")
    except (psutil.AccessDenied, OSError):  # type: ignore[attr-defined]
        return {"connections": [], "listeners": []}
    for entry in raw:
        if entry is None:
            continue
        state = entry.status or ""
        laddr = entry.laddr
        raddr = entry.raddr
        proto = "tcp" if entry.type == 1 else "udp"  # SOCK_STREAM
        l_ip = laddr.ip if laddr else ""
        l_port = laddr.port if laddr else 0
        r_ip = raddr.ip if raddr else ""
        r_port = raddr.port if raddr else None
        pid = entry.pid
        info = lookup.get(pid or 0, {})
        if state == "LISTEN":
            if len(listeners) >= max_listeners:
                break
            listeners.append(
                {
                    "proto": proto,
                    "ip": l_ip,
                    "port": l_port,
                    "pid": pid,
                    "process_name": info.get("name"),
                    "user": info.get("user"),
                    "executable": info.get("executable"),
                }
            )
            continue
        # Skip local/wildcard destinations (not useful for monitoring).
        if not r_ip or r_ip in ("0.0.0.0", "::", "127.0.0.1", "::1") or not r_port:
            continue
        if len(conns) >= max_connections:
            break
        conns.append(
            {
                "proto": proto,
                "local_ip": l_ip,
                "local_port": l_port,
                "foreign_ip": r_ip,
                "foreign_port": r_port,
                "state": state,
                "pid": pid,
                "process_name": info.get("name"),
                "user": info.get("user"),
                "executable": info.get("executable"),
                "is_private": _is_private(r_ip),
            }
        )
    conns.sort(key=lambda c: (c["foreign_ip"], c["foreign_port"]))
    listeners.sort(key=lambda c: (c["ip"], c["port"]))
    return {"connections": conns, "listeners": listeners}


def _netstat_network_snapshot(*, max_connections: int = 1000) -> dict[str, Any]:
    """stdlib fallback using ``netstat -ano`` (splits listeners/connections)."""
    import re

    pattern = re.compile(
        r"^\s*(TCP|UDP)\s+([0-9a-fA-F.:\[\]]+):(\d+)\s+([0-9a-fA-F.:\[\]*]+):(\d+|\*)\s*(?:([A-Z_]+)\s+)?(\d*)\s*$"
    )
    try:
        output = _run(["netstat", "-ano"])
    except (subprocess.TimeoutExpired, OSError):
        return {"connections": [], "listeners": []}
    conns: list[dict[str, Any]] = []
    listeners: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        proto, l_ip, l_port, f_ip, f_port, state, pid = match.groups()
        if state == "LISTENING":
            listeners.append(
                {
                    "proto": proto.lower(),
                    "ip": l_ip,
                    "port": int(l_port),
                    "pid": int(pid) if pid else None,
                    "process_name": None,
                    "user": None,
                    "executable": None,
                }
            )
            continue
        bare = f_ip.strip("[]")
        if bare in ("0.0.0.0", "::", "127.0.0.1", "::1") or f_port == "*":
            continue
        if len(conns) >= max_connections:
            break
        conns.append(
            {
                "proto": proto.lower(),
                "local_ip": l_ip,
                "local_port": int(l_port),
                "foreign_ip": f_ip,
                "foreign_port": int(f_port) if f_port != "*" else None,
                "state": state,
                "pid": int(pid) if pid else None,
                "process_name": None,
                "user": None,
                "executable": None,
                "is_private": _is_private(bare),
            }
        )
    return {"connections": conns, "listeners": listeners}


def _network_interfaces() -> list[dict[str, Any]]:
    if psutil is None:
        return []
    interfaces: list[dict[str, Any]] = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except (psutil.AccessDenied, OSError):  # type: ignore[attr-defined]
        return []
    for name, entries in addrs.items():
        addresses: list[str] = []
        mac: str | None = None
        for entry in entries:
            if entry.family.name == "AF_LINK" or (entry.address and ":" in entry.address and "." not in entry.address and len(entry.address) == 17):
                mac = entry.address
                continue
            if entry.address:
                addresses.append(entry.address)
        iface_stats = stats.get(name)
        interfaces.append(
            {
                "name": name,
                "mac": mac,
                "addresses": addresses,
                "mtu": iface_stats.mtu if iface_stats else None,
                "speed_mbps": int(iface_stats.speed) if iface_stats and iface_stats.speed else None,
                "status": "up" if iface_stats and iface_stats.isup else "down",
            }
        )
    interfaces.sort(key=lambda i: i["name"])
    return interfaces


def _network_statistics() -> dict[str, Any]:
    stats: dict[str, Any] = {
        "bytes_sent": 0,
        "bytes_recv": 0,
        "packets_sent": 0,
        "packets_recv": 0,
        "connections_total": 0,
        "listeners_total": 0,
    }
    if psutil is None:
        return stats
    try:
        io = psutil.net_io_counters()
    except OSError:
        return stats
    stats["bytes_sent"] = int(io.bytes_sent)
    stats["bytes_recv"] = int(io.bytes_recv)
    stats["packets_sent"] = int(io.packets_sent)
    stats["packets_recv"] = int(io.packets_recv)
    return stats


def collect_network(*, demo: bool = False, max_connections: int = 1000, max_listeners: int = 500) -> dict[str, Any]:
    """Full network block: connections, listeners, interfaces, statistics."""
    if demo:
        connections: list[dict[str, Any]] = [dict(c) for c in _DEMO_CONNECTIONS]
        listeners: list[dict[str, Any]] = [dict(c) for c in _DEMO_LISTENERS]
        for conn in connections:
            conn["is_private"] = _is_private(conn["foreign_ip"])
    else:
        if psutil is not None:
            snap = _psutil_network_snapshot(max_connections=max_connections, max_listeners=max_listeners)
            connections = snap["connections"]
            listeners = snap["listeners"]
        else:
            connections = _netstat_network_snapshot(max_connections=max_connections)["connections"]
            listeners = _netstat_listeners()
    return {
        "connections": connections,
        "listeners": listeners,
        "interfaces": _DEMO_INTERFACES if demo else _network_interfaces(),
        "statistics": _DEMO_STATISTICS if demo else _network_statistics(),
    }


def _netstat_listeners(*, max_listeners: int = 500) -> list[dict[str, Any]]:
    import re

    pattern = re.compile(
        r"^\s*(TCP|UDP)\s+([0-9a-fA-F.:\[\]]+):(\d+)\s+([0-9a-fA-F.:\[\]*]+):(\d+|\*)\s*(?:([A-Z_]+)\s+)?(\d*)\s*$"
    )
    try:
        output = _run(["netstat", "-ano"])
    except (subprocess.TimeoutExpired, OSError):
        return []
    listeners: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        proto, l_ip, l_port, _f_ip, _f_port, state, pid = match.groups()
        if state != "LISTENING":
            continue
        listeners.append(
            {
                "proto": proto.lower(),
                "ip": l_ip,
                "port": int(l_port),
                "pid": int(pid) if pid else None,
                "process_name": None,
                "user": None,
                "executable": None,
            }
        )
        if len(listeners) >= max_listeners:
            break
    listeners.sort(key=lambda c: (c["ip"], c["port"]))
    return listeners


# ================================================================== processes
def _psutil_processes() -> list[dict[str, Any]]:
    if psutil is None:
        return []
    processes: list[dict[str, Any]] = []
    try:
        cpu_percents = psutil.cpu_percent(interval=None, percpu=False)
    except Exception:
        cpu_percents = None
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "ppid", "memory_info", "threads", "cmdline", "create_time"]):
        try:
            info = proc.info
            mem_rss = info.get("memory_info")
            cmdline = info.get("cmdline") or []
            create_time = info.get("create_time")
            processes.append(
                {
                    "pid": int(info["pid"]),
                    "name": info.get("name"),
                    "executable": info.get("exe"),
                    "command_line": " ".join(cmdline),
                    "parent_pid": int(info.get("ppid") or 0),
                    "parent_name": None,
                    "user": info.get("username"),
                    "cpu_percent": None,
                    "memory_rss_mb": round(mem_rss.rss / (1024 * 1024), 1) if mem_rss else None,
                    "threads": info.get("threads"),
                    "started_at": datetime.fromtimestamp(create_time, tz=timezone.utc).isoformat() if create_time else None,
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):  # type: ignore[attr-defined]
            continue
    by_pid = {p["pid"]: p for p in processes}
    for p in processes:
        parent = by_pid.get(p["parent_pid"])
        if parent:
            p["parent_name"] = parent["name"]
    return sorted(processes, key=lambda p: (p["name"] or "", p["pid"]))


def _tasklist_processes() -> list[dict[str, Any]]:
    """stdlib fallback via ``tasklist /FO CSV /V`` (Windows) or ``ps`` (POSIX)."""
    if sys.platform == "win32":
        return _tasklist_windows()
    return _ps_posix()


def _tasklist_windows() -> list[dict[str, Any]]:
    # NOTE: the verbose variant (/V) is very slow on busy hosts, so we use the
    # fast CSV layout (no per-process username/CPU columns).
    try:
        output = _run(["tasklist", "/FO", "CSV", "/NH"])
    except (subprocess.TimeoutExpired, OSError):
        return []
    processes: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            parts = json.loads("[" + line + "]")
        except json.JSONDecodeError:
            continue
        if not parts or len(parts) < 5:
            continue
        # Layout: "Image Name","PID","Session Name","Session#","Mem Usage"
        image, pid = parts[0], parts[1]
        session = parts[2] if len(parts) > 2 else None
        mem_usage = parts[4] if len(parts) > 4 else None
        processes.append(
            {
                "pid": int(pid),
                "name": image,
                "executable": None,
                "command_line": None,
                "parent_pid": None,
                "parent_name": None,
                "user": session,
                "cpu_percent": None,
                "memory_rss_mb": _mem_str_to_mb(mem_usage),
                "threads": None,
                "started_at": None,
            }
        )
    return sorted(processes, key=lambda p: (p["name"] or "", p["pid"]))


def _ps_posix() -> list[dict[str, Any]]:
    try:
        output = _run(["ps", "-eo", "pid,ppid,user,comm,rss,args"])
    except (subprocess.TimeoutExpired, OSError):
        return []
    processes: list[dict[str, Any]] = []
    lines = output.splitlines()
    for line in lines[1:]:  # skip header
        parts = line.split(maxsplit=5)
        if len(parts) < 5:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        processes.append(
            {
                "pid": pid,
                "name": parts[3],
                "executable": None,
                "command_line": parts[5] if len(parts) > 5 else parts[3],
                "parent_pid": int(parts[1]) if parts[1].isdigit() else None,
                "parent_name": None,
                "user": parts[2],
                "cpu_percent": None,
                "memory_rss_mb": _rss_to_mb(parts[4]),
                "threads": None,
                "started_at": None,
            }
        )
    by_pid = {p["pid"]: p for p in processes}
    for p in processes:
        parent = by_pid.get(p["parent_pid"])
        if parent:
            p["parent_name"] = parent["name"]
    return sorted(processes, key=lambda p: (p["name"] or "", p["pid"]))


def _mem_str_to_mb(value: str) -> float | None:
    """'123 K' -> MB, '123 M' -> MB, '1,234,567 K' -> MB (tasklist style)."""
    if not value:
        return None
    value = value.strip()
    if not value or value == "N/A":
        return None
    try:
        number = float(value.split()[0].replace(",", ""))
        suffix = value.split()[-1] if " " in value else "K"
        if suffix.upper().startswith("K"):
            return round(number / 1024.0, 1)
        if suffix.upper().startswith("M"):
            return round(number, 1)
        if suffix.upper().startswith("G"):
            return round(number * 1024.0, 1)
        return round(number / 1024.0, 1)
    except (IndexError, ValueError):
        return None


def _rss_to_mb(value: str) -> float | None:
    try:
        return round(int(value) / 1024.0, 1)
    except (ValueError, TypeError):
        return None


def collect_processes(*, demo: bool = False) -> list[dict[str, Any]]:
    if demo:
        return [dict(p) for p in _DEMO_PROCESSES]
    if psutil is not None:
        return _psutil_processes()
    return _tasklist_processes()


# ================================================================== services
def _wmic_services() -> list[dict[str, Any]]:
    """stdlib fallback for Windows: ``wmic service get ... /FORMAT:CSV``."""
    try:
        output = _run(["wmic", "service", "get", "Name,DisplayName,State,StartMode,StartName,PathName,ProcessId", "/FORMAT:CSV"])
    except (subprocess.TimeoutExpired, OSError):
        return []
    services: list[dict[str, Any]] = []
    lines = output.splitlines()
    if not lines:
        return services
    for line in lines[1:]:  # skip header
        fields = [f.strip() for f in line.split(",") if f.strip()]
        if not fields:
            continue
        # CSV layout: Node,Name,DisplayName,State,StartMode,StartName,PathName,ProcessId
        if len(fields) < 8:
            continue
        _, name, display_name, state, start_mode, start_name, path_name, pid = fields[:8]
        if not name:
            continue
        services.append(
            {
                "name": name,
                "display_name": display_name,
                "state": state,
                "start_type": start_mode,
                "account": start_name,
                "binary_path": path_name,
                "pid": int(pid) if pid.isdigit() else None,
            }
        )
    return services


def _sc_services() -> list[dict[str, Any]]:
    """fallback for Windows without wmic: ``sc query state= all``."""
    try:
        output = _run(["sc", "query", "state=", "all"])
    except (subprocess.TimeoutExpired, OSError):
        return []
    services: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            if current.get("name"):
                services.append(current)
            current = {"name": line.split(":", 1)[1].strip()}
        elif line.startswith("DISPLAY_NAME:"):
            current["display_name"] = line.split(":", 1)[1].strip()
        elif line.startswith("STATE"):
            # "STATE              : 4  RUNNING"
            parts = line.split(":", 1)
            state = parts[1].split()[-1] if len(parts) > 1 else ""
            current["state"] = state
        elif line.startswith("START_TYPE"):
            parts = line.split(":", 1)
            current["start_type"] = parts[1].split()[-1] if len(parts) > 1 else ""
        elif line.startswith("PID"):
            parts = line.split(":", 1)
            pid = parts[1].strip() if len(parts) > 1 else ""
            current["pid"] = int(pid) if pid.isdigit() else None
    if current.get("name"):
        services.append(current)
    for s in services:
        s.setdefault("display_name", None)
        s.setdefault("account", None)
        s.setdefault("binary_path", None)
        s.setdefault("start_type", None)
        s.setdefault("pid", None)
    return services


def collect_services(*, demo: bool = False) -> list[dict[str, Any]]:
    if demo:
        return [dict(s) for s in _DEMO_SERVICES]
    if sys.platform == "win32":
        services = _wmic_services()
        if services:
            return services
        return _sc_services()
    # POSIX: read /etc/init.d-style services from systemctl if available.
    return _systemctl_services()


def _systemctl_services() -> list[dict[str, Any]]:
    try:
        output = _run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"])
    except (subprocess.TimeoutExpired, OSError):
        return []
    services: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name, load, active, sub = parts[0], parts[1], parts[2], parts[3]
        if not name.endswith(".service"):
            continue
        services.append(
            {
                "name": name[:-8],
                "display_name": name[:-8],
                "state": "running" if active == "active" else active,
                "start_type": None,
                "account": None,
                "binary_path": None,
                "pid": None,
            }
        )
    return services


def collect_telemetry_snapshot(*, demo: bool = False, max_connections: int = 1000, max_listeners: int = 500) -> dict[str, Any]:
    """Assemble a full telemetry snapshot (network + processes + services)."""
    network = collect_network(demo=demo, max_connections=max_connections, max_listeners=max_listeners)
    snapshot = {
        "collected_at": _now_iso(),
        "network": network,
        "processes": collect_processes(demo=demo),
        "services": collect_services(demo=demo),
    }
    snapshot["fingerprint"] = snapshot_fingerprint(
        {"network": network, "processes": snapshot["processes"], "services": snapshot["services"]}
    )
    return snapshot


_DEMO_STATISTICS = {
    "bytes_sent": 1234567890,
    "bytes_recv": 9876543210,
    "packets_sent": 12345678,
    "packets_recv": 98765432,
    "connections_total": len(_DEMO_CONNECTIONS),
    "listeners_total": len(_DEMO_LISTENERS),
}
