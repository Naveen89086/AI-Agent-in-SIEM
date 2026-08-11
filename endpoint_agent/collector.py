"""Endpoint agent collectors (stdlib only).

Three efficient, bounded collectors:

- ``collect_inventory``: installed software. Windows reads the Uninstall
  registry keys; Linux reads dpkg/rpm; everything else falls back to demo
  data (only when ``demo=True``).
- ``collect_observations``: indicator observations (outbound network
  connections from ``netstat`` and running process names from ``tasklist`` /
  ``ps``). Capped and deduplicated - the agent never floods the manager.
- ``parse_*`` helpers are pure and unit-testable.

Demo data is only produced when the config explicitly opts in; it is labeled
``source_label="demo"`` so it can never be mistaken for a real finding.
"""

import ipaddress
import json
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

TIMEOUT_SECONDS = 10

# Bundled demo inventory - deterministic, clearly labeled.
_DEMO_INVENTORY = [
    {"vendor": "Google", "product": "Chrome", "version": "126.0.6478.115"},
    {"vendor": "Microsoft", "product": "Windows 10 Pro", "version": "10.0.19045"},
    {"vendor": "Adobe", "product": "Acrobat Reader DC", "version": "24.001.20604"},
    {"vendor": "Notepad++", "product": "Notepad++", "version": "8.6.8"},
    {"vendor": "Apache", "product": "Apache HTTP Server", "version": "2.4.55"},
]

# Bundled demo observations - clearly labeled demo indicators.
_DEMO_OBSERVATIONS = [
    {"type": "ipv4", "value": "45.83.193.105", "source": "network.connection",
     "context": {"proto": "tcp", "local_port": 49872, "pid": 421}},
    {"type": "domain", "value": "freemathhelp.ga", "source": "network.dns",
     "context": {"resolver": "system"}},
    {"type": "filehash", "value": "d3a2c1b4e5f60718293a4b5c6d7e8f90123a4b5c6d7e8f90123a4b5c6d7e8f9",
     "source": "file.hash", "context": {"path": "C:\\Users\\public\\update.exe"}},
    {"type": "registry", "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemCheck",
     "source": "registry.autostart", "context": {"hive": "HKCU"}},
]

_CONN_RE = re.compile(r"^\s*(TCP|UDP)\s+([0-9a-fA-F.:\[\]]+):(\d+)\s+([0-9a-fA-F.:\[\]]+):(\d+|\*)\s+([A-Z_]+)\s*(\d*)\s*$")
_PS_WIN_RE = re.compile(r"^([^\r\n]+?)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# --------------------------------------------------------------------- parsing
def parse_netstat(output: str) -> list[dict[str, Any]]:
    """Parse ``netstat -ano`` output into connection dicts."""
    rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = _CONN_RE.match(line)
        if not match:
            continue
        proto, local_ip, local_port, foreign_ip, foreign_port, state, pid = match.groups()
        bare_foreign = foreign_ip.strip("[]")
        if (
            bare_foreign in ("0.0.0.0", "::", "127.0.0.1", "::1", "localhost")
            or foreign_port == "*"
        ):
            continue
        rows.append(
            {
                "proto": proto.lower(),
                "local_ip": local_ip,
                "local_port": int(local_port),
                "foreign_ip": foreign_ip,
                "foreign_port": foreign_port,
                "state": state,
                "pid": int(pid) if pid else None,
            }
        )
    return rows


def parse_dpkg(output: str) -> list[dict[str, str]]:
    """Parse ``dpkg-query -W -f=...`` output (lines: name\tversion)."""
    rows: list[dict[str, str]] = []
    for line in output.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2 and parts[0] and parts[1]:
            rows.append({"vendor": "", "product": parts[0], "version": parts[1]})
    return rows


def parse_rpm(output: str) -> list[dict[str, str]]:
    """Parse ``rpm -qa --qf`` output (lines: name-version-release)."""
    rows: list[dict[str, str]] = []
    for line in output.splitlines():
        parts = line.strip().split("-")
        if len(parts) >= 2:
            rows.append({"vendor": "", "product": parts[0], "version": "-".join(parts[1:])})
    return rows


# ------------------------------------------------------------------- inventory
def _registry_inventory() -> list[dict[str, Any]]:
    """Read installed software from the Windows Uninstall registry keys."""
    import winreg

    items: list[dict[str, Any]] = []
    uninstall_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    for path in uninstall_paths:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        except OSError:
            continue
        try:
            for index in range(winreg.QueryInfoKey(key)[0]):
                try:
                    sub_name = winreg.EnumKey(key, index)
                except OSError:
                    break
                try:
                    with winreg.OpenKey(key, sub_name) as sub:
                        display = _query(sub, "DisplayName")
                        version = _query(sub, "DisplayVersion")
                        publisher = _query(sub, "Publisher")
                        install_date = _query(sub, "InstallDate")
                except OSError:
                    continue
                if not display:
                    continue
                item: dict[str, Any] = {
                    "vendor": publisher or "",
                    "product": display,
                    "version": version or "",
                    "source": "registry",
                }
                if install_date:
                    try:
                        item["install_date"] = datetime.strptime(install_date, "%Y%m%d").replace(tzinfo=timezone.utc).isoformat()
                    except ValueError:
                        pass
                items.append(item)
        finally:
            key.Close()
    # Dedupe by product+version.
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = (item["product"].lower(), item["version"].lower(), item["vendor"].lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _query(key, name: str) -> str:
    try:
        return str(winreg.QueryValueEx(key, name)[0])
    except OSError:
        return ""


def _dpkg_inventory() -> list[dict[str, Any]]:
    proc = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
        capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
    )
    rows = parse_dpkg(proc.stdout or "")
    return [dict(r, source="dpkg") for r in rows]


def _rpm_inventory() -> list[dict[str, Any]]:
    proc = subprocess.run(
        ["rpm", "-qa", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\n"],
        capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
    )
    rows = parse_rpm(proc.stdout or "")
    return [dict(r, source="rpm") for r in rows]


def collect_inventory(*, demo: bool = False) -> list[dict[str, Any]]:
    """Return the installed-software inventory (bounded, deterministic in demo)."""
    if demo:
        return [
            dict(item, source="demo", install_date=_now_iso()[:10])
            for item in _DEMO_INVENTORY
        ]
    if sys.platform == "win32":
        try:
            items = _registry_inventory()
        except Exception:
            items = []
        # Fall back to PowerShell/WMIC-free path: registry is authoritative on
        # Windows. If registry returned nothing, try the demo corpus is NOT used
        # here (would be a fabricated inventory) - return empty instead.
        return items
    if shutil.which("dpkg-query"):
        try:
            return _dpkg_inventory()
        except (subprocess.TimeoutExpired, OSError):
            pass
    if shutil.which("rpm"):
        try:
            return _rpm_inventory()
        except (subprocess.TimeoutExpired, OSError):
            pass
    return []


# --------------------------------------------------------------- observations
def _netstat_observations(*, max_obs: int, skip_private: bool) -> list[dict[str, Any]]:
    try:
        proc = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=TIMEOUT_SECONDS
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    rows = parse_netstat(proc.stdout or "")
    out: list[dict[str, Any]] = []
    for row in rows:
        if len(out) >= max_obs:
            break
        if row["proto"] not in ("tcp", "udp"):
            continue
        if row["state"] in ("LISTENING", "CLOSE_WAIT", "TIME_WAIT"):
            continue
        if skip_private and _is_private(row["foreign_ip"]):
            continue
        out.append(
            {
                "type": "ipv6" if ":" in row["foreign_ip"] else "ipv4",
                "value": row["foreign_ip"],
                "source": "network.connection",
                "observed_at": _now_iso(),
                "context": {
                    "proto": row["proto"],
                    "foreign_port": row["foreign_port"],
                    "local_ip": row["local_ip"],
                    "local_port": row["local_port"],
                    "pid": row["pid"],
                },
            }
        )
    return out


def _process_observations(*, max_obs: int) -> list[dict[str, Any]]:
    if sys.platform == "win32":
        try:
            proc = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
            )
        except (subprocess.TimeoutExpired, OSError):
            return []
        out: list[dict[str, Any]] = []
        for line in (proc.stdout or "").splitlines():
            if len(out) >= max_obs:
                break
            parts = line.strip().strip('"').split('","')
            if not parts:
                continue
            name = parts[0].strip('"').lower()
            if not name or name in ("system idle process", "system"):
                continue
            out.append(
                {
                    "type": "process",
                    "value": name,
                    "source": "process.running",
                    "observed_at": _now_iso(),
                    "context": {"pid": parts[1].strip('"') if len(parts) > 1 else None},
                }
            )
        return out
    try:
        proc = subprocess.run(
            ["ps", "-eo", "comm"], capture_output=True, text=True, timeout=TIMEOUT_SECONDS
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    out = []
    for line in (proc.stdout or "").splitlines():
        if len(out) >= max_obs:
            break
        name = line.strip().split("/")[-1].lower()
        if not name or name in ("ps", "bash", "sh"):
            continue
        out.append(
            {
                "type": "process",
                "value": name,
                "source": "process.running",
                "observed_at": _now_iso(),
                "context": {},
            }
        )
    return out


def collect_observations(
    *,
    demo: bool = False,
    max_obs: int = 50,
    skip_private: bool = True,
) -> list[dict[str, Any]]:
    """Collect indicator observations (bounded)."""
    if demo:
        return [dict(o, observed_at=_now_iso()) for o in _DEMO_OBSERVATIONS]
    observations: list[dict[str, Any]] = []
    observations.extend(_netstat_observations(max_obs=max_obs, skip_private=skip_private))
    remaining = max_obs - len(observations)
    if remaining > 0:
        observations.extend(_process_observations(max_obs=remaining))
    return observations[:max_obs]


def filter_new(observations: list[dict[str, Any]], seen: set[str]) -> list[dict[str, Any]]:
    """Keep only observations whose type:value was not reported before."""
    fresh: list[dict[str, Any]] = []
    for obs in observations:
        key = f"{obs.get('type')}:{obs.get('value')}"
        if key in seen:
            continue
        seen.add(key)
        fresh.append(obs)
    return fresh
