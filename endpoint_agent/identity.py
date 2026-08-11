"""Stable machine identity for the protected device.

Derives the machine fingerprint (Windows MachineGuid when available) and a
stable agent code derived from it. The identity never changes across restarts
(no random IDs), which is what lets the manager enforce the single-protected-
device model: a second, different machine presents a different fingerprint and
is rejected.
"""

import hashlib
import socket


def machine_guid() -> str:
    """Return the stable Windows MachineGuid, or a hashed fallback identity."""
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
        )
        try:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
        finally:
            winreg.CloseKey(key)
        if value and str(value).strip():
            return str(value).strip()
    except Exception:
        pass
    # Fallback (non-Windows / registry unavailable): stable hash of the machine.
    raw = f"{socket.gethostname()}|{_os_tag()}".encode("utf-8")
    return "host-" + hashlib.sha256(raw).hexdigest()[:32]


def derive_agent_code(guid: str | None = None) -> str:
    """Stable per-machine agent code derived from the machine fingerprint."""
    guid = guid or machine_guid()
    return "local-" + hashlib.sha256(guid.encode("utf-8")).hexdigest()[:8]


def collect_identity() -> dict:
    """The identity block the agent sends during registration."""
    guid = machine_guid()
    return {
        "machine_guid": guid,
        "agent_code": derive_agent_code(guid),
        "hostname": socket.gethostname(),
    }


def _os_tag() -> str:
    try:
        import platform

        return platform.platform()
    except Exception:
        return "unknown"
