"""File hashing and state collection (agent side).

SHA-256 of the file *content* is the integrity primitive sent to the manager.
The manager compares it against its own persisted baseline and decides the
final event type - the agent only reports state, never classification alone.
"""

import fnmatch
import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path


def normalize_path(path: str) -> str:
    """Canonical string form (backslashes, uppercase drive) for comparisons."""
    if not path:
        return path
    p = path.replace("/", "\\")
    parts = [part for part in p.split("\\") if part not in ("", ".")]
    p = "\\".join(parts)
    if len(p) >= 2 and p[1] == ":":
        p = p[0].upper() + p[1:]
    return p


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str | None:
    """Content SHA-256, or None when the file is unreadable/not a regular file."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def _is_regular_file(path: str) -> bool:
    try:
        return os.path.isfile(path)
    except OSError:
        return False


def file_state(path: str) -> dict | None:
    """Return ``{path, sha256, size, mtime, file_type}`` or None if gone/unsupported."""
    if not _is_regular_file(path):
        return None
    digest = sha256_file(path)
    if digest is None:
        return None
    try:
        info = os.stat(path)
        mtime = datetime.fromtimestamp(info.st_mtime, tz=timezone.utc)
        size = info.st_size
    except OSError:
        return None
    return {
        "path": normalize_path(path),
        "sha256": digest,
        "size": size,
        "mtime": mtime.isoformat(),
        "file_type": _file_type(path),
    }


def _file_type(path: str) -> str:
    name = os.path.basename(path)
    if "." not in name:
        return "file"
    return name.rsplit(".", 1)[-1].lower()


def excluded(path: str, patterns: list[str]) -> bool:
    """True when a path should be skipped (patterns use fnmatch, case-insensitive)."""
    name = os.path.basename(path)
    normalized = path.replace("/", "\\")
    for pattern in patterns or []:
        if not pattern:
            continue
        p = pattern.replace("/", "\\")
        if fnmatch.fnmatch(name, p) or fnmatch.fnmatch(normalized, p):
            return True
    return False


def classify_change(path: str, previous: dict | None, current: dict | None) -> str:
    """Determine the *observed* change for a path from baseline -> current state.

    The manager re-validates this against its own baseline before storing; this
    is just the agent's observation to route the right payload fields.
    """
    if previous is None and current is not None:
        return "added"
    if previous is not None and current is None:
        return "deleted"
    if previous is not None and current is not None:
        if previous.get("sha256") != current.get("sha256"):
            return "modified"
        return "unchanged"
    return "unchanged"
