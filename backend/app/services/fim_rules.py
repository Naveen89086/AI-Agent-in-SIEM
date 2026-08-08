"""Deterministic FIM severity rules.

The severity of a FIM event is a pure function of the file path - no AI, no
randomness. Rules are structured data (not hundreds of if statements) so they
can be audited and overridden through ``FIM_RULES_JSON``.

Rule schema::

    {
      "rule_id": "FIM-WIN-SYSTEM32-001",
      "name": "Windows System32 change",
      "severity": "high",                 # low | medium | high | critical
      "path_prefixes": ["C:\\Windows\\System32"],
      "path_contains": [],
      "extensions": [],
      "regex": null                        # optional, applied to the normalized path
    }

Evaluation picks the highest severity of every matching rule and records the
first matching rule id/name on the event.
"""

import json
import re
from typing import Any

from app.core.config import settings

LEVELS = {"low": 2, "medium": 4, "high": 6, "critical": 8}

# Security-sensitive paths / persistence locations that deserve critical
# attention when they change.
_SECURITY_MARKERS = [
    "\\Windows\\System32\\drivers\\etc",
    "\\Windows\\System32\\Config",
    "\\Windows\\System32\\wbem",
    "\\Windows\\System32\\WindowsPowerShell",
    "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu",
    "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "\\Startup\\",
    "\\Windows\\System32\\Tasks",
    "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
]

_EXECUTABLE_EXTENSIONS = [
    "exe", "dll", "sys", "scr", "ps1", "bat", "cmd", "vbs", "msi", "com", "ocx", "cpl",
]


def default_rules() -> list[dict[str, Any]]:
    """The built-in rule set (overridable via FIM_RULES_JSON)."""
    return [
        {
            "rule_id": "FIM-SECURITY-001",
            "name": "Security-sensitive path changed",
            "severity": "critical",
            "path_prefixes": [],
            "path_contains": _SECURITY_MARKERS,
            "extensions": [],
            "regex": None,
        },
        {
            "rule_id": "FIM-PERSISTENCE-001",
            "name": "Persistence-related file changed",
            "severity": "critical",
            "path_prefixes": [
                "C:\\Windows\\System32\\Tasks",
                "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
            ],
            "path_contains": [],
            "extensions": [],
            "regex": None,
        },
        {
            "rule_id": "FIM-WIN-SYSTEM32-001",
            "name": "Windows System32 change",
            "severity": "high",
            "path_prefixes": ["C:\\Windows\\System32"],
            "path_contains": [],
            "extensions": [],
            "regex": None,
        },
        {
            "rule_id": "FIM-EXECUTABLE-001",
            "name": "Executable file changed",
            "severity": "medium",
            "path_prefixes": [],
            "path_contains": [],
            "extensions": _EXECUTABLE_EXTENSIONS,
            "regex": None,
        },
        {
            "rule_id": "FIM-DEFAULT-001",
            "name": "File change",
            "severity": "low",
            "path_prefixes": [],
            "path_contains": [],
            "extensions": [],
            "regex": None,
        },
    ]


def load_rules() -> list[dict[str, Any]]:
    """Return the configured rule set, or the built-in defaults."""
    if not settings.fim_rules_json:
        return default_rules()
    try:
        parsed = json.loads(settings.fim_rules_json)
    except (TypeError, json.JSONDecodeError):
        return default_rules()
    if not isinstance(parsed, list) or not parsed:
        return default_rules()
    return parsed


def _normalize(path: str) -> str:
    return path.replace("/", "\\").lower()


def _matches(rule: dict[str, Any], path: str) -> bool:
    p = _normalize(path)
    for prefix in rule.get("path_prefixes", []):
        if p.startswith(_normalize(prefix)):
            return True
    for marker in rule.get("path_contains", []):
        if _normalize(marker) in p:
            return True
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("\\", 1)[-1] else ""
    for candidate in rule.get("extensions", []):
        if ext == candidate.lower():
            return True
    pattern = rule.get("regex")
    if pattern:
        try:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        except re.error:
            return False
    return False


def evaluate_rule(path: str) -> dict[str, Any]:
    """Return ``{rule_id, rule, severity, level}`` for a file path.

    Deterministic: the highest severity among matching rules wins; the first
    matching rule supplies the rule id/name used on the event.
    """
    rules = load_rules()
    best: dict[str, Any] | None = None
    best_level = -1
    for rule in rules:
        if not _matches(rule, path):
            continue
        severity = rule.get("severity", "low")
        level = LEVELS.get(severity, 2)
        if level > best_level:
            best_level = level
            best = rule
    if best is None:
        best = {"rule_id": "FIM-DEFAULT-001", "name": "File change"}
        best_level = LEVELS["low"]
    return {
        "rule_id": best["rule_id"],
        "rule": best["name"],
        "severity": next(s for s, l in LEVELS.items() if l == best_level),
        "level": best_level,
    }
