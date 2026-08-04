"""SOAR playbook engine (function 10 - automated response).

Playbooks are YAML files defining a trigger and an ordered list of actions.
The engine evaluates triggers against alerts and executes actions through
connectors, recording an audit trail for every step.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.core.config import settings

log = logging.getLogger("siem.soar")

_ACTION_TYPES = {"block_ip", "isolate_host", "kill_process", "webhook", "email"}
_DESTRUCTIVE = {"block_ip", "isolate_host", "kill_process"}
_TEMPLATE_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")
_ENV_RE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")


def resolve_env(value: str) -> str:
    """Substitute ${ENV_VAR} references from application settings / environment."""

    def _lookup(match: re.Match) -> str:
        import os

        name = match.group(1)
        attr = getattr(settings, name.lower(), None)
        if attr is not None:
            return str(attr)
        return os.environ.get(name, "")

    return _ENV_RE.sub(_lookup, value)


class PlaybookError(Exception):
    pass


@dataclass
class Playbook:
    id: str
    name: str
    description: str
    trigger: dict
    actions: list[dict] = field(default_factory=list)
    enabled: bool = True


def render_template(template: str, context: dict[str, Any]) -> str:
    def _replace(match: re.Match) -> str:
        value = context.get(match.group(1))
        return str(value if value is not None else match.group(0))

    return _TEMPLATE_RE.sub(_replace, template)


class PlaybookSet:
    def __init__(self, playbooks: list[Playbook] | None = None) -> None:
        self._playbooks = playbooks or []

    @classmethod
    def load_dir(cls, directory: str) -> "PlaybookSet":
        path = Path(directory)
        playbooks: list[Playbook] = []
        if not path.exists():
            log.warning("Playbook directory %s does not exist", directory)
            return cls([])
        for file in sorted(path.glob("*.yml")):
            try:
                playbooks.append(cls._from_file(file))
            except PlaybookError as exc:
                log.error("Skipping playbook %s: %s", file.name, exc)
        return cls(playbooks)

    @classmethod
    def from_yaml(cls, raw: str) -> "PlaybookSet":
        return cls([cls._parse(yaml.safe_load(raw))])

    @classmethod
    def _from_file(cls, file: Path) -> Playbook:
        with file.open("r", encoding="utf-8") as fh:
            return cls._parse(yaml.safe_load(fh))

    @staticmethod
    def _parse(data: Any) -> Playbook:
        if not isinstance(data, dict):
            raise PlaybookError("playbook root must be a mapping")
        pid = str(data.get("id", "")).strip()
        if not pid:
            raise PlaybookError("playbook missing required 'id'")
        actions = data.get("actions", [])
        if not isinstance(actions, list) or not actions:
            raise PlaybookError(f"playbook '{pid}' has no actions")
        for action in actions:
            if action.get("type") not in _ACTION_TYPES:
                raise PlaybookError(f"playbook '{pid}' has unsupported action type {action.get('type')!r}")
        return Playbook(
            id=pid,
            name=str(data.get("name", pid)),
            description=str(data.get("description", "")),
            trigger=data.get("trigger", {}) or {},
            actions=actions,
            enabled=bool(data.get("enabled", True)),
        )

    def list_playbooks(self) -> list[Playbook]:
        return self._playbooks

    def get(self, playbook_id: str) -> Playbook | None:
        return next((p for p in self._playbooks if p.id == playbook_id), None)

    def match(self, alert: dict[str, Any]) -> list[Playbook]:
        """Return enabled playbooks whose trigger matches the alert."""
        severity_rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        alert_severity = severity_rank.get(str(alert.get("severity", "")).lower(), 0)
        matched: list[Playbook] = []
        for playbook in self._playbooks:
            if not playbook.enabled:
                continue
            trigger = playbook.trigger
            if trigger.get("type", "alert") != "alert":
                continue
            rule_id = trigger.get("rule_id")
            if rule_id and rule_id != alert.get("rule_id"):
                continue
            min_severity = trigger.get("min_severity")
            if min_severity and severity_rank.get(str(min_severity).lower(), 0) > alert_severity:
                continue
            matched.append(playbook)
        return matched


def load_playbook_set() -> PlaybookSet:
    return PlaybookSet.load_dir(settings.soar_playbooks_dir)
