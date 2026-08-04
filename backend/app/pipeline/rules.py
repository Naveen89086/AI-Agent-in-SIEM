"""Detection rule model and loader (Sigma-inspired YAML).

Rule file structure:
    title:      human readable title
    id:         stable uuid
    status:     active | test | deprecated
    description:what this rule detects
    severity:   informational | low | medium | high | critical
    tags:       [ ... ]
    mitre:      [{tactic, technique, technique_name}]
    logsource:  {product, category}
    detection:
      condition:  single | threshold
      event:      {field: value, other_field: [v1, v2]}   (exact match, OR for lists)
      threshold:  N      (only for threshold)
      timeframe:  "60s"  (only for threshold; also supports "5m", "1h")
"""

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class RuleError(ValueError):
    pass


@dataclass
class DetectionRule:
    title: str
    id: str
    description: str
    severity: str
    detection: dict[str, Any]
    status: str = "active"
    tags: list[str] = field(default_factory=list)
    mitre: list[dict[str, str]] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    source: str | None = None

    @property
    def condition(self) -> str:
        return self.detection.get("condition", "single")

    @property
    def timeframe_seconds(self) -> int | None:
        raw = self.detection.get("timeframe")
        if not raw:
            return None
        m = re.fullmatch(r"(\d+)([smhd])", str(raw).strip().lower())
        if not m:
            raise RuleError(f"Invalid timeframe '{raw}' in rule {self.id}")
        multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
        return int(m.group(1)) * multiplier

    @property
    def threshold(self) -> int:
        return int(self.detection.get("threshold", 1))

    @property
    def grouping_field(self) -> str | None:
        return self.detection.get("group_by")

    @property
    def event_filters(self) -> dict[str, Any]:
        return self.detection.get("event", {}) or {}

    @classmethod
    def from_mapping(cls, data: dict[str, Any], source: str | None = None) -> "DetectionRule":
        try:
            rule = cls(
                title=str(data["title"]),
                id=str(data.get("id") or uuid.uuid4()),
                description=str(data.get("description", "")),
                severity=str(data.get("severity", "medium")).lower(),
                detection=dict(data["detection"]),
                status=str(data.get("status", "active")),
                tags=list(data.get("tags", []) or []),
                mitre=list(data.get("mitre", []) or []),
                logsource=dict(data.get("logsource", {}) or {}),
                source=source,
            )
        except KeyError as exc:
            raise RuleError(f"Rule is missing required field {exc.args[0]}") from exc
        if rule.condition not in ("single", "threshold"):
            raise RuleError(f"Unsupported condition '{rule.condition}' in rule {rule.id}")
        if rule.condition == "threshold":
            if not rule.timeframe_seconds:
                raise RuleError(f"Threshold rule {rule.id} requires a timeframe")
            if rule.threshold < 1:
                raise RuleError(f"Threshold rule {rule.id} requires threshold >= 1")
        return rule


class RuleSet:
    """A collection of loaded detection rules with match helpers."""

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules = rules or []

    def active(self) -> list[DetectionRule]:
        return [r for r in self.rules if r.status == "active"]

    def by_id(self, rule_id: str) -> DetectionRule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    @staticmethod
    def load_dir(path: str | Path) -> "RuleSet":
        path = Path(path)
        rules: list[DetectionRule] = []
        if not path.exists():
            return RuleSet(rules)
        for file in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
            try:
                data = yaml.safe_load(file.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                raise RuleError(f"Invalid YAML in {file.name}: {exc}") from exc
            if isinstance(data, list):
                for item in data:
                    rules.append(DetectionRule.from_mapping(item, str(file)))
            elif isinstance(data, dict):
                rules.append(DetectionRule.from_mapping(data, str(file)))
        return RuleSet(rules)

    @staticmethod
    def from_file(path: str | Path) -> "DetectionRule":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return DetectionRule.from_mapping(data, str(path))
