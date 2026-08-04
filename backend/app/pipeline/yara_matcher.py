"""Signature-based threat detection (function 4, part 1).

Two matchers share the same contract:

  SignatureMatcher - pure-Python YAML signatures (works everywhere):
      title, id, severity, description, mitre, tags
      match:
        process.name: powershell.exe
        process.command_line contains: mimikatz
        file.hash.md5: [...]
        user.name: ...

  YaraMatcher - native yara-python wrapper (optional). Detects file hashes,
  process names and command-line strings with real YARA rules. When the
  `yara` package is unavailable it degrades to a no-op so the pipeline never
  breaks on hosts without the native library.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.core.config import settings
from app.pipeline.detection import Detection, summarize_event

log = logging.getLogger("siem.detectors.signature")


@dataclass
class SignatureRule:
    title: str
    id: str
    description: str
    severity: str
    match: dict[str, Any]
    mitre: list[dict[str, str]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, data: dict[str, Any], source: str) -> "SignatureRule":
        return cls(
            title=str(data.get("title", source)),
            id=str(data.get("id") or f"sig-{source}"),
            description=str(data.get("description", "")),
            severity=str(data.get("severity", "medium")).lower(),
            match=dict(data.get("match", {})),
            mitre=list(data.get("mitre", []) or []),
            tags=list(data.get("tags", []) or []),
        )


class SignatureMatcher:
    """Pure-Python event signature matcher (no native dependencies)."""

    def __init__(self, rules: list[SignatureRule] | None = None) -> None:
        self.rules = rules or []
        self._compiled = self._compile(self.rules)

    @staticmethod
    def _compile(rules: list[SignatureRule]) -> list[tuple[SignatureRule, list[tuple]]]:
        """Pre-compile each match condition into (field_path, op, expected) tuples.

        Supported ops derived from the condition key:
            field: value            -> exact
            field contains: substr  -> substring
            field endswith: x
            field startswith: x
            field present           -> field must exist
        """
        compiled = []
        for rule in rules:
            conditions: list[tuple] = []
            for raw_field, expected in rule.match.items():
                op = "exact"
                field = raw_field
                for candidate, candidate_op in (
                    (" contains", "contains"),
                    (" startswith", "startswith"),
                    (" endswith", "endswith"),
                    (" present", "present"),
                ):
                    if candidate in raw_field:
                        field = raw_field.replace(candidate, "")
                        op = candidate_op
                        break
                conditions.append((field, op, expected))
            compiled.append((rule, conditions))
        return compiled

    @staticmethod
    def _get_path(event: dict[str, Any], dotted: str) -> Any:
        node: Any = event
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    @staticmethod
    def _as_list(value: Any) -> list:
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    def _condition_holds(self, event: dict[str, Any], field: str, op: str, expected: Any) -> bool:
        actual = self._get_path(event, field)
        expected_list = self._as_list(expected)
        if op == "present":
            return actual is not None
        if actual is None:
            return False
        for exp in expected_list:
            if op == "exact" and str(actual).lower() == str(exp).lower():
                return True
            if op == "contains" and str(exp).lower() in str(actual).lower():
                return True
            if op == "startswith" and str(actual).lower().startswith(str(exp).lower()):
                return True
            if op == "endswith" and str(actual).lower().endswith(str(exp).lower()):
                return True
        return False

    def match(self, event: dict[str, Any]) -> list[Detection]:
        detections: list[Detection] = []
        for rule, conditions in self._compiled:
            if all(self._condition_holds(event, f, op, exp) for f, op, exp in conditions):
                detections.append(
                    Detection(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        severity=rule.severity,
                        description=rule.description,
                        detector="signature",
                        event_ids=[event.get("event_id", "")],
                        events=[summarize_event(event)],
                        mitre=rule.mitre,
                        tags=rule.tags,
                    )
                )
        return detections

    @staticmethod
    def load_dir(path: str | Path) -> "SignatureMatcher":
        path = Path(path)
        rules: list[SignatureRule] = []
        if path.exists():
            for file in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
                try:
                    data = yaml.safe_load(file.read_text(encoding="utf-8"))
                except yaml.YAMLError as exc:
                    log.warning("Skipping invalid signature file %s: %s", file.name, exc)
                    continue
                if isinstance(data, list):
                    rules.extend(SignatureRule.from_mapping(d, str(file)) for d in data)
                elif isinstance(data, dict):
                    rules.append(SignatureRule.from_mapping(data, str(file)))
        return SignatureMatcher(rules)


class YaraMatcher:
    """Native YARA matcher. Degrades to no-op when yara is unavailable."""

    def __init__(self, rules_dir: str | Path | None = None) -> None:
        self.available = False
        self._engine: Any = None
        rules_dir = rules_dir or settings.yara_rules_dir
        try:
            import yara  # type: ignore

            self.available = True
        except ImportError:
            log.info("yara-python not installed; native YARA matching disabled")
            return
        compiled: list[Any] = []
        path = Path(rules_dir)
        if path.exists():
            for file in sorted(path.rglob("*.yar")) + sorted(path.rglob("*.yars")):
                try:
                    compiled.append(yara.compile(filepaths={str(file): str(file)}))
                except Exception as exc:
                    log.warning("Failed to compile YARA rule %s: %s", file.name, exc)
        self._engine = compiled
        if compiled:
            self.available = True

    def match(self, event: dict[str, Any]) -> list[Detection]:
        if not self.available or not self._engine:
            return []
        targets = {
            "process_name": self._dig(event, "process.name"),
            "command_line": self._dig(event, "process.command_line"),
            "file_hash": self._dig(event, "file.hash.md5"),
            "file_name": self._dig(event, "file.name"),
            "user": self._dig(event, "user.name"),
        }
        detections: list[Detection] = []
        for rule_set in self._engine:
            for rule in rule_set.match(data=str(targets).lower()):
                meta = rule.meta or {}
                detections.append(
                    Detection(
                        rule_id=str(rule.namespace),
                        rule_title=rule.rule,
                        severity=str(meta.get("severity", "medium")).lower(),
                        description=str(meta.get("description", "")),
                        detector="yara",
                        event_ids=[event.get("event_id", "")],
                        events=[summarize_event(event)],
                        tags=["yara"],
                    )
                )
        return detections

    @staticmethod
    def _dig(event: dict[str, Any], dotted: str) -> str:
        node: Any = event
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return ""
        return str(node if node is not None else "")


def build_signature_matcher() -> SignatureMatcher:
    if not settings.yara_enabled:
        return SignatureMatcher()
    dirs = Path(settings.yara_rules_dir) / "signatures"
    return SignatureMatcher.load_dir(dirs)
