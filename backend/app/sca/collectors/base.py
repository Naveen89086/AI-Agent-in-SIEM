"""Collector contracts for SCA endpoint evidence."""

from dataclasses import dataclass, field
from typing import Any

from app.models.sca.policy import CheckRule


class CollectorError(Exception):
    """Raised when a collector cannot read evidence from an endpoint."""


@dataclass
class Evidence:
    """Structured result returned by a collector.

    - ``collected``: True when evidence was read successfully.
    - ``actual_value``: the raw value to compare against the rule.
    - ``not_applicable``: True when the check does not apply (e.g. path absent).
    - ``raw``: full evidence payload persisted as JSON for the audit trail.
    - ``message``: human-readable note (or error) about the collection.
    """

    collected: bool = False
    actual_value: str | None = None
    not_applicable: bool = False
    raw: dict[str, Any] = field(default_factory=dict)
    message: str = ""


class Collector:
    """Base class for a rule-type collector."""

    rule_type: str = ""

    def collect(self, rule: CheckRule, platform: str) -> Evidence:
        raise NotImplementedError
