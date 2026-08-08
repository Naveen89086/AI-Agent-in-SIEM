"""Agent-side collector contracts.

Mirrors the server-side ``app/sca/collectors/base.py`` contract so evidence
produced by an endpoint agent has the same shape the server engine persists.
"""

from dataclasses import dataclass, field
from typing import Any


class CollectorError(Exception):
    """Raised when a collector cannot read evidence from an endpoint."""


@dataclass
class Evidence:
    collected: bool = False
    actual_value: str | None = None
    not_applicable: bool = False
    raw: dict[str, Any] = field(default_factory=dict)
    message: str = ""


class Collector:
    rule_type: str = ""

    def collect(self, rule, platform: str) -> Evidence:
        raise NotImplementedError
