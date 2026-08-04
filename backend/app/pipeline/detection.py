"""Detection model: the normalized output of every detection engine.

Correlator (M3), detector (M4) and the ML anomaly detector all emit the same
shape so alerting (M5) and the AI agent (M6) consume a uniform contract.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Detection:
    rule_id: str
    rule_title: str
    severity: str
    description: str
    detector: str  # correlation | sigma | yara | ml
    event_ids: list[str] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    mitre: list[dict[str, str]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    score: float | None = None
    grouping: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "description": self.description,
            "detector": self.detector,
            "event_ids": self.event_ids,
            "events": self.events,
            "mitre": self.mitre,
            "tags": self.tags,
            "score": self.score,
            "grouping": self.grouping,
            "metadata": self.metadata,
        }


def summarize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Compact projection of a normalized event for correlation output."""
    src = event.get("source") or {}
    dst = event.get("destination") or {}
    host = event.get("host") or {}
    user = event.get("user") or {}
    process = event.get("process") or {}
    return {
        "event_id": event.get("event_id"),
        "@timestamp": event.get("@timestamp"),
        "event": event.get("event", {}),
        "source_ip": src.get("ip"),
        "source_port": src.get("port"),
        "destination_ip": dst.get("ip"),
        "destination_port": dst.get("port"),
        "host": host.get("name"),
        "user": user.get("name"),
        "process": process.get("name"),
        "message": (event.get("message") or "")[:300],
    }
