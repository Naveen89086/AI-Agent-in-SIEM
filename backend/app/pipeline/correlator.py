"""Correlation engine (function 3).

Consumes normalized events, evaluates Sigma-inspired rules:

  - single:      one event satisfying the rule filters -> detection
  - threshold:   N matching events within a sliding window,
                 grouped by an optional field -> detection

Windows are tracked in-memory (a dedicated window store could back this with
Redis later); counts reset after a detection fires so the rule re-arms.
"""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from app.pipeline.bus import EventBus, Topics
from app.pipeline.detection import Detection, summarize_event
from app.pipeline.rules import DetectionRule, RuleSet

log = logging.getLogger("siem.correlator")


class Correlator:
    def __init__(
        self,
        bus: EventBus,
        rules: RuleSet,
        auto_publish: bool = True,
    ) -> None:
        self.bus = bus
        self.rules = rules
        self.auto_publish = auto_publish
        self._windows: dict[tuple[str, str], list[tuple[float, dict[str, Any]]]] = (
            defaultdict(list)
        )

    # ------------------------------------------------------------------ match
    @staticmethod
    def _get_path(event: dict[str, Any], dotted: str) -> Any:
        node: Any = event
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    @classmethod
    def _value_matches(cls, event_value: Any, expected: Any) -> bool:
        if isinstance(expected, list):
            return any(cls._value_matches(event_value, e) for e in expected)
        if expected is None:
            return event_value is None
        if isinstance(event_value, bool) or isinstance(expected, bool):
            return event_value == expected
        if isinstance(event_value, (int, float)) and isinstance(expected, str):
            try:
                return event_value == int(expected) or event_value == float(expected)
            except ValueError:
                return str(event_value) == expected
        if isinstance(event_value, str) and isinstance(expected, str):
            return event_value.lower() == expected.lower()
        return event_value == expected

    def matches(self, event: dict[str, Any], rule: DetectionRule) -> bool:
        filters = rule.event_filters
        for field, expected in filters.items():
            value = self._get_path(event, field)
            if not self._value_matches(value, expected):
                return False
        return True

    # ------------------------------------------------------------------ events
    def _group_value(self, event: dict[str, Any], rule: DetectionRule) -> str:
        field = rule.grouping_field
        if not field:
            return "*"
        value = self._get_path(event, field)
        return str(value if value is not None else "null")

    def _emit(
        self,
        rule: DetectionRule,
        events: list[dict[str, Any]],
        grouping: dict[str, Any] | None = None,
    ) -> Detection:
        return Detection(
            rule_id=rule.id,
            rule_title=rule.title,
            severity=rule.severity,
            description=rule.description,
            detector="correlation",
            event_ids=[e.get("event_id", "") for e in events if e.get("event_id")],
            events=[summarize_event(e) for e in events],
            mitre=rule.mitre,
            tags=rule.tags,
            grouping=grouping or {},
            metadata={"source": rule.source, "condition": rule.condition},
        )

    # ------------------------------------------------------------------ checks
    async def process_event(self, event: dict[str, Any]) -> list[Detection]:
        detections: list[Detection] = []
        for rule in self.rules.active():
            if not self.matches(event, rule):
                continue
            if rule.condition == "single":
                detections.append(self._emit(rule, [event]))
            elif rule.condition == "threshold":
                fired = self._track_threshold(rule, event)
                if fired:
                    detections.append(fired)
        if self.auto_publish:
            for detection in detections:
                await self.bus.publish(Topics.DETECTIONS, detection.to_dict())
        return detections

    def _event_time(self, event: dict[str, Any]) -> float:
        ts = event.get("@timestamp")
        if isinstance(ts, (int, float)):
            return float(ts)
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            return datetime.now(timezone.utc).timestamp()

    def _track_threshold(
        self, rule: DetectionRule, event: dict[str, Any]
    ) -> Detection | None:
        now = self._event_time(event)
        window = rule.timeframe_seconds or 60
        group = self._group_value(event, rule)
        key = (rule.id, group)

        bucket = self._windows[key]
        bucket[:] = [(ts, e) for ts, e in bucket if now - ts <= window]
        bucket.append((now, event))

        if len(bucket) >= rule.threshold:
            events = [e for _, e in bucket]
            grouping = {rule.grouping_field or "group": group}
            self._windows[key] = []  # re-arm after firing
            return self._emit(rule, events, grouping)
        return None

    async def run(self, group: str = "correlator") -> None:
        consumer = f"correlator-{uuid.uuid4().hex[:6]}"
        log.info("Correlator consuming %s as %s", Topics.NORMALIZED_EVENTS, consumer)
        async for topic, event, msg_id in self.bus.subscribe(
            [Topics.NORMALIZED_EVENTS], group, consumer
        ):
            try:
                await self.process_event(event)
            except Exception:
                log.exception("Correlation failed (event=%s)", event.get("event_id"))
            await self.bus.ack(topic, group, msg_id)
