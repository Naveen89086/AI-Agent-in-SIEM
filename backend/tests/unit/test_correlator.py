"""Module 3 - event correlation tests."""

import asyncio
from pathlib import Path

from app.pipeline.bus import InMemoryBus, Topics
from app.pipeline.correlator import Correlator
from app.pipeline.detection import summarize_event
from app.pipeline.rules import DetectionRule, RuleSet

RULES_DIR = Path(__file__).resolve().parents[2] / "app" / "rules"


def _event(
    action: str,
    *,
    ip: str = "203.0.113.9",
    outcome: str = "failure",
    ts: str = "2026-08-01T12:00:01+00:00",
    event_id: str = "evt",
    status_code: int | None = None,
) -> dict:
    ev: dict = {
        "event_id": event_id,
        "@timestamp": ts,
        "event": {"action": action, "outcome": outcome},
        "source": {"ip": ip},
        "host": {"name": "srv1"},
        "message": f"{action} from {ip}",
        "pipeline": {"normalized": True},
    }
    if status_code is not None:
        ev["event"]["module"] = "httpd"
        ev["http"] = {"response": {"status_code": status_code}}
    return ev


def _rule(**overrides) -> DetectionRule:
    base = {
        "title": "Test Rule",
        "id": "test-rule-1",
        "description": "test",
        "severity": "high",
        "detection": {
            "condition": "single",
            "event": {"event.action": "ssh_failed_login"},
        },
    }
    base.update(overrides)
    return DetectionRule.from_mapping(base)


# ------------------------------------------------------------------- rule loading
def test_bundled_rules_load():
    rules = RuleSet.load_dir(RULES_DIR)
    assert len(rules.active()) >= 8
    ids = {r.id for r in rules.active()}
    assert len(ids) == len(rules.active())
    for rule in rules.active():
        assert rule.severity in ("informational", "low", "medium", "high", "critical")


def test_rule_from_mapping_validation():
    try:
        _rule(detection={"condition": "threshold", "event": {}})
    except ValueError:
        pass
    else:
        raise AssertionError("threshold rule without timeframe must be rejected")


def test_timeframe_parsing():
    rule = _rule(
        detection={
            "condition": "threshold",
            "event": {},
            "threshold": 5,
            "timeframe": "5m",
        }
    )
    assert rule.timeframe_seconds == 300


# --------------------------------------------------------------------- single
def test_single_condition_detects():
    async def scenario():
        bus = InMemoryBus()
        corr = Correlator(bus, RuleSet([_rule()]))
        result = await corr.process_event(_event("ssh_failed_login"))
        assert len(result) == 1
        d = result[0]
        assert d.rule_id == "test-rule-1"
        assert d.detector == "correlation"
        assert d.severity == "high"
        assert d.events[0]["source_ip"] == "203.0.113.9"

        # published on detections topic
        received = []
        async for topic, event, msg_id in bus.subscribe(
            [Topics.DETECTIONS], "g", "c", block_ms=200
        ):
            received.append(event)
            if len(received) == 1:
                break
        assert received[0]["rule_title"] == "Test Rule"

    asyncio.run(scenario())


def test_single_no_false_positive():
    async def scenario():
        bus = InMemoryBus()
        corr = Correlator(bus, RuleSet([_rule()]))
        result = await corr.process_event(_event("ssh_login", outcome="success"))
        assert result == []

    asyncio.run(scenario())


# ------------------------------------------------------------------- threshold
def test_threshold_fires_after_n():
    async def scenario():
        bus = InMemoryBus()
        rule = _rule(
            detection={
                "condition": "threshold",
                "event": {"event.action": "ssh_failed_login"},
                "group_by": "source.ip",
                "threshold": 5,
                "timeframe": "60s",
            }
        )
        corr = Correlator(bus, RuleSet([rule]))
        for i in range(4):
            assert await corr.process_event(_event("ssh_failed_login", event_id=f"e{i}")) == []
        detections = await corr.process_event(_event("ssh_failed_login", event_id="e4"))
        assert len(detections) == 1
        assert detections[0].grouping["source.ip"] == "203.0.113.9"
        assert len(detections[0].events) == 5

    asyncio.run(scenario())


def test_threshold_groups_by_field():
    async def scenario():
        bus = InMemoryBus()
        rule = _rule(
            detection={
                "condition": "threshold",
                "event": {"event.action": "ssh_failed_login"},
                "group_by": "source.ip",
                "threshold": 5,
                "timeframe": "60s",
            }
        )
        corr = Correlator(bus, RuleSet([rule]))
        # attacker A gets 4 (below threshold), attacker B gets 5 -> only B fires
        detections = []
        for i in range(4):
            detections += await corr.process_event(
                _event("ssh_failed_login", ip="1.1.1.1", event_id=f"a{i}")
            )
        for i in range(5):
            detections += await corr.process_event(
                _event("ssh_failed_login", ip="2.2.2.2", event_id=f"b{i}")
            )
        assert len(detections) == 1
        assert detections[0].grouping["source.ip"] == "2.2.2.2"

    asyncio.run(scenario())


def test_threshold_window_expiry():
    async def scenario():
        bus = InMemoryBus()
        rule = _rule(
            detection={
                "condition": "threshold",
                "event": {"event.action": "ssh_failed_login"},
                "group_by": "source.ip",
                "threshold": 3,
                "timeframe": "60s",
            }
        )
        corr = Correlator(bus, RuleSet([rule]))
        for i, ts in enumerate(
            ["2026-08-01T12:00:00+00:00", "2026-08-01T12:00:10+00:00"]
        ):
            await corr.process_event(_event("ssh_failed_login", ts=ts, event_id=f"e{i}"))
        # third event falls outside the 60s window of the first two
        detections = await corr.process_event(
            _event("ssh_failed_login", ts="2026-08-01T12:02:00+00:00", event_id="e3")
        )
        assert detections == []

    asyncio.run(scenario())


def test_threshold_rearms_after_fire():
    async def scenario():
        bus = InMemoryBus()
        rule = _rule(
            detection={
                "condition": "threshold",
                "event": {"event.action": "ssh_failed_login"},
                "threshold": 3,
                "timeframe": "60s",
            }
        )
        corr = Correlator(bus, RuleSet([rule]))
        for i in range(3):  # e0,e1,e2 -> fires at e2, window cleared
            await corr.process_event(_event("ssh_failed_login", event_id=f"e{i}"))
        # a fresh 3 events within the window must fire again
        for i in range(3, 5):
            await corr.process_event(_event("ssh_failed_login", event_id=f"e{i}"))
        second = await corr.process_event(_event("ssh_failed_login", event_id="e5"))
        assert len(second) == 1

    asyncio.run(scenario())


# ------------------------------------------------------------- value matching
def test_list_and_numeric_matching():
    async def scenario():
        bus = InMemoryBus()
        rule = _rule(
            detection={
                "condition": "single",
                "event": {
                    "event.action": "http_response",
                    "http.response.status_code": [401, 403],
                },
            }
        )
        corr = Correlator(bus, RuleSet([rule]))
        assert await corr.process_event(
            _event("http_response", status_code=403, event_id="w1")
        )
        assert await corr.process_event(_event("http_response", event_id="w2")) == []

    asyncio.run(scenario())


# --------------------------------------------------------------------- summary
def test_summarize_event():
    ev = _event("ssh_failed_login")
    summary = summarize_event(ev)
    assert summary["source_ip"] == "203.0.113.9"
    assert summary["host"] == "srv1"
    assert summary["event_id"] == "evt"
