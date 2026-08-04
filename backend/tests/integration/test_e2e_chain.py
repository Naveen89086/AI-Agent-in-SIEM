"""End-to-end integration test for the full detection-to-response chain.

Feeds realistic malicious events through the real pipeline components:

    raw event -> normalize -> detect (correlation + signatures + YARA + ML)
              -> alert -> AI analysis -> investigation case -> SOAR playbook

Runs entirely in-process with the in-memory bus and the temp SQLite DB that
the shared conftest configures, so no external services are needed.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.models.alert import Alert
from app.pipeline.bus import EventBus, InMemoryBus, Topics, stamp
from app.schemas.case import CaseCreate
from app.services.agent_service import AgentService
from app.services.alert_service import AlertService
from app.services.case_service import CaseService
from app.services.detection_service import DetectionService
from app.services.normalizer_service import NormalizerService
from app.services.soar_service import SoarService
from app.storage.base import build_log_store


def _ts(offset_s: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)).isoformat()


def _ssh_failed(offset_s: int, ip: str) -> dict[str, str]:
    ts = _ts(offset_s)
    return {
        "source_type": "linux",
        "source_name": "webserver01-sshd",
        "host": "webserver01",
        "message": (
            f"{ts} webserver01 sshd[10233]: Failed password for root "
            f"from {ip} port 53221 ssh2"
        ),
        "received_at": ts,
        "extra": {},
        "tags": ["e2e"],
    }


@pytest.fixture()
def pipeline(db, seeded_playbook):
    """Wire the real pipeline services over one in-memory bus + local store."""
    bus = InMemoryBus()
    store = build_log_store()
    return {
        "db": db,
        "bus": bus,
        "normalizer": NormalizerService(bus, store),
        "detectors": DetectionService(bus),
        "alerts": AlertService(db, bus),
        "agent": AgentService(db),
        "cases": CaseService(db),
        "soar": SoarService(db),
    }


@pytest.fixture()
def seeded_playbook():
    """Ensure the SSH brute-force SOAR playbook exists in the temp dir."""
    from pathlib import Path

    from app.core.config import settings

    playbook_dir = Path(settings.soar_playbooks_dir)
    playbook_dir.mkdir(parents=True, exist_ok=True)
    (playbook_dir / "block-brute-force-source.yml").write_text(
        """\
id: block-brute-force-source
name: Block brute-force source IP
description: Block the source IP when SSH brute force is detected.
enabled: true
trigger:
  type: alert
  rule_id: 11111111-1111-4111-8111-111111111101
  min_severity: high
actions:
  - type: block_ip
    name: Block source IP
    target: source.ip
  - type: webhook
    name: Notify SOC channel
    url: "${SOAR_WEBHOOK_DEFAULT_URL}"
    payload:
      ip: "{{source.ip}}"
""",
        encoding="utf-8",
    )
    return playbook_dir


async def _run_chain(pipeline, raw_events: list[dict]) -> list[str]:
    """Push raw events through normalize -> detect -> alert, return new alert ids."""
    bus: EventBus = pipeline["bus"]
    alert_ids: list[str] = []
    for raw in raw_events:
        raw = stamp(raw)
        await bus.publish(Topics.RAW_EVENTS, raw)
        event = await pipeline["normalizer"].process(raw)
        assert event is not None, "normalizer dropped the event"
        for detection in await pipeline["detectors"].process_event(event):
            alert = await pipeline["alerts"].process_detection(detection)
            if alert.id not in alert_ids:
                alert_ids.append(alert.id)
    return alert_ids


def test_full_chain_ssh_brute_force(pipeline):
    """SSH brute force: raw -> alert -> AI -> case -> SOAR playbook."""
    attacker = "185.220.101.34"
    raw_events = [_ssh_failed(-30 + i * 3, attacker) for i in range(8)]

    alert_ids = asyncio.run(_run_chain(pipeline, raw_events))
    assert alert_ids, "no alerts were raised for the brute force"
    alert_id = alert_ids[0]

    # AI analysis of the alert (heuristic provider, no external LLM needed)
    response, record = asyncio.run(pipeline["agent"].analyze_alert(alert_id))
    assert record.alert_id == alert_id
    assert response.risk_score is not None

    # Investigation case tied to the alert
    case = pipeline["cases"].create(
        CaseCreate(
            title="[E2E] SSH brute force",
            description="Investigation case from E2E chain.",
            severity="high",
            tags=["e2e"],
            alert_ids=[alert_id],
        )
    )
    assert alert_id in (case.alert_ids or [])
    timeline = pipeline["cases"].timeline(case.id)
    assert any(entry["type"] == "alert" for entry in timeline)

    # SOAR playbook executes against the alert
    from app.services.alert_service import _to_dict

    alert_obj = pipeline["db"].get(Alert, alert_id)
    records = asyncio.run(pipeline["soar"].execute_for_alert(_to_dict(alert_obj)))
    assert any(r.playbook_id == "block-brute-force-source" for r in records)
    # destructive step must be skipped by default safety gate
    assert any(r.action_type == "block_ip" and r.status == "skipped" for r in records)


def test_full_chain_benign_traffic_no_alerts(pipeline):
    """Benign traffic must not raise alerts."""
    benign = [
        _ssh_failed(-5, "10.0.0.5"),
        _ssh_failed(-3, "10.0.0.6"),
        _ssh_failed(-1, "10.0.0.7"),
    ]
    alert_ids = asyncio.run(_run_chain(pipeline, benign))
    assert alert_ids == []
