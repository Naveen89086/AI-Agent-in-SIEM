"""Module 12 - SOAR tests."""

import asyncio
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.core.config import settings
from app.db.base import Base
from app.pipeline.playbooks import PlaybookSet, PlaybookError, render_template
from app.services.soar_service import Connectors, SoarService


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def post(self, url, json=None, **kwargs):
        self.calls.append((url, json or {}))
        return type("R", (), {"status_code": 200, "raise_for_status": lambda self: None})()


def _playbooks_yaml() -> str:
    return """
id: block-brute-force-source
name: Block brute-force source IP
description: Block the attacking IP.
enabled: true
trigger:
  type: alert
  rule_id: ssh_brute_force
  min_severity: high
actions:
  - type: webhook
    url: "https://hooks.example.com/respond"
    payload:
      event: playbook.executed
      ip: "{{source.ip}}"
  - type: block_ip
    target: source.ip
    api: "https://firewall.example.com/block"
"""


def _alert() -> dict:
    return {
        "id": "alert-1",
        "rule_id": "ssh_brute_force",
        "rule_title": "SSH Brute Force",
        "severity": "high",
        "source.ip": "198.51.100.42",
        "host.name": "web-01",
    }


# ---------------------------------------------------------------- playbooks
def test_playbook_parse_and_match():
    pb = PlaybookSet.from_yaml(_playbooks_yaml())
    playbook = pb.get("block-brute-force-source")
    assert playbook is not None
    assert playbook.trigger["rule_id"] == "ssh_brute_force"
    matches = pb.match(_alert())
    assert len(matches) == 1
    # severity gate
    low_alert = {**_alert(), "severity": "low"}
    assert pb.match(low_alert) == []


def test_playbook_invalid_action_rejected():
    raw = """
id: bad
name: bad
actions:
  - type: explode
"""
    with pytest.raises(PlaybookError):
        PlaybookSet.from_yaml(raw)


def test_render_template():
    assert render_template("ip {{source.ip}}", {"source.ip": "1.2.3.4"}) == "ip 1.2.3.4"
    assert render_template("keep {{missing}}", {}) == "keep {{missing}}"


# ---------------------------------------------------------------- execution
def test_execute_success_records_audit(db_session):
    async def scenario():
        settings.soar_allow_destructive = True
        client = FakeClient()
        service = SoarService(
            db_session,
            playbook_set=PlaybookSet.from_yaml(_playbooks_yaml()),
            connectors=Connectors(http_client=client),
        )
        records = await service.execute("block-brute-force-source", _alert())
        record = records[-1]
        assert record.status == "success"
        assert [r.status for r in records] == ["success", "success"]
        assert client.calls == [
            ("https://hooks.example.com/respond", {"event": "playbook.executed", "ip": "198.51.100.42"}),
            ("https://firewall.example.com/block", {"action": "block_ip", "target": "198.51.100.42"}),
        ]
        rows, total = service.list_actions(alert_id="alert-1")
        assert total == 2
        assert {r.status for r in rows} == {"success"}

    asyncio.run(scenario())


def test_destructive_actions_gated(db_session):
    async def scenario():
        settings.soar_allow_destructive = False
        service = SoarService(
            db_session,
            playbook_set=PlaybookSet.from_yaml(_playbooks_yaml()),
            connectors=Connectors(http_client=FakeClient()),
        )
        records = await service.execute("block-brute-force-source", _alert())
        # webhook succeeds, destructive block_ip skipped
        assert [r.status for r in records] == ["success", "skipped"]
        assert "disabled" in records[1].detail

    asyncio.run(scenario())


def test_webhook_failure_records_failed(db_session):
    async def scenario():
        class FailingClient:
            async def post(self, url, json=None, **kwargs):
                raise RuntimeError("connection refused")

        service = SoarService(
            db_session,
            playbook_set=PlaybookSet.from_yaml(_playbooks_yaml()),
            connectors=Connectors(http_client=FailingClient()),
        )
        records = await service.execute("block-brute-force-source", _alert())
        assert records[0].status == "failed"  # webhook connector raised
        assert records[1].status == "skipped"  # destructive gated off

    asyncio.run(scenario())


# ---------------------------------------------------------------------- API
@pytest.fixture()
def seeded_playbooks():
    from pathlib import Path

    from app.core.config import settings

    playbook_dir = Path(settings.soar_playbooks_dir)
    playbook_dir.mkdir(parents=True, exist_ok=True)
    (playbook_dir / "block-brute-force-source.yml").write_text(_playbooks_yaml(), encoding="utf-8")
    (playbook_dir / "webhook-only.yml").write_text(
        """
id: webhook-only
name: Webhook only
description: test
enabled: true
trigger:
  type: alert
  rule_id: ssh_brute_force
  min_severity: high
actions:
  - type: webhook
    url: "${SOAR_WEBHOOK_DEFAULT_URL}"
    payload:
      ip: "{{source.ip}}"
""",
        encoding="utf-8",
    )
    return playbook_dir


def test_api_soar_status(client, admin_headers):
    resp = client.get("/api/v1/soar/status", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["destructive_actions_enabled"] is False


def test_api_soar_playbooks(client, admin_headers, seeded_playbooks):
    resp = client.get("/api/v1/soar/playbooks", headers=admin_headers)
    assert resp.status_code == 200
    ids = [p["id"] for p in resp.json()]
    assert "block-brute-force-source" in ids


def test_api_soar_execute_webhook_safe(client, admin_headers, seeded_playbooks):
    resp = client.post(
        "/api/v1/soar/playbooks/webhook-only/execute",
        headers=admin_headers,
        json={"alert": _alert()},
    )
    assert resp.status_code == 200
    assert resp.json()["actions"] == 1
    # webhook may fail without a configured URL, but the audit trail records it
    assert resp.json()["success"] + resp.json()["failed"] + resp.json()["skipped"] == 1

    actions = client.get("/api/v1/soar/actions", headers=admin_headers)
    assert actions.status_code == 200
    assert actions.json()["total"] >= 1
    assert actions.json()["items"][0]["playbook_id"] == "webhook-only"


def test_api_soar_execute_missing_playbook(client, admin_headers):
    resp = client.post(
        "/api/v1/soar/playbooks/does-not-exist/execute",
        headers=admin_headers,
        json={"alert": _alert()},
    )
    assert resp.status_code == 422


def test_api_soar_requires_auth(client):
    assert client.get("/api/v1/soar/playbooks").status_code == 401
