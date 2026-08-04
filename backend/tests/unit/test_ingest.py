"""Module 1 - log collection tests: ingest API, syslog parsing, file tailer."""

from fastapi.testclient import TestClient

from app.ingestion.syslog_receiver import SyslogReceiver
from app.pipeline.bus import InMemoryBus, Topics, build_event_bus


def test_ingest_batch_accepts(client: TestClient, admin_headers):
    resp = client.post(
        "/api/v1/ingest/events",
        headers=admin_headers,
        json={
            "events": [
                {
                    "message": "Failed password for root from 203.0.113.5 port 22",
                    "source_type": "linux",
                    "source_name": "srv-auth-01",
                    "host": "srv-auth-01",
                },
                {
                    "message": "Login event",
                    "source_type": "windows",
                    "source_name": "win01",
                },
            ]
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["accepted"] == 2


def test_ingest_rejects_empty(client: TestClient, admin_headers):
    resp = client.post(
        "/api/v1/ingest/events",
        headers=admin_headers,
        json={"events": []},
    )
    assert resp.status_code == 422


def test_ingest_requires_auth(client: TestClient):
    resp = client.post(
        "/api/v1/ingest/events", json={"events": [{"message": "x"}]}
    )
    assert resp.status_code == 401


def test_sources_crud(client: TestClient, admin_headers):
    created = client.post(
        "/api/v1/sources",
        headers=admin_headers,
        json={
            "name": "firewall-edge",
            "source_type": "syslog",
            "format": "syslog",
            "parser": "firewall",
        },
    )
    assert created.status_code == 201, created.text
    sid = created.json()["id"]

    listed = client.get("/api/v1/sources", headers=admin_headers)
    assert listed.status_code == 200
    assert any(s["name"] == "firewall-edge" for s in listed.json()["items"])

    toggled = client.post(f"/api/v1/sources/{sid}/toggle?enabled=false", headers=admin_headers)
    assert toggled.json()["enabled"] is False

    dup = client.post(
        "/api/v1/sources",
        headers=admin_headers,
        json={"name": "firewall-edge", "source_type": "syslog"},
    )
    assert dup.status_code == 409


def test_ingest_updates_source_stats(client: TestClient, admin_headers):
    client.post(
        "/api/v1/ingest/events",
        headers=admin_headers,
        json={"events": [{"message": "e1", "source_name": "stats-src", "source_type": "file"}]},
    )
    resp = client.get("/api/v1/sources", headers=admin_headers)
    src = next(s for s in resp.json()["items"] if s["name"] == "stats-src")
    assert src["received_count"] == 1
    assert src["last_seen_at"] is not None


# ---------------------------------------------------------------------------
# Bus behaviour
# ---------------------------------------------------------------------------
def test_inmemory_bus_publish_subscribe():
    import asyncio

    bus = InMemoryBus()

    async def scenario():
        await bus.publish(Topics.RAW_EVENTS, {"x": 1})
        async for topic, event, msg_id in bus.subscribe([Topics.RAW_EVENTS], "g", "c"):
            assert topic == Topics.RAW_EVENTS
            assert event["x"] == 1
            await bus.ack(topic, "g", msg_id)
            return

    asyncio.run(scenario())


def test_bus_factory_from_url():
    assert isinstance(build_event_bus("inmemory://"), InMemoryBus)
    assert build_event_bus("redis://localhost:6379/0").__class__.__name__ == "RedisStreamBus"


# ---------------------------------------------------------------------------
# Syslog parsing
# ---------------------------------------------------------------------------
def test_syslog_rfc3164():
    parsed = SyslogReceiver._parse_message(
        b"<34>Oct 11 22:14:15 myhost sshd[1234]: Failed password for root"
    )
    assert parsed is not None
    assert parsed["host"] == "myhost"
    assert parsed["extra"]["severity"] == 2  # critical
    assert "Failed password" in parsed["message"]


def test_syslog_rfc5424():
    parsed = SyslogReceiver._parse_message(
        b'<165>1 2003-10-11T22:14:15.003Z host1 app 123 ID47 - event happened'
    )
    assert parsed is not None
    assert parsed["host"] == "host1"
    assert parsed["extra"]["version"] == "1"
    assert "event happened" in parsed["message"]


def test_syslog_unstructured():
    parsed = SyslogReceiver._parse_message(b"just a plain line")
    assert parsed is not None
    assert parsed["message"] == "just a plain line"


def test_syslog_empty_line():
    assert SyslogReceiver._parse_message(b"") is None
