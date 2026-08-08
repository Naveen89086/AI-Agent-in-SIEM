"""Real-mode FIM tests: agent enrollment, authenticated ingest, server-side
reclassification against the baseline, dedupe and the demo-mode gate.

These use the shared session-scoped client (demo seeding enabled) plus a
freshly-registered real agent so the two data streams never mix.
"""

import hashlib

import pytest

API = "/api/v1/fim"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------- helpers
def _register(client, admin_headers, code="fim-test-001") -> dict:
    resp = client.post(
        f"{API}/agents/register",
        headers=admin_headers,
        json={
            "agent_code": code,
            "hostname": "fim-test-host",
            "ip_address": "10.0.0.9",
            "os_name": "Windows 11",
            "platform": "windows",
            "version": "1.0.0",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["api_key"], "registration must return a per-agent API key"
    assert data["code"] == code
    return data


def _ingest_headers(api_key: str) -> dict:
    return {"X-API-Key": api_key}


def test_register_agent_returns_api_key(client, admin_headers):
    data = _register(client, admin_headers, code="fim-reg-001")
    assert data["status"] == "active"
    assert data["last_seen"] is not None


def test_register_duplicate_conflict(client, admin_headers):
    _register(client, admin_headers, code="fim-reg-002")
    resp = client.post(
        f"{API}/agents/register",
        headers=admin_headers,
        json={"agent_code": "fim-reg-002", "hostname": "dup"},
    )
    assert resp.status_code == 409


def test_register_requires_admin_or_token(client):
    resp = client.post(
        f"{API}/agents/register",
        json={"agent_code": "fim-reg-003", "hostname": "x"},
    )
    assert resp.status_code == 401


def test_ingest_requires_api_key(client, admin_headers, db):
    data = _register(client, admin_headers, code="fim-ing-001")
    resp = client.post(
        f"{API}/ingest",
        json={
            "agent_code": data["code"],
            "event_type": "added",
            "path": r"C:\fim\new.txt",
            "sha256": _sha("hi"),
        },
    )
    assert resp.status_code == 401
    # nothing was stored
    events = client.get(f"{API}/events?agent_code=fim-ing-001", headers=admin_headers).json()
    assert events["total"] == 0


def test_ingest_added_updates_baseline(client, admin_headers):
    data = _register(client, admin_headers, code="fim-ing-002")
    digest = _sha("baseline content")
    resp = client.post(
        f"{API}/ingest",
        headers=_ingest_headers(data["api_key"]),
        json={
            "agent_code": data["code"],
            "event_type": "added",
            "path": r"C:\fim\file-a.txt",
            "sha256": digest,
            "size": 16,
            "source": "fim-agent",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] is True
    assert body["event_type"] == "added"
    assert body["severity"] in {"low", "medium", "high", "critical"}

    files = client.get(f"{API}/files?agent_code=fim-ing-002", headers=admin_headers).json()
    assert len(files) == 1
    assert files[0]["file"] == r"C:\fim\file-a.txt"
    assert files[0]["sha256"] == digest
    assert files[0]["status"] == "active"

    events = client.get(f"{API}/events?agent_code=fim-ing-002", headers=admin_headers).json()
    assert events["total"] == 1
    assert events["items"][0]["event_type"] == "added"
    assert events["items"][0]["sha256"] == digest


def test_ingest_reclassifies_modified_as_added(client, admin_headers):
    """A 'modified' report for a path the server never saw becomes 'added'."""
    data = _register(client, admin_headers, code="fim-recl-001")
    resp = client.post(
        f"{API}/ingest",
        headers=_ingest_headers(data["api_key"]),
        json={
            "agent_code": data["code"],
            "event_type": "modified",
            "path": r"C:\fim\unknown.bin",
            "sha256": _sha("x"),
        },
    )
    assert resp.status_code == 200
    assert resp.json()["event_type"] == "added"


def test_ingest_reclassifies_added_as_modified(client, admin_headers):
    """An 'added' report for a path already in baseline becomes 'modified'."""
    data = _register(client, admin_headers, code="fim-recl-002")
    path = r"C:\fim\known.txt"
    digest1 = _sha("v1")
    headers = _ingest_headers(data["api_key"])
    assert client.post(
        f"{API}/ingest",
        headers=headers,
        json={"agent_code": data["code"], "event_type": "added", "path": path, "sha256": digest1},
    ).json()["event_type"] == "added"

    digest2 = _sha("v2")
    resp = client.post(
        f"{API}/ingest",
        headers=headers,
        json={"agent_code": data["code"], "event_type": "added", "path": path, "sha256": digest2},
    )
    assert resp.status_code == 200
    assert resp.json()["event_type"] == "modified"


def test_ingest_deleted_keeps_baseline_history(client, admin_headers):
    data = _register(client, admin_headers, code="fim-del-001")
    path = r"C:\fim\doomed.txt"
    digest = _sha("doomed")
    headers = _ingest_headers(data["api_key"])
    client.post(
        f"{API}/ingest",
        headers=headers,
        json={"agent_code": data["code"], "event_type": "added", "path": path, "sha256": digest},
    )
    resp = client.post(
        f"{API}/ingest",
        headers=headers,
        json={"agent_code": data["code"], "event_type": "deleted", "path": path},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["event_type"] == "deleted"
    assert body["accepted"] is True

    files = client.get(f"{API}/files?agent_code=fim-del-001", headers=admin_headers).json()
    assert files[0]["status"] == "deleted", "baseline rows are kept for history"
    events = client.get(f"{API}/events?agent_code=fim-del-001", headers=admin_headers).json()
    assert events["items"][0]["old_sha256"] == digest


def test_ingest_renamed(client, admin_headers):
    data = _register(client, admin_headers, code="fim-ren-001")
    old = r"C:\fim\old-name.txt"
    new = r"C:\fim\new-name.txt"
    digest = _sha("renamed content")
    headers = _ingest_headers(data["api_key"])
    client.post(
        f"{API}/ingest",
        headers=headers,
        json={"agent_code": data["code"], "event_type": "added", "path": old, "sha256": digest},
    )
    resp = client.post(
        f"{API}/ingest",
        headers=headers,
        json={
            "agent_code": data["code"],
            "event_type": "renamed",
            "path": new,
            "old_path": old,
            "sha256": digest,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["event_type"] == "renamed"
    files = client.get(f"{API}/files?agent_code=fim-ren-001", headers=admin_headers).json()
    assert files[0]["file"] == new
    events = client.get(f"{API}/events?agent_code=fim-ren-001", headers=admin_headers).json()
    ev = events["items"][0]
    assert ev["event_type"] == "renamed"
    assert ev["old_path"] == old


def test_ingest_dedupes_by_event_id(client, admin_headers, db):
    from sqlalchemy import func, select

    from app.models.syscheck import SyscheckAgent, SyscheckEvent

    data = _register(client, admin_headers, code="fim-ded-001")
    headers = _ingest_headers(data["api_key"])
    payload = {
        "agent_code": data["code"],
        "event_type": "added",
        "path": r"C:\fim\dedupe.txt",
        "sha256": _sha("once"),
        "event_id": "stable-event-id-1",
    }
    first = client.post(f"{API}/ingest", headers=headers, json=payload)
    assert first.json()["accepted"] is True
    second = client.post(f"{API}/ingest", headers=headers, json=payload)
    assert second.json()["duplicated"] is True
    assert second.json()["accepted"] is False

    count = db.execute(
        select(func.count())
        .select_from(SyscheckEvent)
        .join(SyscheckAgent, SyscheckAgent.id == SyscheckEvent.agent_id)
        .where(SyscheckAgent.code == "fim-ded-001")
    ).scalar()
    assert count == 1


def test_ingest_validates_sha256(client, admin_headers):
    data = _register(client, admin_headers, code="fim-val-001")
    resp = client.post(
        f"{API}/ingest",
        headers=_ingest_headers(data["api_key"]),
        json={
            "agent_code": data["code"],
            "event_type": "added",
            "path": r"C:\fim\bad.txt",
            "sha256": "not-a-real-hash",
        },
    )
    assert resp.status_code == 422


def test_ingest_rejects_empty_and_control_paths(client, admin_headers):
    data = _register(client, admin_headers, code="fim-val-002")
    headers = _ingest_headers(data["api_key"])
    for bad_path in ("", "  ", "C:\\fim\\nul\x00byte"):
        resp = client.post(
            f"{API}/ingest",
            headers=headers,
            json={
                "agent_code": data["code"],
                "event_type": "added",
                "path": bad_path,
                "sha256": _sha("x"),
            },
        )
        assert resp.status_code == 422, bad_path


def test_ingest_rejects_unknown_agent(client, admin_headers):
    resp = client.post(
        f"{API}/ingest",
        headers=_ingest_headers("whatever"),
        json={
            "agent_code": "does-not-exist",
            "event_type": "added",
            "path": r"C:\fim\x.txt",
            "sha256": _sha("x"),
        },
    )
    assert resp.status_code == 404


def test_registration_token(monkeypatch, client):
    from app.core.config import settings

    monkeypatch.setattr(settings, "fim_registration_token", "shared-secret")
    bad = client.post(
        f"{API}/agents/register",
        json={"agent_code": "fim-tok-001", "hostname": "x"},
        headers={"X-Registration-Token": "wrong"},
    )
    assert bad.status_code == 401
    good = client.post(
        f"{API}/agents/register",
        json={"agent_code": "fim-tok-001", "hostname": "x"},
        headers={"X-Registration-Token": "shared-secret"},
    )
    assert good.status_code == 200


def test_api_key_is_stored_hashed(client, admin_headers, db):
    from sqlalchemy import select

    from app.models.syscheck import SyscheckAgent

    data = _register(client, admin_headers, code="fim-hash-001")
    agent = db.execute(
        select(SyscheckAgent).where(SyscheckAgent.code == "fim-hash-001")
    ).scalar_one()
    assert agent.api_key_hash == hashlib.sha256(data["api_key"].encode()).hexdigest()
    assert agent.api_key_hash != data["api_key"]


# --------------------------------------------------------------- demo mode gate
def test_seed_syscheck_skipped_when_demo_off(monkeypatch):
    from sqlalchemy import create_engine, func, select
    from sqlalchemy.orm import sessionmaker

    from app.core.config import settings
    from app.db.base import Base
    from app.models.syscheck import SyscheckAgent, SyscheckEvent, SyscheckFile
    from app.services.endpoint_seed import seed_syscheck

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    monkeypatch.setattr(settings, "fim_demo_mode", False)
    with Session() as s:
        seed_syscheck(s)
        s.commit()
        assert s.execute(select(func.count()).select_from(SyscheckAgent)).scalar() == 0
        assert s.execute(select(func.count()).select_from(SyscheckFile)).scalar() == 0
        assert s.execute(select(func.count()).select_from(SyscheckEvent)).scalar() == 0

    monkeypatch.setattr(settings, "fim_demo_mode", True)
    with Session() as s:
        seed_syscheck(s)
        s.commit()
        assert s.execute(select(func.count()).select_from(SyscheckAgent)).scalar() == 3
        assert s.execute(select(func.count()).select_from(SyscheckFile)).scalar() == 13
        assert s.execute(select(func.count()).select_from(SyscheckEvent)).scalar() == 977


# ------------------------------------------------------------- deterministic rules
def test_fim_rules_deterministic():
    from app.services import fim_rules

    critical = fim_rules.evaluate_rule(r"C:\Windows\System32\drivers\etc\hosts")
    assert critical["severity"] == "critical"
    high = fim_rules.evaluate_rule(r"C:\Windows\System32\some.dll")
    assert high["severity"] == "high"
    medium = fim_rules.evaluate_rule(r"C:\tools\app.exe")
    assert medium["severity"] == "medium"
    low = fim_rules.evaluate_rule(r"C:\FIM-Test\notes.txt")
    assert low["severity"] == "low"
    # deterministic: identical input -> identical output
    assert fim_rules.evaluate_rule(r"C:\tools\app.exe") == medium
