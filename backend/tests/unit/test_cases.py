"""Module 9 - investigation & forensics tests."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.db.base import Base
from app.pipeline.detection import Detection
from app.schemas.case import CaseArtifactCreate, CaseCreate, CaseNoteCreate, CaseUpdate
from app.services.alert_service import AlertService
from app.services.case_service import CaseService


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()


def _detection(rule_id: str = "r1") -> Detection:
    return Detection(
        rule_id=rule_id,
        rule_title="SSH Brute Force",
        severity="high",
        description="brute force",
        detector="correlation",
        events=[{"event_id": "e1"}],
        grouping={"source.ip": "203.0.113.5"},
    )


def _seed_alert(db) -> str:
    alert, _ = AlertService(db).ingest_detection(_detection())
    return alert.id


def _create_case(db, alert_id: str | None = None) -> str:
    case = CaseService(db).create(
        CaseCreate(
            title="Suspicious SSH activity",
            description="Investigate brute force",
            severity="high",
            alert_ids=[alert_id] if alert_id else [],
        )
    )
    return case.id


# -------------------------------------------------------------------- CRUD
def test_case_crud_and_timeline(db_session):
    service = CaseService(db_session)
    alert_id = _seed_alert(db_session)
    case_id = _create_case(db_session, alert_id)

    case = service.get(case_id)
    assert case.status == "open"
    assert case.severity == "high"
    assert case.title == "Suspicious SSH activity"

    service.add_note(case_id, CaseNoteCreate(content="correlated with endpoint logs"))
    service.add_artifact(
        case_id,
        CaseArtifactCreate(artifact_type="ip", value="203.0.113.5", source="alert"),
    )

    timeline = service.timeline(case_id)
    types = [entry["type"] for entry in timeline]
    assert "case_opened" in types
    assert "note" in types
    assert "artifact" in types
    assert "alert" in types
    # chronological order
    times = [entry["at"] for entry in timeline]
    assert times == sorted(times)


def test_case_update_status_closes_case(db_session):
    service = CaseService(db_session)
    case_id = _create_case(db_session)
    case = service.update(case_id, CaseUpdate(status="closed"))
    assert case.status == "closed"
    assert case.closed_at is not None
    notes = service.list_notes(case_id)
    assert any("Updated: status" in n.content for n in notes)


def test_case_summary(db_session):
    service = CaseService(db_session)
    _create_case(db_session)
    _create_case(db_session)
    summary = service.summary()
    assert summary["open_count"] == 2
    assert summary["total_open"] == 2


def test_case_list_filters(db_session):
    service = CaseService(db_session)
    first = _create_case(db_session)
    service.update(first, CaseUpdate(severity="low"))
    rows, total = service.list_cases(severity="low")
    assert total == 1
    assert rows[0].severity == "low"


# ---------------------------------------------------------------------- API
def _seed_event(message: str, source_name: str = "auth") -> None:
    import asyncio
    from datetime import datetime, timezone

    from app.storage.base import build_log_store

    store = build_log_store()
    asyncio.run(
        store.index_event(
            {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "message": message,
                "source": {"name": source_name},
                "event": {"kind": "event"},
            }
        )
    )


def test_api_cases_flow(client, admin_headers):
    resp = client.post(
        "/api/v1/cases",
        headers=admin_headers,
        json={"title": "Phishing campaign", "severity": "critical", "tags": ["phish"]},
    )
    assert resp.status_code == 201, resp.text
    case_id = resp.json()["id"]
    assert resp.json()["tags"] == ["phish"]

    listed = client.get("/api/v1/cases?severity=critical", headers=admin_headers)
    assert listed.status_code == 200
    assert any(c["id"] == case_id for c in listed.json()["items"])

    patched = client.patch(
        f"/api/v1/cases/{case_id}",
        headers=admin_headers,
        json={"status": "in_progress", "assignee": "analyst-1"},
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "in_progress"

    note = client.post(
        f"/api/v1/cases/{case_id}/notes",
        headers=admin_headers,
        json={"content": "sent to forensics"},
    )
    assert note.status_code == 201

    artifact = client.post(
        f"/api/v1/cases/{case_id}/artifacts",
        headers=admin_headers,
        json={"artifact_type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e"},
    )
    assert artifact.status_code == 201

    timeline = client.get(f"/api/v1/cases/{case_id}/timeline", headers=admin_headers)
    assert timeline.status_code == 200
    assert len(timeline.json()) >= 4

    summary = client.get("/api/v1/cases/summary", headers=admin_headers)
    assert summary.json()["in_progress_count"] >= 1


def test_api_case_bad_severity_rejected(client, admin_headers):
    resp = client.post(
        "/api/v1/cases", headers=admin_headers, json={"title": "x", "severity": "banana"}
    )
    assert resp.status_code == 422


def test_api_cases_require_auth(client):
    assert client.get("/api/v1/cases").status_code == 401


# ------------------------------------------------------------------- search
def test_api_search_requires_auth(client):
    assert client.get("/api/v1/search").status_code == 401


def test_api_search_flow(client, admin_headers):
    _seed_event("failed password for user root from 198.51.100.7")
    resp = client.get("/api/v1/search?q=root", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert any("root" in (item.get("message") or "") for item in body["items"])


def test_api_search_aggregate(client, admin_headers):
    _seed_event("port scan detected 10.0.0.1", source_name="fw")
    _seed_event("port scan detected 10.0.0.2", source_name="fw")
    resp = client.get("/api/v1/search/aggregate?field=source.name", headers=admin_headers)
    assert resp.status_code == 200
    assert any(b["key"] == "fw" and b["count"] >= 1 for b in resp.json()["buckets"])


def test_api_search_histogram(client, admin_headers):
    _seed_event("hello world", source_name="app")
    resp = client.get("/api/v1/search/histogram?interval_seconds=3600", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["interval_seconds"] == 3600
    assert resp.json()["buckets"]
