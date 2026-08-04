"""Module 5 - real-time alerting tests."""

import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401  (register ORM models)
from app.core.exceptions import ValidationError as AppValidationError
from app.db.base import Base
from app.pipeline.bus import InMemoryBus, Topics
from app.pipeline.detection import Detection
from app.schemas.alert import AlertUpdate
from app.services.alert_service import AlertService
from app.services.notifications import SEVERITY_RANK


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()


class FakeNotifier:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bool]] = []

    @property
    def enabled(self) -> bool:
        return True

    async def notify(self, alert: dict, *, is_new: bool) -> None:
        self.calls.append((alert["id"], is_new))


def _detection(rule_id: str = "r1", grouping: dict | None = None,
               severity: str = "medium", title: str = "Brute Force") -> Detection:
    return Detection(
        rule_id=rule_id,
        rule_title=title,
        severity=severity,
        description="detected",
        detector="correlation",
        events=[{"event_id": "e1"}],
        grouping=grouping or {"source.ip": "1.1.1.1"},
        mitre=[{"tactic": "Credential Access", "technique": "T1110", "technique_name": "Brute Force"}],
        tags=["auth"],
    )


# ---------------------------------------------------------------------- dedup
def test_dedup_creates_single_alert(db_session):
    service = AlertService(db_session)
    d = _detection()
    alert1, _ = service.ingest_detection(d)
    alert2, _ = service.ingest_detection(d)
    assert alert1.id == alert2.id
    assert alert2.count == 2
    assert alert1.first_seen_at <= alert2.last_seen_at


def test_distinct_groupings_separate_alerts(db_session):
    service = AlertService(db_session)
    a1, _ = service.ingest_detection(_detection(grouping={"source.ip": "1.1.1.1"}))
    a2, _ = service.ingest_detection(_detection(grouping={"source.ip": "2.2.2.2"}))
    assert a1.id != a2.id
    assert a1.count == 1 and a2.count == 1


def test_different_rules_separate_alerts(db_session):
    service = AlertService(db_session)
    a1, _ = service.ingest_detection(_detection(rule_id="r1"))
    a2, _ = service.ingest_detection(_detection(rule_id="r2"))
    assert a1.id != a2.id


# ------------------------------------------------------------------ escalation
def test_escalation_raises_severity(db_session):
    service = AlertService(db_session)
    alert, escalated = service.ingest_detection(_detection(severity="medium"))
    assert alert.severity == "medium" and escalated is False

    for _ in range(2):
        alert, escalated = service.ingest_detection(_detection(severity="medium"))
    assert alert.count == 3
    assert alert.severity == "high"
    assert escalated is True

    for _ in range(5):
        alert, _ = service.ingest_detection(_detection(severity="medium"))
    assert alert.count == 8
    assert alert.severity == "critical"
    assert SEVERITY_RANK[alert.severity] == SEVERITY_RANK["critical"]


# ------------------------------------------------------------------- lifecycle
def test_status_lifecycle_and_summary(db_session):
    service = AlertService(db_session)
    alert, _ = service.ingest_detection(_detection())

    updated = service.update(alert.id, status="acknowledged", assignee="analyst-1")
    assert updated.status == "acknowledged"
    assert updated.assignee == "analyst-1"

    service.update(alert.id, status="resolved", notes="confirmed legit")
    summary = service.summary()
    assert summary["resolved_count"] == 1
    assert summary["acknowledged_count"] == 0
    assert summary["open_count"] == 0


def test_update_rejects_invalid_status(db_session):
    service = AlertService(db_session)
    alert, _ = service.ingest_detection(_detection())
    with pytest.raises(AppValidationError):
        service.update(alert.id, status="banana")


# ------------------------------------------------------------------ reporting
def test_summary_by_severity(db_session):
    service = AlertService(db_session)
    service.ingest_detection(_detection(severity="high"))
    service.ingest_detection(_detection(severity="low", grouping={"source.ip": "3.3.3.3"}))
    summary = service.summary()
    assert summary["open_count"] == 2
    assert summary["total_open"] == 2
    assert summary["by_severity"]["high"] == 1
    assert summary["by_severity"]["low"] == 1


def test_list_filters(db_session):
    service = AlertService(db_session)
    high = service.ingest_detection(_detection(severity="high"))[0]
    service.ingest_detection(_detection(severity="low", grouping={"source.ip": "9.9.9.9"}))
    service.update(high.id, status="resolved")

    open_alerts, total = service.list(status="open")
    assert total == 1
    assert open_alerts[0].severity == "low"

    all_alerts, total = service.list(severity="high")
    assert total == 1
    assert all_alerts[0].status == "resolved"


# ------------------------------------------------------------- async pipeline
def test_process_detection_publishes_and_notifies(db_session):
    async def scenario():
        bus = InMemoryBus()
        notifier = FakeNotifier()
        service = AlertService(db_session, bus=bus, notifiers=[notifier])
        alert = await service.process_detection(_detection())
        assert notifier.calls == [(alert.id, True)]

        # read from alerts topic
        received = []
        async for topic, event, msg_id in bus.subscribe(
            [Topics.ALERTS], "g", "c", block_ms=200
        ):
            received.append(event)
            if len(received) == 1:
                break
        assert received[0]["id"] == alert.id
        assert received[0]["event"] == "alert.new"

    asyncio.run(scenario())


def test_process_detection_escalation_notifies(db_session):
    async def scenario():
        notifier = FakeNotifier()
        service = AlertService(db_session, notifiers=[notifier])
        for _ in range(3):
            await service.process_detection(_detection())
        # 1st = new (notify), 2nd = increment (no notify), 3rd = escalated to
        # high (notify) -> exactly two notifications, second is escalation
        assert len(notifier.calls) == 2
        assert [is_new for _, is_new in notifier.calls] == [True, False]

    asyncio.run(scenario())


# ------------------------------------------------------------------ pydantic
def test_alert_update_schema_validates():
    assert AlertUpdate(status="resolved").status == "resolved"
    try:
        AlertUpdate(status="bogus")
    except ValueError:
        pass
    else:
        raise AssertionError("bogus status must be rejected by pydantic")


# ----------------------------------------------------------------------- API
def _seed_alert() -> str:
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        alert, _ = AlertService(db).ingest_detection(
            _detection(grouping={"source.ip": "198.51.100.7"})
        )
        return alert.id


def test_api_alerts_flow(client, admin_headers):
    alert_id = _seed_alert()

    listing = client.get("/api/v1/alerts", headers=admin_headers)
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] >= 1
    assert any(item["id"] == alert_id for item in body["items"])

    detail = client.get(f"/api/v1/alerts/{alert_id}", headers=admin_headers)
    assert detail.status_code == 200
    assert detail.json()["rule_title"] == "Brute Force"
    assert detail.json()["grouping"]["source.ip"] == "198.51.100.7"

    updated = client.patch(
        f"/api/v1/alerts/{alert_id}",
        headers=admin_headers,
        json={"status": "acknowledged", "assignee": "soc-analyst"},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "acknowledged"

    summary = client.get("/api/v1/alerts/summary", headers=admin_headers)
    assert summary.status_code == 200
    assert summary.json()["acknowledged_count"] >= 1


def test_api_alert_update_rejects_bad_status(client, admin_headers):
    alert_id = _seed_alert()
    resp = client.patch(
        f"/api/v1/alerts/{alert_id}",
        headers=admin_headers,
        json={"status": "nonsense"},
    )
    assert resp.status_code == 422


def test_api_alerts_require_auth(client):
    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 401
