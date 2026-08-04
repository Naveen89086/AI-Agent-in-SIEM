"""Module 6 - AI agent tests."""

import asyncio
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401  (register ORM models)
from app.agents.heuristic import HeuristicProvider
from app.db.base import Base
from app.pipeline.detection import Detection
from app.schemas.ai import AgentResponseOut, AnalysisRead, AnalyzeAlertRequest
from app.services.agent_service import AgentService
from app.services.alert_service import AlertService


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()


def _detection(severity: str = "high", technique: str = "T1110", grouping: dict | None = None) -> Detection:
    return Detection(
        rule_id="r1",
        rule_title="SSH Brute Force",
        severity=severity,
        description="many failed logins",
        detector="correlation",
        events=[{"event_id": "e1"}],
        grouping=grouping or {"source.ip": "198.51.100.9"},
        mitre=[{"tactic": "Credential Access", "technique": technique, "technique_name": "Brute Force"}],
        tags=["auth"],
    )


def _seed_alert(db, severity: str = "high") -> str:
    alert, _ = AlertService(db).ingest_detection(_detection(severity=severity))
    return alert.id


# --------------------------------------------------------------- heuristic unit
@pytest.mark.asyncio
async def test_heuristic_analyze_alert():
    alert = {
        "rule_title": "SSH Brute Force",
        "severity": "high",
        "detector": "correlation",
        "count": 3,
        "mitre": [{"tactic": "Credential Access", "technique": "T1110", "technique_name": "Brute Force"}],
        "grouping": {"source.ip": "198.51.100.9"},
    }
    response = await HeuristicProvider().analyze_alert(alert)
    assert response.provider == "heuristic"
    assert "SSH Brute Force" in response.analysis
    assert any(m["technique"] == "T1110" for m in response.mitre)
    assert response.risk_score > 0
    assert response.recommended_actions
    assert "MITRE" in response.analysis


@pytest.mark.asyncio
async def test_heuristic_severity_raises_risk():
    low = await HeuristicProvider().analyze_alert({"rule_title": "r", "severity": "low", "count": 1})
    critical = await HeuristicProvider().analyze_alert({"rule_title": "r", "severity": "critical", "count": 1})
    assert critical.risk_score > low.risk_score


@pytest.mark.asyncio
async def test_heuristic_summarize_incident():
    alerts = [
        {"rule_title": "A", "severity": "high", "count": 2, "mitre": [], "grouping": {"source.ip": "1.1.1.1"}},
        {"rule_title": "B", "severity": "medium", "count": 1, "mitre": [], "grouping": {"source.ip": "2.2.2.2"}},
    ]
    response = await HeuristicProvider().summarize_incident(alerts, context="test incident")
    assert "2 distinct alert(s)" in response.analysis
    assert "1.1.1.1" in response.analysis
    assert "test incident" in response.analysis
    assert response.risk_score == 7.5


@pytest.mark.asyncio
async def test_heuristic_chat():
    provider = HeuristicProvider()
    answer = await provider.chat("what should I do about ransomware?")
    assert isinstance(answer, str) and len(answer) > 0
    explain = await provider.chat("explain", context={"alert": {"rule_title": "X", "severity": "medium"}})
    assert "X" in explain


# ---------------------------------------------------------------- service layer
@pytest.mark.asyncio
async def test_service_analyze_alert_persists(db_session):
    alert_id = _seed_alert(db_session)
    service = AgentService(db_session)
    response, record = await service.analyze_alert(alert_id)
    assert response.provider == "heuristic"
    assert record.kind == "alert_analysis"
    assert record.alert_id == alert_id
    assert record.analysis and record.summary
    assert json.loads(record.mitre or "[]")


@pytest.mark.asyncio
async def test_service_summarize_incident(db_session):
    first = _seed_alert(db_session, severity="medium")
    second = _seed_alert(db_session, severity="high")
    service = AgentService(db_session)
    response, record = await service.summarize_incident([first, second], "network breach")
    assert record.kind == "incident_summary"
    assert "2 distinct alert(s)" in response.analysis
    assert record.alert_id == first


def test_service_missing_alert_raises(db_session):
    service = AgentService(db_session)
    with pytest.raises(Exception):
        asyncio.run(service.analyze_alert("does-not-exist"))


def test_service_list_analyses(db_session):
    alert_id = _seed_alert(db_session)
    service = AgentService(db_session)
    asyncio.run(service.analyze_alert(alert_id))
    asyncio.run(service.chat("hello", alert_id=alert_id))
    rows = service.list_analyses(alert_id=alert_id)
    assert len(rows) == 2
    kinds = {row.kind for row in rows}
    assert kinds == {"alert_analysis", "chat"}


# ----------------------------------------------------------------- pydantic
def test_analyze_request_schema():
    assert AnalyzeAlertRequest(alert_id="abc").alert_id == "abc"


def test_analysis_read_schema_decodes_json():
    data = {
        "id": "1",
        "kind": "alert_analysis",
        "alert_id": None,
        "provider": "heuristic",
        "analysis": "a",
        "summary": "s",
        "mitre": '[{"tactic": "Credential Access", "technique": "T1110", "technique_name": "Brute Force"}]',
        "recommended_actions": '["do x"]',
        "risk_score": 5.0,
        "confidence": 0.8,
        "created_at": "2026-08-01T00:00:00",
    }
    parsed = AnalysisRead.model_validate(data)
    assert isinstance(parsed.mitre, list)
    assert parsed.mitre[0]["technique"] == "T1110"
    assert parsed.recommended_actions == ["do x"]


# ----------------------------------------------------------------- API flow
def _api_seed_alert() -> str:
    import uuid

    from app.db.session import SessionLocal

    with SessionLocal() as db:
        alert, _ = AlertService(db).ingest_detection(
            _detection(grouping={"source.ip": f"10.0.0.{uuid.uuid4().int % 100000}"})
        )
        return alert.id


def test_api_analyze_alert(client, admin_headers):
    alert_id = _api_seed_alert()
    resp = client.post(
        "/api/v1/ai/analyze-alert",
        headers=admin_headers,
        json={"alert_id": alert_id},
    )
    assert resp.status_code == 200
    body = AgentResponseOut(**resp.json())
    assert body.provider == "heuristic"
    assert body.analysis
    assert body.risk_score > 0


def test_api_summarize_incident(client, admin_headers):
    first = _api_seed_alert()
    second = _api_seed_alert()
    resp = client.post(
        "/api/v1/ai/summarize-incident",
        headers=admin_headers,
        json={"alert_ids": [first, second], "context": "weekend incident"},
    )
    assert resp.status_code == 200
    assert "2 distinct alert(s)" in resp.json()["analysis"]


def test_api_chat(client, admin_headers):
    resp = client.post("/api/v1/ai/chat", headers=admin_headers, json={"message": "help"})
    assert resp.status_code == 200
    assert resp.json()["reply"]


def test_api_list_analyses(client, admin_headers):
    alert_id = _api_seed_alert()
    client.post("/api/v1/ai/analyze-alert", headers=admin_headers, json={"alert_id": alert_id})
    resp = client.get(f"/api/v1/ai/analyses?alert_id={alert_id}", headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["kind"] == "alert_analysis"


def test_api_ai_requires_auth(client):
    assert client.get("/api/v1/ai/analyses").status_code == 401


def test_api_analyze_missing_alert_404(client, admin_headers):
    resp = client.post(
        "/api/v1/ai/analyze-alert", headers=admin_headers, json={"alert_id": "missing"}
    )
    assert resp.status_code == 404
