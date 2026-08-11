"""Threat Hunting - definitions, execution against the log store, AI analysis.

Hunt definitions ship in ``data/hunts/*.yml``. Running a hunt searches the
configured log store and persists matched events as ``HuntResult`` rows. The
analysis endpoint drives the configured AI provider with a graceful fallback
to the deterministic heuristic provider.
"""

import pytest
from sqlalchemy import func, select

from app.models.hunting import HuntQuery, HuntResult
from app.services.threat_hunting_service import ThreatHuntingService


def test_definitions_load_from_disk():
    svc = ThreatHuntingService.__new__(ThreatHuntingService)
    definitions = ThreatHuntingService.definitions(svc)
    assert len(definitions) >= 5
    ids = {d["id"] for d in definitions}
    assert ids >= {"ssh-brute-force", "powershell-abuse", "new-account-creation"}
    for d in definitions:
        assert d["name"]
        assert d["mitre"]


def test_definition_detail(client, admin_headers):
    resp = client.get("/api/v1/hunting/definitions/ssh-brute-force", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "ssh-brute-force"
    assert body["mitre"]
    assert client.get(
        "/api/v1/hunting/definitions/does-not-exist", headers=admin_headers
    ).status_code == 404


def test_run_hunt_persists_query_and_results(db):
    svc = ThreatHuntingService(db)
    import asyncio

    record = asyncio.run(svc.run_hunt(hunt_id="ssh-brute-force", created_by="analyst"))
    assert record["status"] == "completed"
    assert record["hunt_id"] == "ssh-brute-force"
    row = db.get(HuntQuery, record["id"])
    assert row is not None
    assert row.created_by == "analyst"
    assert row.matched_events >= 0


def test_run_hunt_unknown_definition_fails(db):
    svc = ThreatHuntingService(db)
    import asyncio

    with pytest.raises(Exception):
        asyncio.run(svc.run_hunt(hunt_id="does-not-exist"))


def test_query_list_and_detail(client, admin_headers, db):
    svc = ThreatHuntingService(db)
    import asyncio

    asyncio.run(svc.run_hunt(hunt_id="powershell-abuse", created_by="analyst"))
    resp = client.get("/api/v1/hunting/queries", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1
    qid = resp.json()["items"][0]["id"]
    detail = client.get(f"/api/v1/hunting/queries/{qid}", headers=admin_headers)
    assert detail.status_code == 200
    results = client.get(f"/api/v1/hunting/queries/{qid}/results", headers=admin_headers)
    assert results.status_code == 200


def test_analyze_completed_hunt_uses_provider(client, admin_headers, db):
    svc = ThreatHuntingService(db)
    import asyncio

    record = asyncio.run(svc.run_hunt(hunt_id="ssh-brute-force", created_by="analyst"))
    resp = client.post(f"/api/v1/hunting/queries/{record['id']}/analyze", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["kind"] == "hunt_analysis"
    assert body["provider"] in ("heuristic", "llm")
    assert body["analysis"]
    assert body["summary"]
    assert "risk_score" in body


def test_analyze_requires_completed_hunt(client, admin_headers):
    resp = client.post("/api/v1/hunting/queries/not-a-real-id/analyze", headers=admin_headers)
    assert resp.status_code in (404, 422)


def test_analyze_fallback_to_heuristic(db, monkeypatch):
    """If the AI provider raises, the heuristic provider still produces output."""
    import asyncio

    from app.agents.heuristic import HeuristicProvider

    svc = ThreatHuntingService(db)
    record = asyncio.run(svc.run_hunt(hunt_id="ssh-brute-force", created_by="analyst"))

    class BrokenProvider:
        provider_name = "broken"

        async def analyze_hunt(self, context):
            raise RuntimeError("provider unavailable")

    monkeypatch.setattr("app.agents.build_provider", lambda: BrokenProvider())
    out = asyncio.run(svc.analyze(record["id"]))
    assert out["provider"] == "heuristic"
    assert out["analysis"]
    assert out["risk_score"] >= 0


def test_hunting_endpoints_require_auth(client):
    assert client.get("/api/v1/hunting/definitions").status_code in (401, 403)
    assert client.get("/api/v1/hunting/queries").status_code in (401, 403)
