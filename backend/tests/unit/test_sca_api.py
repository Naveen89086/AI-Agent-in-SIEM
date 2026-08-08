"""SCA - API auth, validation, AI analysis and remediation workflow tests."""

from sqlalchemy import select

from app.models.sca import Agent, CheckResult
from app.schemas.user import UserCreate
from app.services.auth_service import AuthService


def _make_user(client, db, username: str, role: str) -> str:
    AuthService(db).create_user(
        UserCreate(username=username, email=f"{username}@example.com", password="Passw0rd!", role=role)
    )
    db.commit()
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "Passw0rd!"},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _agent(db) -> Agent:
    return db.execute(select(Agent).where(Agent.agent_code == "001")).scalar_one()


def _failed_result(db) -> CheckResult:
    return db.execute(
        select(CheckResult).where(CheckResult.result == "failed").limit(1)
    ).scalar_one()


# ---------------------------------------------------------------------- auth
def test_sca_endpoints_require_auth(client):
    assert client.get("/api/v1/sca/dashboard").status_code == 401
    assert client.get("/api/v1/sca/agents").status_code == 401
    assert client.get("/api/v1/sca/scans").status_code == 401
    assert client.get("/api/v1/sca/events").status_code == 401
    assert client.get("/api/v1/sca/drifts").status_code == 401


def test_analyst_can_read_sca(client, db):
    token = _make_user(client, db, "sca_analyst", "analyst")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/sca/dashboard", headers=headers).status_code == 200
    assert client.get("/api/v1/sca/agents", headers=headers).status_code == 200
    assert client.get("/api/v1/sca/scans", headers=headers).status_code == 200


def test_viewer_cannot_access_sca(client, db):
    token = _make_user(client, db, "sca_viewer", "viewer")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/sca/dashboard", headers=headers).status_code == 403
    assert client.get("/api/v1/sca/agents", headers=headers).status_code == 403


# ------------------------------------------------------- agent transport auth
def test_register_requires_valid_token(client, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "sca_registration_token", "shared-secret")
    resp = client.post(
        "/api/v1/sca/agents/register",
        json={"agent_code": "rogue", "hostname": "h"},
        headers={"X-Registration-Token": "wrong-token"},
    )
    assert resp.status_code == 401

    ok = client.post(
        "/api/v1/sca/agents/register",
        json={"agent_code": "rogue", "hostname": "h"},
        headers={"X-Registration-Token": "shared-secret"},
    )
    assert ok.status_code == 200
    assert ok.json()["api_key"]


def test_register_validation_and_conflict(client, admin_headers):
    resp = client.post(
        "/api/v1/sca/agents/register",
        json={"hostname": "no-code"},
        headers=admin_headers,
    )
    assert resp.status_code == 422

    ok = client.post(
        "/api/v1/sca/agents/register",
        json={"agent_code": "api-test-agent", "hostname": "tester"},
        headers=admin_headers,
    )
    assert ok.status_code == 200
    assert ok.json()["api_key"]

    dup = client.post(
        "/api/v1/sca/agents/register",
        json={"agent_code": "api-test-agent", "hostname": "tester"},
        headers=admin_headers,
    )
    assert dup.status_code == 409


def test_heartbeat_requires_valid_api_key(client, db):
    agent = _agent(db)
    resp = client.post(
        f"/api/v1/sca/agents/{agent.agent_code}/heartbeat",
        json={"status": "online"},
        headers={"X-API-Key": "bogus-key"},
    )
    assert resp.status_code == 401


def test_heartbeat_unknown_agent(client):
    resp = client.post(
        "/api/v1/sca/agents/unknown-agent/heartbeat",
        json={"status": "online"},
        headers={"X-API-Key": "bogus-key"},
    )
    assert resp.status_code == 401


# --------------------------------------------------------------------- scans
def test_create_scan_validation(client, admin_headers):
    resp = client.post("/api/v1/sca/scans", json={}, headers=admin_headers)
    assert resp.status_code == 422


def test_create_scan_unknown_policy(client, admin_headers, db):
    agent = _agent(db)
    resp = client.post(
        "/api/v1/sca/scans",
        json={"policy_id": "does-not-exist", "agent_id": agent.id},
        headers=admin_headers,
    )
    assert resp.status_code == 404


def test_scan_lifecycle_via_api(client, admin_headers, db):
    agent = _agent(db)
    policies = client.get("/api/v1/policies", headers=admin_headers).json()
    policy_id = policies[0]["id"]

    created = client.post(
        "/api/v1/sca/scans",
        json={"policy_id": policy_id, "agent_id": agent.id},
        headers=admin_headers,
    )
    assert created.status_code == 200, created.text
    scan_id = created.json()["id"]
    assert created.json()["status"] == "queued"

    detail = client.get(f"/api/v1/sca/scans/{scan_id}", headers=admin_headers)
    assert detail.status_code == 200

    results = client.get(
        f"/api/v1/sca/scans/{scan_id}/results",
        headers=admin_headers,
        params={"result": "failed", "search": "audit"},
    )
    assert results.status_code == 200
    assert results.json()["total"] >= 0


# --------------------------------------------------------- AI analysis flows
def test_analyze_check_not_found(client, admin_headers):
    assert (
        client.post(
            "/api/v1/sca/checks/does-not-exist/analysis", headers=admin_headers
        ).status_code
        == 404
    )


def test_analyze_check_idempotent_and_force(client, admin_headers, db):
    result = _failed_result(db)

    first = client.post(
        f"/api/v1/sca/checks/{result.id}/analysis", headers=admin_headers
    )
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["kind"] == "sca_check_analysis"
    assert body["provider"] in ("heuristic", "llm")

    second = client.post(
        f"/api/v1/sca/checks/{result.id}/analysis", headers=admin_headers
    )
    assert second.json()["id"] == body["id"]

    forced = client.post(
        f"/api/v1/sca/checks/{result.id}/analysis?force=true", headers=admin_headers
    )
    assert forced.json()["id"] != body["id"]


# -------------------------------------------------------------- remediation
def test_remediation_workflow(client, admin_headers, db):
    result = _failed_result(db)

    requested = client.post(
        "/api/v1/sca/remediation",
        json={"check_result_id": result.id, "description": "Apply benchmark setting"},
        headers=admin_headers,
    )
    assert requested.status_code == 200, requested.text
    assert requested.json()["status"] == "pending"
    remediation_id = requested.json()["id"]

    # analyst cannot approve
    analyst_token = _make_user(client, db, "sca_remed_analyst", "analyst")
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    denied = client.post(
        f"/api/v1/sca/remediation/{remediation_id}/approve", headers=analyst_headers
    )
    assert denied.status_code == 403

    approved = client.post(
        f"/api/v1/sca/remediation/{remediation_id}/approve", headers=admin_headers
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    executed = client.post(
        f"/api/v1/sca/remediation/{remediation_id}/execute", headers=admin_headers
    )
    assert executed.status_code == 200
    assert executed.json()["status"] in ("completed", "executing")

    listing = client.get(
        "/api/v1/sca/remediation",
        params={"status": "completed"},
        headers=admin_headers,
    )
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1


def test_remediation_requires_check_result(client, admin_headers):
    resp = client.post(
        "/api/v1/sca/remediation",
        json={"check_result_id": "missing", "description": "x"},
        headers=admin_headers,
    )
    assert resp.status_code == 404


def test_approve_remediation_requires_pending(client, admin_headers, db):
    result = _failed_result(db)
    requested = client.post(
        "/api/v1/sca/remediation",
        json={"check_result_id": result.id, "description": "second"},
        headers=admin_headers,
    ).json()
    rid = requested["id"]
    client.post(f"/api/v1/sca/remediation/{rid}/approve", headers=admin_headers)
    again = client.post(
        f"/api/v1/sca/remediation/{rid}/approve", headers=admin_headers
    )
    assert again.status_code == 409
