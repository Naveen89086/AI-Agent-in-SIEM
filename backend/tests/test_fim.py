"""Tests for the File Integrity Monitoring and Configuration Assessment APIs."""


def test_fim_agents(client, admin_headers):
    resp = client.get("/api/v1/fim/agents", headers=admin_headers)
    assert resp.status_code == 200
    agents = resp.json()
    assert any(a["code"] == "001" for a in agents)


def test_fim_summary(client, admin_headers):
    resp = client.get("/api/v1/fim/summary", headers=admin_headers)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["users"], "expected user breakdown"
    assert payload["actions"], "expected action breakdown"
    assert payload["files"]["added"] and payload["files"]["deleted"], "expected path breakdowns"


def test_fim_timeline(client, admin_headers):
    resp = client.get(
        "/api/v1/fim/timeline?hours=24&bucket_minutes=30", headers=admin_headers
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["interval_minutes"] == 30
    assert len(payload["points"]) == 48
    assert {"deleted", "added", "modified"} <= set(payload["points"][0].keys())


def test_fim_files(client, admin_headers):
    resp = client.get("/api/v1/fim/files", headers=admin_headers)
    assert resp.status_code == 200
    files = resp.json()
    assert len(files) == 13
    assert any(f["file"].endswith("hosts") for f in files)
    assert "last_modified" in files[0] and "user_id" in files[0]


def test_fim_events_pagination(client, admin_headers):
    resp = client.get("/api/v1/fim/events?page=1&per_page=15", headers=admin_headers)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] == 977
    assert payload["totalPages"] == 66
    assert len(payload["items"]) == 15
    # newest-first ordering
    times = [item["timestamp"] for item in payload["items"]]
    assert times == sorted(times, reverse=True)


def test_fim_events_search(client, admin_headers):
    resp = client.get("/api/v1/fim/events?search=597", headers=admin_headers)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] < 977
    assert all(item["rule_id"] == 597 for item in payload["items"])


def test_policies(client, admin_headers):
    resp = client.get("/api/v1/policies", headers=admin_headers)
    assert resp.status_code == 200
    policies = resp.json()
    assert any(p["slug"] == "cis-win11" for p in policies)


def test_policy_summary(client, admin_headers):
    policies = client.get("/api/v1/policies", headers=admin_headers).json()
    target = next(p for p in policies if p["slug"] == "cis-win11")
    resp = client.get(f"/api/v1/policies/{target['id']}/summary", headers=admin_headers)
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["total_checks"] == 481
    assert summary["passed"] + summary["failed"] + summary["not_applicable"] == 481


def test_policy_checks_pagination(client, admin_headers):
    policies = client.get("/api/v1/policies", headers=admin_headers).json()
    target = next(p for p in policies if p["slug"] == "cis-win11")
    resp = client.get(f"/api/v1/policies/{target['id']}/checks?page=1&per_page=10", headers=admin_headers)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["total"] == 481
    assert len(payload["items"]) == 10
    assert payload["items"][0]["id"] == 26000
    assert payload["items"][0]["result"] in {"passed", "failed", "not_applicable"}


def test_endpoints_require_auth(client):
    assert client.get("/api/v1/fim/summary").status_code == 401
    assert client.get("/api/v1/policies").status_code == 401
