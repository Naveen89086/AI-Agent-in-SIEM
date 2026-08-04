"""Module 7 - REST API consolidation tests."""

import pytest

from app.api.responses import paginate


def test_paginate_envelope():
    payload = paginate([1, 2, 3], total=10, offset=5, limit=3)
    assert payload == {"items": [1, 2, 3], "total": 10, "offset": 5, "limit": 3}


def test_meta_endpoint(client, admin_headers):
    resp = client.get("/api/v1/meta", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == "1.0.0"
    ids = {c["id"] for c in body["capabilities"]}
    assert "log_collection" in ids
    assert "ai_agent" in ids
    assert "/api/v1/cases" in body["routers"]


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "database" in body["components"]
    assert body["components"]["database"]["status"] == "ok"


def test_request_id_header_present(client):
    resp = client.get("/api/v1/meta", headers={"Authorization": "Bearer x"})
    assert resp.headers.get("x-request-id")


def test_error_envelope_consistent(client, admin_headers):
    resp = client.patch("/api/v1/alerts/does-not-exist", headers=admin_headers, json={})
    assert resp.status_code in (404, 422)
    body = resp.json()
    assert "error" in body


def test_production_refuses_default_secret_key():
    """M13 hardening: production must refuse the default secret key."""
    from app.core.config import Settings
    from app.main import verify_startup_config

    with pytest.raises(RuntimeError):
        verify_startup_config(
            Settings(app_env="production", secret_key="change-me-to-a-long-random-string")
        )


def test_production_boots_with_custom_secret_key():
    """A production config with a real secret key must pass the check."""
    from app.core.config import Settings
    from app.main import verify_startup_config

    verify_startup_config(
        Settings(
            app_env="production",
            secret_key="a-very-long-random-production-secret-0123456789abcdef",
        )
    )


def test_dev_allows_default_secret_key():
    """Non-production environments may keep the default key."""
    from app.core.config import Settings
    from app.main import verify_startup_config

    verify_startup_config(Settings(app_env="development", secret_key="change-me-to-a-long-random-string"))


def test_users_paginated(client, admin_headers):
    resp = client.get("/api/v1/users?limit=1", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["limit"] == 1
    assert body["total"] >= 1
    assert len(body["items"]) == 1


def test_sources_paginated(client, admin_headers):
    resp = client.get("/api/v1/sources", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"items", "total", "offset", "limit"}
