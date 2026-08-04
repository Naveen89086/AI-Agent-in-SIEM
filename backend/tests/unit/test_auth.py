"""Module 0 - platform foundation tests: health, auth, RBAC, security."""


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_docs_available(client):
    assert client.get("/docs").status_code == 200
    assert client.get("/api/v1/openapi.json").status_code == 200


def test_security_headers(client):
    resp = client.get("/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"


def test_login_success(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "Admin@12345"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["user"]["username"] == "admin"
    assert body["user"]["role"] == "admin"


def test_login_invalid_password(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong-password"},
    )
    assert resp.status_code == 401


def test_me_requires_token(client):
    assert client.get("/api/v1/auth/me").status_code == 401


def test_me_valid_token(client, admin_token):
    resp = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"


def test_users_admin_only(client, admin_headers):
    assert client.get("/api/v1/users").status_code == 401
    resp = client.get("/api/v1/users", headers=admin_headers)
    assert resp.status_code == 200
    assert any(u["username"] == "admin" for u in resp.json()["items"])


def test_create_user_flow(client, admin_headers):
    resp = client.post(
        "/api/v1/users",
        json={
            "username": "socanalyst1",
            "email": "soc1@example.com",
            "password": "StrongPass!123",
            "role": "analyst",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["role"] == "analyst"

    dup = client.post(
        "/api/v1/users",
        json={
            "username": "socanalyst1",
            "email": "other@example.com",
            "password": "StrongPass!123",
            "role": "analyst",
        },
        headers=admin_headers,
    )
    assert dup.status_code == 409
