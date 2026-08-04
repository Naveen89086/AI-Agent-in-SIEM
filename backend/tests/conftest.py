"""Shared pytest fixtures.

The application is configured for a temp SQLite database and the
in-memory event bus / local log store so tests need no external services.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="siem_test_")

os.environ["APP_ENV"] = "test"
os.environ["DEBUG"] = "false"
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP}/test.db"
os.environ["EVENT_BUS_URL"] = "inmemory://"
os.environ["LOG_STORE_URL"] = f"local://{_TMP}/events"
os.environ["SECRET_KEY"] = "test-secret-key-0123456789abcdefghijklmnopqrstuvwxyz"
os.environ["AI_PROVIDER"] = "heuristic"
os.environ["FIRST_ADMIN_USERNAME"] = "admin"
os.environ["FIRST_ADMIN_PASSWORD"] = "Admin@12345"
os.environ["FIRST_ADMIN_EMAIL"] = "admin@example.com"
os.environ["ML_MODEL_DIR"] = f"{_TMP}/ml"
os.environ["YARA_RULES_DIR"] = f"{_TMP}/yara"
os.environ["YARA_ENABLED"] = "false"
os.environ["SOAR_PLAYBOOKS_DIR"] = f"{_TMP}/playbooks"

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_token(client) -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "Admin@12345"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture(scope="session")
def admin_headers(admin_token) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture()
def db(client):
    from app.db.session import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
