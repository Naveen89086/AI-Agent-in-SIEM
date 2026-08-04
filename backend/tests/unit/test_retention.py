"""Module 11 - retention & storage tests."""

import asyncio
import os
import tempfile
from pathlib import Path

from app.core.config import settings
from app.services.retention_service import RetentionService


def test_retention_status(client, admin_headers):
    resp = client.get("/api/v1/retention/status", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["retention_delete_days"] == settings.retention_delete_days
    assert body["lifecycle_policy"] == "siem-lifecycle"
    assert body["backend"]


def test_retention_requires_auth(client):
    assert client.get("/api/v1/retention/status").status_code == 401


def test_local_cleanup_removes_old_files():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        old = base / "events-2020.01.01.jsonl"
        new = base / "events-2026.07.01.jsonl"
        old.write_text("{}\n")
        new.write_text("{}\n")
        # fake old mtime
        import time

        stamp = time.time() - 400 * 86400
        os.utime(old, (stamp, stamp))

        service = RetentionService.__new__(RetentionService)
        service.store = type("S", (), {"base_dir": tmp})()
        deleted = service._local_cleanup()
        assert deleted == 1
        assert not old.exists()
        assert new.exists()


def test_local_run_report():
    async def scenario():
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["LOG_STORE_URL"] = f"local://{tmp}/events"
            from app.core.config import get_settings

            get_settings.cache_clear()
            service = RetentionService()
            report = await service.run()
            assert report["at"]
            assert "local_cleanup" in report["actions"]
            return report

    report = asyncio.run(scenario())
    assert report["actions"]["local_cleanup"]["files_deleted"] >= 0


def test_es_policy_build_reflects_retention_days():
    from app.services.retention_service import build_lifecycle_policy

    policy = build_lifecycle_policy(180)
    assert policy["policy"]["phases"]["hot"]["actions"]["rollover"] == {"max_age": "1d"}
    assert policy["policy"]["phases"]["delete"]["min_age"] == "180d"
