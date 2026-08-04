"""M8 backend support - dashboard and rules endpoint tests."""

import asyncio
from datetime import datetime, timedelta, timezone

from app.services.dashboard_service import DashboardService
from app.storage.base import SearchQuery, build_log_store


def test_dashboard_summary(client, admin_headers):
    resp = client.get("/api/v1/dashboard/summary", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    for key in (
        "events_total",
        "events_last_24h",
        "alerts_open",
        "alerts_by_severity",
        "cases_open",
        "sources_total",
    ):
        assert key in body
    assert set(body["alerts_by_severity"]) >= {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    }


def test_dashboard_timeseries(client, admin_headers):
    resp = client.get("/api/v1/dashboard/timeseries?hours=24&bucket_minutes=60", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["interval_seconds"] == 3600
    assert isinstance(body["points"], list)


def test_dashboard_top_rules_and_sources(client, admin_headers):
    rules = client.get("/api/v1/dashboard/top-rules", headers=admin_headers)
    assert rules.status_code == 200
    sources = client.get("/api/v1/dashboard/top-sources", headers=admin_headers)
    assert sources.status_code == 200
    assert isinstance(rules.json(), list)
    assert isinstance(sources.json(), list)


def test_dashboard_recent_alerts(client, admin_headers):
    resp = client.get("/api/v1/dashboard/recent-alerts?limit=5", headers=admin_headers)
    assert resp.status_code == 200
    for alert in resp.json():
        assert alert["rule_title"]
        assert alert["severity"]


def test_rules_listing(client, admin_headers):
    resp = client.get("/api/v1/rules", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert body["counts"]["correlation"] >= 1
    first = body["items"][0]
    for key in ("id", "title", "severity", "status", "condition", "mitre"):
        assert key in first


def test_rules_filter_by_severity(client, admin_headers):
    resp = client.get("/api/v1/rules?severity=critical", headers=admin_headers)
    assert resp.status_code == 200
    assert all(r["severity"] == "critical" for r in resp.json()["items"])


def test_dashboard_service_summary_shape(client, db):
    data = DashboardService(db).summary()
    assert data["alerts_by_severity"]["critical"] >= 0
    assert data["generated_at"]


def test_dashboard_requires_auth(client):
    assert client.get("/api/v1/dashboard/summary").status_code == 401


def test_store_histogram_bucket_keys_are_real_timestamps():
    """Histogram bucket keys must be aligned to the event timestamps, not 1970."""

    now = datetime.now(timezone.utc)

    async def _run():
        store = build_log_store()
        await store.index_event(
            {
                "@timestamp": (now - timedelta(hours=3)).isoformat(),
                "message": "histogram key regression",
                "source_type": "test",
            }
        )
        since = now - timedelta(hours=6)
        buckets = await store.histogram(
            3600, query=SearchQuery(time_from=since, time_to=now + timedelta(hours=1))
        )
        return buckets

    buckets = asyncio.run(_run())
    assert buckets
    for b in buckets:
        key_ts = datetime.fromisoformat(b.key)
        assert key_ts.year >= now.year, f"bucket key not a real timestamp: {b.key}"
        assert abs((key_ts - now).total_seconds()) < 6 * 3600
