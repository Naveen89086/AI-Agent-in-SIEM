"""Threat Intelligence (IOC) - offline lookup honesty and agent ingest tests.

The server is the final authority: agents submit observations, the service
computes every verdict deterministically, demo rows are labeled ``demo`` and
real agent rows ``real_endpoint``. Unknown is the default verdict - never
fabricated.
"""

from sqlalchemy import func, select

from app.models.ioc import IocAgent, IocIndicator, IocMatch, IocObservation
from app.services.ioc_data import canonical_value, lookup_offline
from app.services.ioc_service import IocService

# Real indicators present in the bundled offline corpus (data/ioc/iocs.yaml).
MALICIOUS_IP = "45.83.193.105"
MALICIOUS_DOMAIN = "freemathhelp.ga"
PRIVATE_TEST_IP = "203.0.113.99"


# ------------------------------------------------------------------ offline data
def test_offline_lookup_returns_malicious_for_known_indicator():
    result = lookup_offline("ipv4", MALICIOUS_IP)
    assert result is not None
    assert result.verdict == "malicious"
    assert result.source  # real threat-intel source name
    assert result.confidence > 0.0


def test_offline_lookup_unknown_for_unlisted_value():
    result = lookup_offline("ipv4", "8.8.8.8")
    assert result is None


def test_offline_lookup_unknown_for_private_test_ip():
    result = lookup_offline("ipv4", PRIVATE_TEST_IP)
    assert result is None


def test_canonical_value_normalizes_forms():
    assert canonical_value("ipv4", " 203.0.113.99 ") == "203.0.113.99"
    assert canonical_value("domain", "Freemathhelp.GA") == "freemathhelp.ga"


def test_offline_indicators_load_non_empty():
    from app.services.ioc_data import offline_indicators

    entries = offline_indicators()
    assert len(entries) >= 5
    types = {e["indicator_type"] for e in entries}
    assert types.issubset({"ipv4", "ipv6", "domain", "url", "filehash", "email", "registry"})
    for e in entries:
        assert e["value"]
        assert e["source"]


# ---------------------------------------------------------------- service layer
def test_register_agent_returns_api_key_once(db):
    data = IocService(db).register_agent(agent_code="ioc-unit-agent", hostname="H1", platform="windows")
    assert "api_key" in data
    assert data["agent_code"] == "ioc-unit-agent"
    agent = db.get(IocAgent, data["id"])
    assert agent.api_key_hash  # only the hash is stored
    assert agent.api_key_hash != data["api_key"]


def test_ingest_observation_labels_real_endpoint(db):
    svc = IocService(db)
    agent = svc.register_agent(agent_code="ioc-real-agent", hostname="H2", platform="windows")
    result = svc.ingest_observation(
        agent_code="ioc-real-agent",
        observations=[
            {"type": "ipv4", "value": MALICIOUS_IP, "source": "network.connection"},
            {"type": "ipv4", "value": PRIVATE_TEST_IP, "source": "network.connection"},
        ],
        source_label="real_endpoint",
    )
    assert result["stored"] == 2
    assert result["matched"] == 1
    assert result["unknown"] == 1

    rows = db.execute(select(IocObservation).where(IocObservation.agent_id == agent["id"])).scalars().all()
    assert len(rows) == 2
    assert all(r.source_label == "real_endpoint" for r in rows)

    matches = db.execute(select(IocMatch).where(IocMatch.agent_id == agent["id"])).scalars().all()
    assert len(matches) == 2
    by_value = {m.value: m for m in matches}
    assert by_value[MALICIOUS_IP].verdict == "malicious"
    assert by_value[MALICIOUS_IP].confidence == 0.95
    assert by_value[PRIVATE_TEST_IP].verdict == "unknown"
    assert by_value[PRIVATE_TEST_IP].confidence == 0.0


def test_ingest_unknown_never_fabricates_verdict(db):
    svc = IocService(db)
    svc.register_agent(agent_code="ioc-unknown-agent", hostname="H3", platform="windows")
    result = svc.ingest_observation(
        agent_code="ioc-unknown-agent",
        observations=[{"type": "domain", "value": "example-not-listed.com"}],
        source_label="real_endpoint",
    )
    assert result["matched"] == 0
    assert result["unknown"] == 1
    match = db.scalar(select(IocMatch).where(IocMatch.agent_id != ""))
    assert match is not None


def test_ingest_requires_valid_type_and_value(db):
    svc = IocService(db)
    svc.register_agent(agent_code="ioc-bad-agent", hostname="H4", platform="windows")
    from app.core.exceptions import ValidationError

    import pytest

    with pytest.raises(ValidationError):
        svc.ingest_observation(
            agent_code="ioc-bad-agent",
            observations=[{"type": "nope", "value": "x"}],
        )
    with pytest.raises(ValidationError):
        svc.ingest_observation(
            agent_code="ioc-bad-agent",
            observations=[{"type": "ipv4", "value": ""}],
        )


def test_lookup_sync_returns_honest_dict(db):
    svc = IocService(db)
    out = svc.lookup_sync("ipv4", MALICIOUS_IP)
    assert out["verdict"] == "malicious"
    assert out["confidence"] == 0.95
    assert out["source"]  # real threat-intel source name
    out2 = svc.lookup_sync("ipv4", "8.8.8.8")
    assert out2["verdict"] == "unknown"
    assert out2["source"] == "bundled"


# ----------------------------------------------------------------------- demo
def test_demo_seed_marks_rows_as_demo(client, admin_headers, db):
    agents = client.get("/api/v1/ioc/agents", headers=admin_headers).json()
    assert agents
    demo_codes = {"ioc-win-001", "ioc-win-002"}
    assert any(a["agent_code"] in demo_codes for a in agents)
    assert all(a["demo"] is True for a in agents)

    dash = client.get("/api/v1/ioc/dashboard", headers=admin_headers).json()
    assert dash["demo"] is True
    assert dash["matches_total"] >= 1


def test_agent_api_key_required_for_ingest(client):
    assert (
        client.post(
            "/api/v1/ioc/ingest",
            json={"agent_code": "ioc-win-001", "observations": []},
            headers={"X-API-Key": "bogus"},
        ).status_code
        == 401
    )
    assert client.get("/api/v1/ioc/indicators", headers={"X-API-Key": "bogus"}).status_code == 401


def test_indicators_endpoint_lists_seeded_corpus(client, admin_headers):
    resp = client.get("/api/v1/ioc/indicators", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 5


def test_lookup_endpoint_honest(client, admin_headers):
    resp = client.get(
        "/api/v1/ioc/lookup", params={"type": "ipv4", "value": MALICIOUS_IP}, headers=admin_headers
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "malicious"
    resp2 = client.get(
        "/api/v1/ioc/lookup", params={"type": "ipv4", "value": "8.8.8.8"}, headers=admin_headers
    )
    assert resp2.json()["verdict"] == "unknown"
