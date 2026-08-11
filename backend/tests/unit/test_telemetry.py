"""Network + Process/Service telemetry - service, parser, rules and API tests.

The endpoint telemetry module ships two read surfaces (live state tables) and a
transition stream: lifecycle changes are emitted as ``RawEventIn``-shaped events
(``source_type="endpoint"``, ``extra.parser="endpoint_telemetry"``), parsed into
ECS fields and run through the correlation rules. Real vs demo labeling is
server-authoritative (``source_label``).
"""

import asyncio
from pathlib import Path

from sqlalchemy import select

from app.models.telemetry import (
    NetworkConnection,
    NetworkListener,
    ProcessRecord,
    ServiceRecord,
    TelemetryAgent,
)
from app.pipeline.bus import InMemoryBus
from app.pipeline.correlator import Correlator
from app.pipeline.parsers import get_parser
from app.pipeline.rules import RuleSet
from app.services.telemetry_service import TelemetryService, conn_key, listen_key

RULES_DIR = Path(__file__).resolve().parents[2] / "app" / "rules"

TEMP_PROCESS_RULE = "44444444-4444-4444-8444-444444444402"
NETWORK_TEMP_RULE = "44444444-4444-4444-8444-444444444403"
SERVICE_RULE = "44444444-4444-4444-8444-444444444404"
OFFICE_SHELL_RULE = "44444444-4444-4444-8444-444444444401"

NETWORK_SNAPSHOT = {
    "network": {
        "connections": [
            {
                "proto": "tcp",
                "local_ip": "10.10.10.31",
                "local_port": 51234,
                "foreign_ip": "45.83.193.105",
                "foreign_port": 4444,
                "state": "ESTABLISHED",
                "pid": 9988,
                "process_name": "update.exe",
                "user": "analyst",
                "executable": r"C:\Users\analyst\AppData\Local\Temp\update.exe",
                "is_private": False,
            },
            {
                "proto": "tcp",
                "local_ip": "10.10.10.31",
                "local_port": 49872,
                "foreign_ip": "10.10.10.20",
                "foreign_port": 445,
                "state": "ESTABLISHED",
                "pid": 812,
                "process_name": "svchost.exe",
                "user": "SYSTEM",
                "executable": r"C:\Windows\System32\svchost.exe",
                "is_private": True,
            },
        ],
        "listeners": [
            {
                "proto": "tcp",
                "ip": "0.0.0.0",
                "port": 135,
                "pid": 812,
                "process_name": "svchost.exe",
                "user": "NETWORK SERVICE",
            }
        ],
        "interfaces": [
            {
                "name": "Ethernet",
                "mac": "00:15:5d:01:aa:01",
                "addresses": ["10.10.10.31"],
                "mtu": 1500,
                "speed_mbps": 1000,
                "status": "up",
            }
        ],
        "statistics": {
            "bytes_sent": 1234,
            "bytes_recv": 5678,
            "packets_sent": 100,
            "packets_recv": 200,
        },
    },
    "processes": [
        {
            "pid": 9988,
            "name": "update.exe",
            "executable": r"C:\Users\analyst\AppData\Local\Temp\update.exe",
            "command_line": "update.exe -silent",
            "parent_pid": 4211,
            "parent_name": "explorer.exe",
            "user": "analyst",
            "cpu_percent": 12.5,
            "memory_rss_mb": 88.1,
            "threads": 6,
            "started_at": None,
        }
    ],
    "services": [
        {
            "name": "Spooler",
            "display_name": "Print Spooler",
            "state": "running",
            "start_type": "auto",
            "account": "LocalSystem",
            "binary_path": r"C:\Windows\System32\spoolsv.exe",
            "pid": 2411,
        }
    ],
}


def _ecs_event(**overrides) -> dict:
    ev = {
        "@timestamp": "2026-08-11T10:00:00+00:00",
        "event": {"action": "process_created", "kind": "event", "module": "endpoint-telemetry"},
        "host": {"name": "WORKSTATION-01"},
        "labels": {"agent_code": "tlm-unit"},
        "process": {"name": "cmd.exe", "pid": 7000, "executable": None, "parent": {"pid": None, "name": None}},
        "message": "endpoint telemetry",
        "pipeline": {"parsed": True, "parser": "endpoint_telemetry"},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(ev.get(key), dict):
            ev[key].update(value)
        else:
            ev[key] = value
    return ev


# ------------------------------------------------------------------- helpers
def test_conn_and_listen_keys():
    assert conn_key("tcp", "10.0.0.1", 100, "1.2.3.4", 80) == "tcp|10.0.0.1|100|1.2.3.4|80"
    assert listen_key("tcp", "0.0.0.0", 135) == "tcp|0.0.0.0|135"


# --------------------------------------------------------------- service layer
def test_ingest_snapshot_upserts_state_and_emits_transitions(db):
    svc = TelemetryService(db)
    svc.register_agent(agent_code="tlm-unit-agent", hostname="WORKSTATION-01", platform="windows")
    result = svc.ingest_snapshot(
        agent_code="tlm-unit-agent",
        payload=NETWORK_SNAPSHOT,
        source_label="demo",
    )
    assert result["connections"]["new"] == 2
    assert result["connections"]["listeners"] == 1
    assert result["processes"]["created"] == 1
    assert result["services"]["created"] == 1

    transitions = result["transitions"]
    assert len(transitions) >= 4  # 2 connection_new + 1 listener_added + process/service
    for transition in transitions:
        assert transition["source_type"] == "endpoint"
        assert transition["extra"]["parser"] == "endpoint_telemetry"
        assert transition["extra"]["event_action"]
        assert transition["message"]
        assert isinstance(transition["tags"], list)

    # live-state tables are populated
    agent = db.scalar(select(TelemetryAgent).where(TelemetryAgent.agent_code == "tlm-unit-agent"))
    assert agent.demo is False  # server stores demo rows under source_label only
    conns = db.execute(select(NetworkConnection)).scalars().all()
    assert any(c.foreign_ip == "45.83.193.105" and c.source_label == "demo" for c in conns)
    assert db.scalar(select(ProcessRecord).where(ProcessRecord.pid == 9988)) is not None
    assert db.scalar(select(ServiceRecord).where(ServiceRecord.name == "Spooler")) is not None

    # transitions persist as normalized/detected events when run through the pipeline
    assert svc.network_dashboard()["connections_total"] >= 2
    assert svc.process_summary()["processes_running"] >= 1
    assert len(svc.services()) >= 1


def test_ingest_snapshot_close_vanished_connection_emits_closed_transition(db):
    svc = TelemetryService(db)
    svc.register_agent(agent_code="tlm-unit-agent-2", hostname="H2", platform="windows")
    svc.ingest_snapshot(agent_code="tlm-unit-agent-2", payload=NETWORK_SNAPSHOT, source_label="real_endpoint")

    second = {**NETWORK_SNAPSHOT, "network": {**NETWORK_SNAPSHOT["network"], "connections": []}}
    result = svc.ingest_snapshot(agent_code="tlm-unit-agent-2", payload=second, source_label="real_endpoint")
    assert result["connections"]["closed"] == 2
    assert any(t["extra"]["event_action"] == "connection_closed" for t in result["transitions"])
    agent = db.scalar(select(TelemetryAgent).where(TelemetryAgent.agent_code == "tlm-unit-agent-2"))
    conns = db.execute(select(NetworkConnection).where(NetworkConnection.agent_id == agent.id)).scalars().all()
    assert conns and all(c.status == "closed" for c in conns)


# ------------------------------------------------------------------ parser
def test_endpoint_telemetry_parser_maps_ecs_fields():
    raw = {
        "message": "New TCP connection from 10.10.10.31:51234 to 45.83.193.105:4444 (update.exe)",
        "source_type": "endpoint",
        "source_name": "endpoint-agent",
        "host": "WORKSTATION-01",
        "extra": {
            "parser": "endpoint_telemetry",
            "event_action": "connection_new",
            "agent_code": "tlm-unit-agent",
            "network": {"transport": "tcp", "protocol": "tcp", "direction": "outbound"},
            "source": {"ip": "10.10.10.31", "port": 51234},
            "destination": {"ip": "45.83.193.105", "port": 4444},
            "process": {"name": "update.exe", "pid": 9988, "executable": r"C:\Users\analyst\AppData\Local\Temp\update.exe"},
            "user": {"name": "analyst"},
        },
        "tags": ["network", "connection", "observed"],
    }
    parsed = get_parser("endpoint_telemetry").parse(raw)
    assert parsed is not None
    assert parsed["event"]["action"] == "connection_new"
    assert parsed["event"]["category"] == ["network"]
    assert parsed["network"]["direction"] == "outbound"
    assert parsed["source"]["ip"] == "10.10.10.31"
    assert parsed["destination"]["port"] == 4444
    assert parsed["process"]["executable"] == r"C:\Users\analyst\AppData\Local\Temp\update.exe"
    assert parsed["user"]["name"] == "analyst"
    assert parsed["labels"]["agent_code"] == "tlm-unit-agent"


def test_endpoint_telemetry_parser_ignores_unknown_action():
    raw = {
        "message": "nothing",
        "source_type": "endpoint",
        "source_name": "endpoint-agent",
        "host": "H1",
        "extra": {"parser": "endpoint_telemetry", "event_action": "not_a_real_action"},
        "tags": [],
    }
    assert get_parser("endpoint_telemetry").parse(raw) is None


# ------------------------------------------------------------------- rules
def test_rules_fire_process_from_temp():
    async def scenario():
        corr = Correlator(InMemoryBus(), RuleSet.load_dir(RULES_DIR))
        ev = _ecs_event(process={"name": "bad.exe", "pid": 7000, "executable": r"C:\Users\analyst\AppData\Local\Temp\bad.exe"})
        detections = await corr.process_event(ev)
        assert any(d.rule_id == TEMP_PROCESS_RULE for d in detections)

    asyncio.run(scenario())


def test_rule_fires_network_outbound_from_temp():
    async def scenario():
        corr = Correlator(InMemoryBus(), RuleSet.load_dir(RULES_DIR))
        ev = _ecs_event(
            event={"action": "connection_new", "kind": "event", "module": "endpoint-telemetry"},
            network={"transport": "tcp", "protocol": "tcp", "direction": "outbound"},
            process={"name": "update.exe", "pid": 9988, "executable": r"C:\Users\analyst\AppData\Local\Temp\update.exe"},
        )
        detections = await corr.process_event(ev)
        assert any(d.rule_id == NETWORK_TEMP_RULE for d in detections)

    asyncio.run(scenario())


def test_rule_fires_office_spawns_shell():
    async def scenario():
        corr = Correlator(InMemoryBus(), RuleSet.load_dir(RULES_DIR))
        ev = _ecs_event(
            process={
                "name": "cmd.exe",
                "pid": 7000,
                "executable": r"C:\Windows\System32\cmd.exe",
                "parent": {"pid": 4212, "name": "winword.exe"},
            }
        )
        detections = await corr.process_event(ev)
        assert any(d.rule_id == OFFICE_SHELL_RULE for d in detections)

    asyncio.run(scenario())


def test_rule_fires_service_created():
    async def scenario():
        corr = Correlator(InMemoryBus(), RuleSet.load_dir(RULES_DIR))
        ev = _ecs_event(
            event={"action": "service_created", "kind": "event", "module": "endpoint-telemetry"},
            service={"name": "TotallyLegit", "display_name": "Totally Legit", "state": "running"},
        )
        detections = await corr.process_event(ev)
        assert any(d.rule_id == SERVICE_RULE for d in detections)

    asyncio.run(scenario())


def test_rule_does_not_fire_clean_process():
    async def scenario():
        corr = Correlator(InMemoryBus(), RuleSet.load_dir(RULES_DIR))
        ev = _ecs_event(
            process={
                "name": "explorer.exe",
                "pid": 4211,
                "executable": r"C:\Windows\explorer.exe",
                "parent": {"pid": 4, "name": "System"},
            }
        )
        detections = await corr.process_event(ev)
        assert all(d.rule_id not in (TEMP_PROCESS_RULE, OFFICE_SHELL_RULE) for d in detections)

    asyncio.run(scenario())


# -------------------------------------------------------------------- API
def test_api_register_ingest_and_dashboards(client, admin_headers, db):
    code = "tlm-api-agent"
    reg = client.post(
        "/api/v1/telemetry/agents/register",
        json={"agent_code": code, "hostname": "API-WIN-01", "platform": "windows"},
        headers=admin_headers,
    )
    assert reg.status_code == 200, reg.text
    api_key = reg.json()["api_key"]
    assert reg.json()["demo"] is False

    ingest = client.post(
        "/api/v1/telemetry/ingest",
        json={**NETWORK_SNAPSHOT, "agent_code": code, "demo": True},
        headers={"X-API-Key": api_key},
    )
    assert ingest.status_code == 200, ingest.text
    body = ingest.json()
    assert body["transitions"] >= 4
    assert body["connections"]["new"] == 2
    assert body["processes"]["created"] == 1

    dash = client.get("/api/v1/network/dashboard", headers=admin_headers)
    assert dash.status_code == 200
    assert dash.json()["connections_total"] >= 2

    summary = client.get("/api/v1/processes/summary", headers=admin_headers)
    assert summary.status_code == 200
    assert summary.json()["processes_running"] >= 1

    procs = client.get(f"/api/v1/processes?agent_id={reg.json()['id']}&search=update", headers=admin_headers)
    assert procs.status_code == 200
    assert any(p["name"] == "update.exe" for p in procs.json())

    conns = client.get("/api/v1/network/connections?state=ESTABLISHED", headers=admin_headers)
    assert conns.status_code == 200
    assert any(c["foreign_ip"] == "45.83.193.105" for c in conns.json())

    listeners = client.get("/api/v1/network/listening", headers=admin_headers)
    assert listeners.status_code == 200
    assert any(l["port"] == 135 for l in listeners.json())

    svcs = client.get("/api/v1/services", headers=admin_headers)
    assert svcs.status_code == 200
    assert any(s["name"] == "Spooler" for s in svcs.json())


def test_api_ingest_rejects_unknown_agent(client, admin_headers):
    resp = client.post(
        "/api/v1/telemetry/ingest",
        json={**NETWORK_SNAPSHOT, "agent_code": "does-not-exist", "demo": False},
        headers={"X-API-Key": "garbage-key"},
    )
    assert resp.status_code == 401


def test_api_ingest_requires_valid_api_key(client, admin_headers):
    code = "tlm-api-agent-2"
    client.post(
        "/api/v1/telemetry/agents/register",
        json={"agent_code": code, "hostname": "API-WIN-02", "platform": "windows"},
        headers=admin_headers,
    )
    resp = client.post(
        "/api/v1/telemetry/ingest",
        json={**NETWORK_SNAPSHOT, "agent_code": code, "demo": False},
        headers={"X-API-Key": "wrong-key"},
    )
    assert resp.status_code == 401
