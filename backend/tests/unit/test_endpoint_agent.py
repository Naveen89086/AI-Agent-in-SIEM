"""Endpoint agent (stdlib-only) - collectors and CLI unit tests.

The agent is a thin, dependency-free client: it collects bounded inventory and
indicator observations, deduplicates them and submits them through the
authenticated ingest APIs. Pure parsing helpers are tested here; live OS
collectors are exercised where the host supports them.
"""

import sys

import pytest

sys.path.insert(0, r"F:\AI-Agent in SIEM Project")

from endpoint_agent.collector import (  # noqa: E402
    _is_private,
    collect_inventory,
    collect_observations,
    filter_new,
    parse_dpkg,
    parse_netstat,
    parse_rpm,
)
from endpoint_agent.config import EndpointAgentConfig  # noqa: E402
from endpoint_agent.telemetry_collector import (  # noqa: E402
    _mem_str_to_mb,
    _netstat_listeners,
    _netstat_network_snapshot,
    collect_processes,
    collect_services,
    collect_telemetry_snapshot,
    snapshot_fingerprint,
)

is_windows = sys.platform == "win32"


# ------------------------------------------------------------ telemetry config
def test_config_telemetry_knobs_and_key_file(tmp_path):
    cfg = EndpointAgentConfig(
        server_url="http://localhost:8000",
        agent_code="telemetry-cfg",
        telemetry_api_key_file=str(tmp_path / "t.telemetry.key"),
    )
    assert cfg.network_interval == 5
    assert cfg.process_interval == 5
    assert cfg.service_interval == 15
    assert cfg.max_connections == 1000
    assert cfg.max_listeners == 500
    assert cfg.telemetry_api_key_file.endswith(".telemetry.key")
    assert cfg.load_telemetry_api_key() is None
    cfg.save_telemetry_api_key("sk-telemetry-123")
    assert cfg.load_telemetry_api_key() == "sk-telemetry-123"


# -------------------------------------------------------- telemetry collectors
def test_telemetry_demo_snapshot_structure():
    snap = collect_telemetry_snapshot(demo=True)
    assert set(snap) == {"collected_at", "fingerprint", "network", "processes", "services"}
    assert snap["network"]["connections"]
    assert snap["network"]["listeners"]
    assert snap["network"]["interfaces"]
    assert snap["network"]["statistics"]
    assert len(snap["processes"]) == 4
    assert len(snap["services"]) == 3
    # the demo corpus must never leak into real mode: demo rows stay explicit
    assert snap["network"]["connections"][0]["is_private"] is False


def test_telemetry_snapshot_fingerprint_is_stable():
    a = collect_telemetry_snapshot(demo=True)
    b = collect_telemetry_snapshot(demo=True)
    assert snapshot_fingerprint(a["network"]) == snapshot_fingerprint(b["network"])
    assert len(a["fingerprint"]) == 64


def test_demo_processes_and_services_are_labeled_explicitly():
    processes = collect_processes(demo=True)
    services = collect_services(demo=True)
    assert all(p["name"] in {"System", "svchost.exe", "chrome.exe", "update.exe"} for p in processes)
    assert all(s["state"] in {"running", "stopped"} for s in services)


def test_netstat_network_snapshot_parses_and_separates_listeners(monkeypatch):
    netstat_output = (
        "  TCP    10.0.0.5:50123    45.83.193.105:4444    ESTABLISHED     4212\n"
        "  TCP    0.0.0.0:135       0.0.0.0:0              LISTENING       812\n"
        "  TCP    127.0.0.1:1234    127.0.0.1:8080         ESTABLISHED     100\n"
    )
    monkeypatch.setattr(
        "endpoint_agent.telemetry_collector._run",
        lambda _cmd: netstat_output,
    )
    snap = _netstat_network_snapshot()
    conns = snap["connections"]
    assert len(conns) == 1
    assert conns[0]["foreign_ip"] == "45.83.193.105"
    assert conns[0]["foreign_port"] == 4444
    assert conns[0]["is_private"] is False
    # localhost destinations are excluded
    assert all(c["foreign_ip"] not in ("127.0.0.1", "0.0.0.0") for c in conns)


def test_netstat_listeners_parse(monkeypatch):
    netstat_output = (
        "  TCP    0.0.0.0:135       0.0.0.0:0              LISTENING       812\n"
        "  UDP    0.0.0.0:5353     *:*                    LISTENING       1092\n"
        "  TCP    10.0.0.5:50123   45.83.193.105:4444     ESTABLISHED     4212\n"
    )
    monkeypatch.setattr(
        "endpoint_agent.telemetry_collector._run",
        lambda _cmd: netstat_output,
    )
    listeners = _netstat_listeners()
    assert len(listeners) == 2
    assert listeners[0]["port"] == 135
    assert listeners[1]["proto"] == "udp"


def test_mem_str_to_mb_parsing():
    assert _mem_str_to_mb("123,456 K") == round(123456 / 1024.0, 1)
    assert _mem_str_to_mb("512 M") == 512.0
    assert _mem_str_to_mb("1 G") == 1024.0
    assert _mem_str_to_mb("N/A") is None
    assert _mem_str_to_mb("") is None


# ------------------------------------------------------------------ parsers
def test_parse_netstat_extracts_established_connections():
    out = parse_netstat(
        "  TCP    10.0.0.5:50123    45.83.193.105:4444    ESTABLISHED     4212\n"
        "  TCP    10.0.0.5:1234      127.0.0.1:8080        ESTABLISHED     100\n"
        "  UDP    0.0.0.0:50000     *:*                  LISTENING       4\n"
    )
    assert len(out) == 1
    row = out[0]
    assert row["proto"] == "tcp"
    assert row["foreign_ip"] == "45.83.193.105"
    assert row["foreign_port"] == "4444"
    assert row["pid"] == 4212


def test_parse_netstat_skips_local_and_listening():
    out = parse_netstat(
        "  TCP    127.0.0.1:1234    0.0.0.0:0              LISTENING       4\n"
        "  TCP    [::1]:8080        [::1]:9000             ESTABLISHED     7\n"
    )
    assert out == []


def test_parse_dpkg():
    out = parse_dpkg("openssl\t3.0.13-1ubuntu1\nbash\t5.1.16-1\n\njunk\n")
    assert len(out) == 2
    assert out[0]["product"] == "openssl"
    assert out[0]["version"] == "3.0.13-1ubuntu1"


def test_parse_rpm():
    out = parse_rpm("bash-5.1.16-1\nopenssl-3.0.13-1.fc38\n")
    assert len(out) == 2
    assert out[1]["product"] == "openssl"
    assert out[1]["version"] == "3.0.13-1.fc38"


def test_is_private():
    assert _is_private("10.0.0.5") is True
    assert _is_private("192.168.1.1") is True
    assert _is_private("45.83.193.105") is False
    assert _is_private("not-an-ip") is False


# --------------------------------------------------------------- collections
def test_collect_inventory_demo_is_labeled():
    inv = collect_inventory(demo=True)
    assert len(inv) == 5
    assert all(i["source"] == "demo" for i in inv)
    assert any(i["product"] == "Chrome" for i in inv)


def test_collect_observations_demo_is_bounded_and_labeled():
    obs = collect_observations(demo=True)
    assert len(obs) == 4
    assert all(o["source"] in ("network.connection", "network.dns", "file.hash", "registry.autostart") for o in obs)


def test_filter_new_deduplicates():
    seen: set[str] = set()
    obs = [
        {"type": "ipv4", "value": "1.2.3.4"},
        {"type": "ipv4", "value": "1.2.3.4"},
        {"type": "domain", "value": "example.com"},
    ]
    fresh = filter_new(obs, seen)
    assert len(fresh) == 2
    assert filter_new(obs, seen) == []


@pytest.mark.skipif(not is_windows, reason="requires a Windows endpoint")
def test_collect_inventory_real_mode_never_fabricates():
    inv = collect_inventory(demo=False)
    # Either the registry returned real rows or we return empty - never demo data.
    assert all(i["source"] != "demo" for i in inv)


# --------------------------------------------------------------------- config
def test_config_defaults_and_layering(tmp_path):
    cfg = EndpointAgentConfig(server_url="http://localhost:8000", agent_code="cfg-test", demo=True)
    assert cfg.agent_code == "cfg-test"
    assert cfg.demo is True
    assert cfg.inventory_interval > 0


def test_config_overrides_from_yaml(tmp_path):
    yaml_file = tmp_path / "agent.yaml"
    yaml_file.write_text(
        "agent_code: yaml-code\nserver_url: http://yaml.example\ninventory_interval: 7\n"
    )
    cfg = EndpointAgentConfig.from_yaml(str(yaml_file))
    assert cfg.agent_code == "yaml-code"
    assert cfg.server_url == "http://yaml.example"
    assert cfg.inventory_interval == 7
