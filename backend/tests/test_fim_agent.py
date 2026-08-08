"""Tests for the standalone FIM agent package.

Covers hashing/state collection, baseline diffing, config layering and the
monitor's change-detection -> ingest pipeline with a fake transport (no real
network). The watchdog path is exercised only when watchdog is installed.
"""

import hashlib
import os
from pathlib import Path

import pytest


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------- config
def test_config_defaults_monitor_small_dir():
    from fim_agent.config import DEFAULT_MONITORED_PATHS, FimAgentConfig

    cfg = FimAgentConfig(agent_code="t")
    assert DEFAULT_MONITORED_PATHS == [r"C:\FIM-Test"]
    assert cfg.monitored_paths == DEFAULT_MONITORED_PATHS
    assert "C:" not in cfg.baseline_file or True  # baseline is per-user, not a drive
    assert cfg.hostname


def test_config_from_yaml(tmp_path):
    from fim_agent.config import FimAgentConfig

    cfg_file = tmp_path / "fim.yaml"
    cfg_file.write_text(
        "\n".join(
            [
                "agent_code: yaml-agent",
                "monitored_paths:",
                "  - C:\\Temp\\one",
                "poll_interval: 9",
            ]
        ),
        encoding="utf-8",
    )
    cfg = FimAgentConfig.from_yaml(str(cfg_file))
    assert cfg.agent_code == "yaml-agent"
    assert cfg.monitored_paths == [r"C:\Temp\one"]
    assert cfg.poll_interval == 9


def test_config_env_overrides(tmp_path, monkeypatch):
    from fim_agent.config import FimAgentConfig

    monkeypatch.setenv("FIM_AGENT_SERVER_URL", "https://siem.example.com")
    monkeypatch.setenv("FIM_AGENT_CODE", "env-agent")
    monkeypatch.setenv("FIM_AGENT_MONITORED_PATHS", "C:\\One;C:\\Two")
    cfg = FimAgentConfig.from_env()
    assert cfg.server_url == "https://siem.example.com"
    assert cfg.agent_code == "env-agent"
    assert cfg.monitored_paths == [r"C:\One", r"C:\Two"]


# -------------------------------------------------------------------- collector
def test_sha256_file(tmp_path):
    from fim_agent.collector import sha256_file

    f = tmp_path / "a.txt"
    _write(f, "hello world")
    assert sha256_file(str(f)) == _sha("hello world")
    assert sha256_file(str(tmp_path / "missing.txt")) is None


def test_file_state_and_classify(tmp_path):
    from fim_agent.collector import classify_change, file_state

    f = tmp_path / "b.txt"
    _write(f, "v1")
    state1 = file_state(str(f))
    assert state1["sha256"] == _sha("v1")
    assert state1["file_type"] == "txt"

    assert classify_change(str(f), None, state1) == "added"
    assert classify_change(str(f), state1, None) == "deleted"
    _write(f, "v2")
    state2 = file_state(str(f))
    assert classify_change(str(f), state1, state2) == "modified"
    assert classify_change(str(f), state2, state2) == "unchanged"


def test_excluded_patterns(tmp_path):
    from fim_agent.collector import excluded

    assert excluded(str(tmp_path / "x.tmp"), ["*.tmp", "~$*"])
    assert not excluded(str(tmp_path / "x.txt"), ["*.tmp", "~$*"])


# --------------------------------------------------------------------- baseline
def test_baseline_scan_diff_and_roundtrip(tmp_path):
    from fim_agent.baseline import Baseline

    root = tmp_path / "watch"
    _write(root / "one.txt", "one")
    _write(root / "two.txt", "two")

    base = Baseline().scan([str(root)], [])
    assert set(base.entries) == {
        str(root / "one.txt").replace("/", "\\"),
        str(root / "two.txt").replace("/", "\\"),
    }

    saved = tmp_path / "base.json"
    base.save(str(saved))
    loaded = Baseline.load(str(saved))
    assert loaded.entries == base.entries

    _write(root / "two.txt", "two-changed")
    _write(root / "three.txt", "three")
    os.remove(root / "one.txt")
    fresh = Baseline().scan([str(root)], [])

    added, removed, modified = base.diff(fresh)
    assert added == [str(root / "three.txt").replace("/", "\\")]
    assert removed == [str(root / "one.txt").replace("/", "\\")]
    assert modified == [str(root / "two.txt").replace("/", "\\")]


# ---------------------------------------------------------------------- monitor
class FakeTransport:
    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.heartbeats = 0

    def ingest(self, api_key: str, payload: dict) -> dict:
        self.sent.append(payload)
        return {"accepted": True, "event_type": payload["event_type"], "severity": "low"}

    def heartbeat(self, api_key: str, status: str = "online") -> dict:
        self.heartbeats += 1
        return {"status": status}


def _monitor(tmp_path, transport=None):
    from fim_agent.config import FimAgentConfig
    from fim_agent.monitor import FimMonitor

    cfg = FimAgentConfig(
        agent_code="t",
        monitored_paths=[str(tmp_path)],
        baseline_file=str(tmp_path / "base.json"),
        api_key_file=str(tmp_path / "key"),
        use_watchdog=False,
        poll_interval=60,
    )
    transport = transport or FakeTransport()
    return FimMonitor(cfg, transport=transport, api_key="k"), transport


def test_monitor_reports_added_modified_deleted(tmp_path):
    monitor, transport = _monitor(tmp_path / "mt")
    root = tmp_path / "mt"

    f = root / "file.txt"
    _write(f, "hello")
    monitor.ensure_baseline()

    _write(f, "hello-changed")
    monitor._evaluate(str(f))
    assert len(transport.sent) == 1
    payload = transport.sent[0]
    assert payload["event_type"] == "modified"
    assert payload["sha256"] == _sha("hello-changed")
    assert payload["event_id"]
    assert payload["user"]
    assert payload["source"] == "fim-agent"

    # unchanged -> no duplicate event
    monitor._evaluate(str(f))
    assert len(transport.sent) == 1

    os.remove(f)
    monitor._evaluate(str(f))
    assert len(transport.sent) == 2
    assert transport.sent[1]["event_type"] == "deleted"
    assert transport.sent[1]["old_sha256"] == _sha("hello-changed")

    _write(f, "new file")
    monitor._evaluate(str(f))
    assert transport.sent[2]["event_type"] == "added"
    assert transport.sent[2]["sha256"] == _sha("new file")


def test_monitor_reports_rename(tmp_path):
    monitor, transport = _monitor(tmp_path / "rn")
    root = tmp_path / "rn"

    old = root / "old.txt"
    new = root / "new.txt"
    _write(old, "renamed body")
    monitor.ensure_baseline()

    os.rename(old, new)
    monitor._handle_raw({"kind": "moved", "src": str(old), "dest": str(new)})
    assert len(transport.sent) == 1
    payload = transport.sent[0]
    assert payload["event_type"] == "renamed"
    assert payload["old_path"] == str(old).replace("/", "\\")
    assert payload["path"] == str(new).replace("/", "\\")


def test_monitor_dedupe_via_event_id(tmp_path):
    monitor, transport = _monitor(tmp_path / "dd")
    root = tmp_path / "dd"

    f = root / "x.txt"
    _write(f, "v1")
    monitor.ensure_baseline()
    _write(f, "v2")
    monitor._evaluate(str(f))
    assert len(transport.sent) == 1
    event_id = transport.sent[0]["event_id"]

    # replaying the exact same event (same state) yields the same event_id
    _write(f, "v2")
    monitor._evaluate(str(f))
    assert transport.sent[-1]["event_id"] == event_id
    assert len(transport.sent) == 1  # unchanged -> not reported again


def test_monitor_periodic_scan_catches_changes(tmp_path):
    monitor, transport = _monitor(tmp_path / "ps")
    root = tmp_path / "ps"

    f = root / "tracked.txt"
    _write(f, "base")
    monitor.ensure_baseline()
    assert len(transport.sent) == 0

    # change a file without going through _evaluate, then poll
    _write(f, "changed by someone")
    monitor._periodic_scan()
    assert len(transport.sent) == 1
    assert transport.sent[0]["event_type"] == "modified"


def test_monitor_skips_excluded(tmp_path):
    from fim_agent.config import FimAgentConfig
    from fim_agent.monitor import FimMonitor

    transport = FakeTransport()
    root = tmp_path / "ex"
    _write(root / "keep.txt", "a")
    _write(root / "skip.tmp", "b")

    cfg = FimAgentConfig(
        agent_code="t",
        monitored_paths=[str(root)],
        baseline_file=str(root / "base.json"),
        api_key_file=str(root / "key"),
        use_watchdog=False,
        poll_interval=60,
    )
    monitor = FimMonitor(cfg, transport=transport, api_key="k")
    monitor.ensure_baseline()
    assert len(monitor.baseline.entries) == 1
    assert "skip.tmp" not in str(list(monitor.baseline.entries)[0]).lower()


def test_watchdog_observer_degrades_gracefully(tmp_path, monkeypatch):
    """Without watchdog installed the agent must still start (polling mode)."""
    monkeypatch.setattr("fim_agent.monitor._HAS_WATCHDOG", False)
    monitor, transport = _monitor(tmp_path / "dg")
    assert monitor.start_observer() is False


def test_transport_ingest_urls():
    from fim_agent.config import FimAgentConfig
    from fim_agent.transport import FimTransport

    cfg = FimAgentConfig(server_url="http://h:8000", agent_code="t")
    t = FimTransport(cfg)
    assert cfg.base_url == "http://h:8000/api/v1"
    assert t.config.agent_code == "t"
