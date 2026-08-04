"""Module 2 - normalization & parsing tests."""

import asyncio

from app.pipeline.bus import InMemoryBus, Topics
from app.pipeline.grok import Grok, cast_value
from app.pipeline.parsers import (
    FirewallParser,
    JsonParser,
    LinuxAuthParser,
    SyslogParser,
    WebServerParser,
    WindowsParser,
    resolve_parser,
)
from app.services.normalizer_service import NormalizerService
from app.storage.base import SearchQuery
from app.storage.local_store import LocalJsonStore

import tempfile


# --------------------------------------------------------------------------- Grok
def test_grok_basic():
    g = Grok("%{IP:ip} %{WORD:word}")
    m = g.match("192.168.1.5 hello")
    assert m is not None
    assert m.fields["ip"] == "192.168.1.5"
    assert m.fields["word"] == "hello"


def test_grok_cast():
    assert cast_value("42") == 42
    assert cast_value("3.5") == 3.5
    assert cast_value("abc") == "abc"
    assert cast_value("true") is True


# ----------------------------------------------------------------------- parsers
def test_linux_failed_login():
    p = LinuxAuthParser()
    event = p.parse(
        {
            "message": "2026-08-01T12:00:01+00:00 srv1 sshd[3124]: Failed password for root from 203.0.113.9 port 22 ssh2",
            "host": "srv1",
        }
    )
    assert event is not None
    assert event["event"]["action"] == "ssh_failed_login"
    assert event["event"]["outcome"] == "failure"
    assert event["source"]["ip"] == "203.0.113.9"
    assert event["user"]["name"] == "root"
    assert event["process"]["pid"] == 3124


def test_linux_success():
    p = LinuxAuthParser()
    event = p.parse(
        {
            "message": "2026-08-01T12:00:02+00:00 srv1 sshd[3125]: Accepted publickey for alice from 10.0.0.5 port 55123",
            "host": "srv1",
        }
    )
    assert event["event"]["action"] == "ssh_login"
    assert event["event"]["outcome"] == "success"
    assert event["source"]["ip"] == "10.0.0.5"


def test_linux_sudo():
    p = LinuxAuthParser()
    event = p.parse(
        {
            "message": "2026-08-01T12:01:00+00:00 srv1 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/passwd alice",
            "host": "srv1",
        }
    )
    assert event is not None
    assert event["event"]["action"] == "sudo_command"
    assert event["user"]["name"] == "alice"
    assert "passwd" in event["process"]["command_line"]


def test_windows_logon_failure():
    p = WindowsParser()
    event = p.parse(
        {
            "message": "An account failed to log on",
            "host": "WIN-HOST",
            "extra": {
                "event_id": 4625,
                "provider": "Microsoft-Windows-Security-Auditing",
                "log_name": "Security",
                "source_ip": "192.168.1.99",
                "target_user": "admin",
            },
        }
    )
    assert event is not None
    assert event["event"]["action"] == "logon_failure"
    assert event["event"]["outcome"] == "failure"
    assert event["source"]["ip"] == "192.168.1.99"
    assert event["user"]["name"] == "admin"


def test_windows_process_created():
    p = WindowsParser()
    event = p.parse(
        {
            "message": "New process created",
            "extra": {
                "event_id": 4688,
                "process_name": "cmd.exe",
                "process_path": r"C:\Windows\System32\cmd.exe",
                "process_id": 1000,
                "command_line": "cmd.exe /c whoami",
                "user": "bob",
            },
        }
    )
    assert event is not None
    assert event["event"]["category"] == ["process"]
    assert event["process"]["name"] == "cmd.exe"
    assert event["process"]["command_line"] == "cmd.exe /c whoami"


def test_web_server():
    p = WebServerParser()
    event = p.parse(
        {
            "message": '203.0.113.7 - - [01/Aug/2026:14:23:45 +0000] "GET /admin HTTP/1.1" 403 512',
        }
    )
    assert event is not None
    assert event["event"]["module"] == "httpd"
    assert event["http"]["response"]["status_code"] == 403
    assert event["url"]["path"] == "/admin"
    assert event["source"]["ip"] == "203.0.113.7"


def test_firewall():
    p = FirewallParser()
    event = p.parse(
        {
            "message": "2026-08-01T13:00:00+00:00 fw1 kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=5.6.7.8 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=50000 DPT=22",
            "host": "fw1",
        }
    )
    assert event is not None
    assert event["event"]["action"] == "firewall_block"
    assert event["event"]["outcome"] == "denied"
    assert event["source"]["ip"] == "5.6.7.8"
    assert event["destination"]["port"] == 22
    assert event["network"]["protocol"] == "tcp"


def test_json_passthrough():
    p = JsonParser()
    event = p.parse({"message": '{"@timestamp": "2026-08-01T10:00:00Z", "user": "x", "action": "read"}'})
    assert event is not None
    assert event["labels"]["action"] == "read"


def test_parser_resolution():
    assert resolve_parser("linux", None, None).id == "linux_auth"
    assert resolve_parser("syslog", None, None).id == "syslog"
    assert resolve_parser("http", "json", None).id == "json"
    assert resolve_parser("syslog", "syslog", "apache").id == "web_server"


# ------------------------------------------------------------------- normalizer
def test_normalizer_pipeline_e2e():
    tmp = tempfile.mkdtemp()
    bus = InMemoryBus()
    store = LocalJsonStore(base_dir=tmp)
    service = NormalizerService(bus, store)

    async def scenario():
        raw = {
            "event_id": "evt-1",
            "raw": "2026-08-01T12:00:01+00:00 srv1 sshd[3124]: Failed password for root from 203.0.113.9 port 22 ssh2",
            "message": "2026-08-01T12:00:01+00:00 srv1 sshd[3124]: Failed password for root from 203.0.113.9 port 22 ssh2",
            "source_type": "linux",
            "source_name": "srv-auth-01",
            "host": "srv1",
            "received_at": "2026-08-01T12:00:01+00:00",
            "tags": ["syslog"],
            "extra": {},
            "pipeline": {"ingested": True},
        }
        result = await service.process(raw)
        assert result is not None
        assert result["event"]["action"] == "ssh_failed_login"
        assert result["pipeline"]["normalized"] is True

        # persisted to store
        search = await store.search(SearchQuery(text="203.0.113.9"))
        assert search.total == 1

        # published to normalized topic
        received = []
        async for topic, event, msg_id in bus.subscribe(
            [Topics.NORMALIZED_EVENTS], "g", "c", block_ms=200
        ):
            received.append(event)
            if len(received) == 1:
                break
        assert received[0]["event_id"] == "evt-1"

    asyncio.run(scenario())


def test_normalizer_unknown_message_still_stored():
    tmp = tempfile.mkdtemp()
    bus = InMemoryBus()
    store = LocalJsonStore(base_dir=tmp)
    service = NormalizerService(bus, store)

    async def scenario():
        raw = {
            "event_id": "evt-2",
            "raw": "completely unstructured junk line",
            "message": "completely unstructured junk line",
            "source_type": "syslog",
            "source_name": "misc",
            "received_at": "2026-08-01T12:00:01+00:00",
            "tags": [],
            "extra": {},
        }
        result = await service.process(raw)
        assert result is not None
        # unmatched by a dedicated parser still falls back to the generic
        # syslog normalizer so no log line is ever dropped
        assert result["pipeline"]["normalized"] is True
        search = await store.search(SearchQuery(text="unstructured"))
        assert search.total == 1

    asyncio.run(scenario())
