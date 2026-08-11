"""Parser registry: converts raw events into ECS-aligned normalized events.

Each parser returns a partial ECS document; the normalizer merges the result
with ingestion metadata and publishes the final event.
"""

import ipaddress
import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from app.pipeline.grok import Grok, cast_value


# ---------------------------------------------------------------------------
# ECS helpers
# ---------------------------------------------------------------------------
def new_ecs() -> dict[str, Any]:
    return {
        "event": {"kind": "event", "category": [], "type": []},
        "source": {},
        "destination": {},
        "host": {},
        "user": {},
        "process": {},
        "file": {},
        "network": {},
        "url": {},
        "http": {},
        "message": "",
        "tags": [],
    }


def _ip(ip: str) -> str | None:
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None


def _ts(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Base parser
# ---------------------------------------------------------------------------
class EventParser(ABC):
    """Interface implemented by all log parsers."""

    id: str = "generic"

    @abstractmethod
    def parse(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        """Return an ECS-normalized event or None if unparsable."""


# ---------------------------------------------------------------------------
# Linux authentication (sshd / sudo / useradd)
# ---------------------------------------------------------------------------
_SSH_FAILED = Grok(
    r"%{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} sshd\[%{POSINT:proc_pid}\]: Failed password for %{DATA:user} from %{IP:src_ip} port %{POSINT:src_port} ssh2"
)
_SSH_INVALID = Grok(
    r"%{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} sshd\[%{POSINT:proc_pid}\]: Invalid user %{DATA:user} from %{IP:src_ip} port %{POSINT:src_port}"
)
_SSH_SUCCESS = Grok(
    r"%{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} sshd\[%{POSINT:proc_pid}\]: Accepted publickey for %{DATA:user} from %{IP:src_ip} port %{POSINT:src_port}"
)
_SSH_SUCCESS_PASS = Grok(
    r"%{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} sshd\[%{POSINT:proc_pid}\]: Accepted password for %{DATA:user} from %{IP:src_ip} port %{POSINT:src_port}"
)
_SSH_BREAKIN = Grok(
    r"%{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} sshd\[%{POSINT:proc_pid}\]: Possible break-in attempt! %{DATA:rest}"
)
_SSH_BAN = Grok(
    r"%{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} sshd\[%{POSINT:proc_pid}\]: error: maximum authentication attempts exceeded for %{DATA:user} from %{IP:src_ip} port %{POSINT:src_port}"
)
_SUDO = Grok(
    "%{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} sudo%{DATA}: %{USERNAME:user} : TTY=%{DATA:tty} ; PWD=%{DATA:cwd} ; USER=%{USERNAME:runas} ; COMMAND=%{DATA:command}"
)
_USERADD = Grok(
    "%{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} useradd%{DATA}: new user: name=%{USERNAME:user}, UID=%{POSINT:uid}, GID=%{POSINT:gid}, home=%{PATH:home}"
)


class LinuxAuthParser(EventParser):
    id = "linux_auth"

    def parse(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        text = raw.get("message") or raw.get("raw") or ""
        ecs = new_ecs()
        ecs["host"] = {"name": raw.get("host")}
        parsed = (
            _SSH_FAILED.match(text)
            or _SSH_INVALID.match(text)
            or _SSH_SUCCESS.match(text)
            or _SSH_SUCCESS_PASS.match(text)
            or _SSH_BREAKIN.match(text)
            or _SSH_BAN.match(text)
        )
        if parsed:
            fields = parsed.fields
            ts = _ts(fields.get("ts"))
            if ts:
                ecs["@timestamp"] = ts
            ecs["user"] = {"name": fields.get("user")}
            ecs["source"] = {
                "ip": _ip(fields.get("src_ip", "")),
                "port": cast_value(fields.get("src_port")),
            }
            ecs["process"] = {
                "pid": cast_value(fields.get("proc_pid")),
                "name": "sshd",
            }
            ecs["event"]["category"] = ["authentication"]
            ecs["event"]["type"] = ["start", "authentication"]
            ecs["event"]["module"] = "sshd"
            if fields.get("proc_pid"):
                ecs["process"]["pid"] = cast_value(fields["proc_pid"])
            if text.startswith(_SSH_FAILED.expression) or "Failed password" in text:
                ecs["event"]["action"] = "ssh_failed_login"
                ecs["event"]["outcome"] = "failure"
            elif "Invalid user" in text:
                ecs["event"]["action"] = "ssh_invalid_user"
                ecs["event"]["outcome"] = "failure"
            elif "Accepted" in text:
                ecs["event"]["action"] = "ssh_login"
                ecs["event"]["outcome"] = "success"
                ecs["event"]["type"] = ["authentication_success"]
            elif "break-in" in text:
                ecs["event"]["action"] = "ssh_breakin_attempt"
                ecs["event"]["outcome"] = "failure"
            elif "maximum authentication" in text:
                ecs["event"]["action"] = "ssh_max_auth_attempts"
                ecs["event"]["outcome"] = "failure"
            ecs["message"] = text
            ecs["pipeline"] = {"parsed": True, "parser": self.id}
            return ecs

        sudo = _SUDO.match(text)
        if sudo:
            fields = sudo.fields
            ts = _ts(fields.get("ts"))
            if ts:
                ecs["@timestamp"] = ts
            ecs["user"] = {"name": fields.get("user")}
            ecs["event"]["category"] = ["process"]
            ecs["event"]["type"] = ["start"]
            ecs["event"]["module"] = "sudo"
            ecs["event"]["action"] = "sudo_command"
            ecs["event"]["outcome"] = "success"
            ecs["process"] = {
                "name": "sudo",
                "command_line": fields.get("command"),
            }
            ecs["message"] = text
            ecs["pipeline"] = {"parsed": True, "parser": self.id}
            return ecs

        useradd = _USERADD.match(text)
        if useradd:
            fields = useradd.fields
            ts = _ts(fields.get("ts"))
            if ts:
                ecs["@timestamp"] = ts
            ecs["user"] = {"name": fields.get("user"), "id": fields.get("uid")}
            ecs["event"]["category"] = ["iam"]
            ecs["event"]["type"] = ["user", "creation"]
            ecs["event"]["module"] = "useradd"
            ecs["event"]["action"] = "user_created"
            ecs["message"] = text
            ecs["pipeline"] = {"parsed": True, "parser": self.id}
            return ecs
        return None


# ---------------------------------------------------------------------------
# Windows (from agent structured fields + event id hints)
# ---------------------------------------------------------------------------
_WIN_EVENT_ACTIONS = {
    4624: ("logon", "success"),
    4625: ("logon_failure", "failure"),
    4634: ("logoff", "success"),
    4647: ("logoff", "success"),
    4672: ("privileged_logon", "success"),
    4688: ("process_created", "success"),
    4720: ("user_created", "success"),
    4724: ("password_reset", "success"),
    4732: ("group_member_added", "success"),
    4740: ("account_locked", "failure"),
    4768: ("kerberos_ticket", "success"),
    4769: ("kerberos_ticket", "success"),
    4771: ("kerberos_preauth_failed", "failure"),
    4776: ("credential_validation", "success"),
    1102: ("audit_log_cleared", "unknown"),
    4104: ("powershell_script", "unknown"),
}


class WindowsParser(EventParser):
    id = "windows"

    def parse(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        extra = raw.get("extra") or {}
        event_id = extra.get("event_id")
        if event_id is None:
            return None
        ecs = new_ecs()
        ecs["host"] = {"name": extra.get("computer") or raw.get("host")}
        ecs["event"]["code"] = event_id
        ecs["event"]["module"] = extra.get("provider") or "windows-security"
        ts = _ts(raw.get("timestamp") or extra.get("time_created"))
        if ts:
            ecs["@timestamp"] = ts
        action, outcome = _WIN_EVENT_ACTIONS.get(int(event_id), ("unknown", "unknown"))
        ecs["event"]["action"] = action
        ecs["event"]["outcome"] = outcome
        if int(event_id) in (4624, 4625, 4634, 4647, 4672, 4768, 4769, 4771, 4776):
            ecs["event"]["category"] = ["authentication"]
            ecs["event"]["type"] = ["authentication", "start"] if outcome == "success" else ["authentication"]
            ecs["user"] = {"name": extra.get("target_user") or extra.get("user")}
            ecs["source"] = {"ip": _ip(str(extra.get("source_ip", ""))) if extra.get("source_ip") else None}
        elif int(event_id) == 4688:
            ecs["event"]["category"] = ["process"]
            ecs["event"]["type"] = ["start"]
            ecs["process"] = {
                "name": extra.get("process_name"),
                "pid": extra.get("process_id"),
                "executable": extra.get("process_path"),
                "command_line": extra.get("command_line"),
                "parent_pid": extra.get("parent_process_id"),
            }
            ecs["user"] = {"name": extra.get("user")}
        elif int(event_id) in (4720, 4724, 4732):
            ecs["event"]["category"] = ["iam"]
            ecs["event"]["type"] = ["user"]
            ecs["user"] = {"name": extra.get("target_user") or extra.get("user")}
        ecs["message"] = raw.get("message") or raw.get("raw") or ""
        ecs["pipeline"] = {"parsed": True, "parser": self.id}
        ecs["labels"] = {"log_name": extra.get("log_name"), "record_id": extra.get("record_id")}
        return ecs


# ---------------------------------------------------------------------------
# Web server (combined log format)
# ---------------------------------------------------------------------------
_COMBINED = Grok(
    r'%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "%{WORD:verb} %{URIPATHPARAM:request} HTTP/%{NUMBER:httpversion}" %{NUMBER:response} (?:%{NUMBER:bytes}|-)',
    anchors=False,
)


class WebServerParser(EventParser):
    id = "web_server"

    def parse(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        text = raw.get("message") or raw.get("raw") or ""
        m = _COMBINED.match(text, full=False)
        if not m:
            return None
        f = m.fields
        ecs = new_ecs()
        ecs["@timestamp"] = _ts(self._httpdate(f.get("timestamp")))
        ecs["source"] = {"ip": _ip(f.get("clientip", ""))}
        ecs["url"] = {"path": f.get("request"), "full": f.get("request")}
        ecs["http"] = {
            "request": {"method": f.get("verb")},
            "version": f.get("httpversion"),
            "response": {"status_code": cast_value(f.get("response"))},
        }
        ecs["network"] = {"protocol": "http"}
        ecs["event"]["category"] = ["web"]
        ecs["event"]["type"] = ["access"]
        ecs["event"]["module"] = "httpd"
        ecs["event"]["action"] = "http_request"
        ecs["host"] = {"name": raw.get("host")}
        if f.get("bytes"):
            ecs["event"]["duration"] = None
        ecs["message"] = text
        ecs["pipeline"] = {"parsed": True, "parser": self.id}
        return ecs

    @staticmethod
    def _httpdate(value: str | None) -> str | None:
        if not value:
            return None
        try:
            # 11/Aug/2026:14:23:45 +0000
            return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").astimezone(
                timezone.utc
            ).isoformat()
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Firewall (ufw / iptables style)
# ---------------------------------------------------------------------------
_UFW = Grok(
    r"%{GREEDYDATA:ts} %{HOSTNAME:host} kernel: \[\d+\.\d+\] \[%{WORD:fw_module} %{WORD:fw_action}\] IN=%{NOTSPACE:iface} OUT=%{DATA:oiface} MAC=%{NOTSPACE:mac} SRC=%{IP:src_ip} DST=%{IP:dst_ip} LEN=%{INT:len} TOS=%{NOTSPACE:tos} PREC=%{NOTSPACE:prec} TTL=%{INT:ttl} ID=%{INT:id} PROTO=%{WORD:proto} SPT=%{INT:src_port} DPT=%{INT:dst_port}",
    anchors=False,
)


class FirewallParser(EventParser):
    id = "firewall"

    def parse(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        text = raw.get("message") or raw.get("raw") or ""
        m = _UFW.match(text, full=False)
        if not m:
            return None
        f = m.fields
        ecs = new_ecs()
        ts = self._fw_ts(f.get("ts"))
        if ts:
            ecs["@timestamp"] = ts
        ecs["host"] = {"name": f.get("host") or raw.get("host")}
        ecs["source"] = {"ip": _ip(f.get("src_ip", "")), "port": cast_value(f.get("src_port"))}
        ecs["destination"] = {"ip": _ip(f.get("dst_ip", "")), "port": cast_value(f.get("dst_port"))}
        ecs["network"] = {"protocol": f.get("proto", "ip").lower()}
        blocked = f.get("fw_action", "").upper() in ("BLOCK", "DROP", "REJECT")
        ecs["event"]["category"] = ["network"]
        ecs["event"]["type"] = ["connection", "denied"] if blocked else ["connection", "allowed"]
        ecs["event"]["action"] = "firewall_block" if blocked else "firewall_allow"
        ecs["event"]["module"] = "ufw"
        ecs["event"]["outcome"] = "denied" if blocked else "allowed"
        ecs["message"] = text
        ecs["pipeline"] = {"parsed": True, "parser": self.id}
        return ecs

    @staticmethod
    def _fw_ts(value: str | None) -> str | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
                timezone.utc
            ).isoformat()
        except ValueError:
            pass
        try:
            # classic syslog: "Aug  1 12:00:00"
            parsed = datetime.strptime(value, "%b %d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
            return parsed.isoformat()
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Endpoint telemetry (network / process / service transitions from agents)
# ---------------------------------------------------------------------------
_ENDPOINT_ACTIONS = {
    "connection_new": (["network"], ["connection", "start"]),
    "connection_closed": (["network"], ["connection", "end"]),
    "listener_added": (["network"], ["connection", "info"]),
    "listener_removed": (["network"], ["connection", "info"]),
    "process_created": (["process"], ["start", "process"]),
    "process_terminated": (["process"], ["end", "process"]),
    "service_created": (["application"], ["info"]),
    "service_started": (["application"], ["start"]),
    "service_stopped": (["application"], ["end"]),
    "service_deleted": (["application"], ["info"]),
}


class EndpointTelemetryParser(EventParser):
    id = "endpoint_telemetry"

    def parse(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        extra = raw.get("extra") or {}
        action = str(extra.get("event_action") or "").lower()
        if action not in _ENDPOINT_ACTIONS:
            return None
        ecs = new_ecs()
        categories, types = _ENDPOINT_ACTIONS[action]
        ecs["event"]["category"] = categories
        ecs["event"]["type"] = types
        ecs["event"]["action"] = action
        ecs["event"]["kind"] = "event"
        ecs["event"]["module"] = "endpoint-telemetry"
        ecs["host"] = {"name": raw.get("host")}
        ecs["labels"] = {"agent_code": extra.get("agent_code")}

        network = extra.get("network") or {}
        if network:
            ecs["network"] = {
                "transport": network.get("transport"),
                "protocol": network.get("protocol"),
                "direction": network.get("direction"),
            }
        source = extra.get("source") or {}
        if source:
            ecs["source"] = {
                "ip": _ip(str(source.get("ip", ""))) if source.get("ip") else None,
                "port": source.get("port"),
            }
        destination = extra.get("destination") or {}
        if destination:
            ecs["destination"] = {
                "ip": _ip(str(destination.get("ip", ""))) if destination.get("ip") else None,
                "port": destination.get("port"),
            }
        process = extra.get("process") or {}
        if process:
            parent = process.get("parent") or {}
            ecs["process"] = {
                "name": process.get("name"),
                "pid": process.get("pid"),
                "executable": process.get("executable"),
                "command_line": process.get("command_line"),
                "parent": {
                    "pid": parent.get("pid"),
                    "name": parent.get("name"),
                },
            }
        user = extra.get("user") or {}
        if user.get("name"):
            ecs["user"] = {"name": user.get("name")}
        service = extra.get("service") or {}
        if service:
            ecs["service"] = {
                "name": service.get("name"),
                "display_name": service.get("display_name"),
                "state": service.get("state"),
                "previous_state": service.get("previous_state"),
                "start_type": service.get("start_type"),
                "account": service.get("account"),
            }
        ecs["@timestamp"] = _ts(raw.get("timestamp") or raw.get("received_at"))
        ecs["message"] = raw.get("message") or raw.get("raw") or ""
        ecs["pipeline"] = {"parsed": True, "parser": self.id}
        return ecs


# ---------------------------------------------------------------------------
# JSON passthrough
# ---------------------------------------------------------------------------
class JsonParser(EventParser):
    id = "json"

    def parse(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        text = raw.get("message") or raw.get("raw") or ""
        if not (text.strip().startswith("{") and text.strip().endswith("}")):
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        ecs = new_ecs()
        ecs["@timestamp"] = _ts(data.get("@timestamp") or data.get("timestamp") or raw.get("received_at"))
        ecs["message"] = text
        ecs["labels"] = data
        ecs["pipeline"] = {"parsed": True, "parser": self.id}
        return ecs


# ---------------------------------------------------------------------------
# Generic syslog fallback
# ---------------------------------------------------------------------------
class SyslogParser(EventParser):
    id = "syslog"

    def parse(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        text = raw.get("message") or raw.get("raw") or ""
        if not text:
            return None
        ecs = new_ecs()
        ts = _ts(raw.get("timestamp") or raw.get("received_at"))
        if ts:
            ecs["@timestamp"] = ts
        ecs["host"] = {"name": raw.get("host")}
        ecs["message"] = text
        ecs["event"]["module"] = (raw.get("extra") or {}).get("severity_name")
        ecs["labels"] = {k: v for k, v in (raw.get("extra") or {}).items()}
        ecs["pipeline"] = {"parsed": True, "parser": self.id}
        return ecs


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
_PARSERS: dict[str, EventParser] = {
    p.id: p()
    for p in (
        LinuxAuthParser,
        WindowsParser,
        WebServerParser,
        FirewallParser,
        EndpointTelemetryParser,
        JsonParser,
        SyslogParser,
    )
}

# Aliases used by agents / source config
_PARSER_ALIASES = {
    "linux": "linux_auth",
    "ssh": "linux_auth",
    "auth": "linux_auth",
    "apache": "web_server",
    "nginx": "web_server",
    "web": "web_server",
    "ufw": "firewall",
    "iptables": "firewall",
    "firewall": "firewall",
    "windows": "windows",
    "win": "windows",
    "sysmon": "windows",
    "json": "json",
    "endpoint": "endpoint_telemetry",
}


def resolve_parser(source_type: str | None, format_: str | None, hint: str | None) -> EventParser:
    """Select a parser from source metadata (deterministic priority)."""
    if hint:
        key = hint.lower().replace("-", "_")
        if key in _PARSERS:
            return _PARSERS[key]
        if key in _PARSER_ALIASES:
            return _PARSERS[_PARSER_ALIASES[key]]
    st = (source_type or "").lower()
    if st in _PARSERS:
        return _PARSERS[st]
    if st in _PARSER_ALIASES:
        return _PARSERS[_PARSER_ALIASES[st]]
    if format_ == "json" or (st == "http"):
        return _PARSERS["json"]
    return _PARSERS["syslog"]


def get_parser(parser_id: str) -> EventParser:
    return _PARSERS[parser_id]
