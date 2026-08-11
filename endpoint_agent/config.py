"""Endpoint agent configuration.

Layered: defaults < YAML config file < environment variables < CLI flags.
The per-agent API keys returned at registration are persisted to local files so
the agent does not re-register on every restart.

Collection is deliberately bounded and incremental:
- ``inventory`` scans are cached and only re-sent when the snapshot changes
  (compare hash of the serialized inventory).
- observations (network connections / processes) are capped per cycle and
  deduplicated against a small local history file.
- no full-disk hashing, no expensive Windows commands every cycle.
"""

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

ENV_PREFIX = "ENDPOINT_AGENT_"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"{ENV_PREFIX}{name}", default)


@dataclass
class EndpointAgentConfig:
    server_url: str = "http://127.0.0.1:8000"
    api_prefix: str = "/api/v1"
    # Stable per-machine code derived from the machine fingerprint. An explicit
    # value (YAML/env/CLI) overrides the derivation.
    agent_code: str = ""
    # Stable machine fingerprint (Windows MachineGuid) read at startup.
    machine_guid: str = ""
    hostname: str = ""
    ip_address: str = ""
    # Shared registration token; can be omitted when an admin JWT registers.
    registration_token: str | None = None
    # Separate API keys for the IOC and vulnerability subsystems.
    ioc_api_key_file: str = ""
    vuln_api_key_file: str = ""
    # API key for the network + process/service telemetry subsystem.
    telemetry_api_key_file: str = ""
    # Where the agent stores the last inventory snapshot (for change detection).
    inventory_cache_file: str = ""
    # Where the agent keeps recently reported indicator values (dedupe).
    observation_history_file: str = ""
    # Where the agent stores the last telemetry snapshot fingerprint (dedupe).
    telemetry_cache_file: str = ""

    # --- collection knobs -----------------------------------------------------
    # Maximum observations (network connections / processes) per cycle.
    max_observations: int = 50
    # Only report outbound connections to non-private addresses.
    skip_private_ips: bool = True
    # Poll intervals (seconds). Inventory is much less frequent than telemetry.
    inventory_interval: int = 3600
    observation_interval: int = 60
    heartbeat_interval: int = 60
    timeout: float = 15.0
    log_level: str = "INFO"

    # --- telemetry knobs ------------------------------------------------------
    # Maximum rows sent per network/process/service snapshot block.
    max_connections: int = 1000
    max_listeners: int = 500
    # Poll intervals (seconds) for the live-state collectors.
    network_interval: int = 5
    process_interval: int = 5
    service_interval: int = 15
    # Independent demo switches for the telemetry collectors (dev/tests only).
    network_demo: bool = False
    process_demo: bool = False
    service_demo: bool = False

    # --- collection modes -----------------------------------------------------
    # When true, collectors use the built-in *demo* corpus instead of live
    # system collection. Used for dev/tests; never labeled as real data.
    demo: bool = False

    def __post_init__(self) -> None:
        if not self.machine_guid:
            from endpoint_agent.identity import machine_guid

            self.machine_guid = machine_guid()
        if not self.agent_code:
            from endpoint_agent.identity import derive_agent_code

            self.agent_code = derive_agent_code(self.machine_guid)
        if not self.hostname:
            self.hostname = socket.gethostname()
        if not self.ip_address:
            self.ip_address = _guess_ip()
        home = Path(os.path.expanduser("~"))
        if not self.ioc_api_key_file:
            self.ioc_api_key_file = str(home / f".endpoint-agent-{self.agent_code}.ioc.key")
        if not self.vuln_api_key_file:
            self.vuln_api_key_file = str(home / f".endpoint-agent-{self.agent_code}.vuln.key")
        if not self.telemetry_api_key_file:
            self.telemetry_api_key_file = str(home / f".endpoint-agent-{self.agent_code}.telemetry.key")
        if not self.inventory_cache_file:
            self.inventory_cache_file = str(home / f".endpoint-agent-{self.agent_code}.inventory.json")
        if not self.observation_history_file:
            self.observation_history_file = str(home / f".endpoint-agent-{self.agent_code}.observed.json")
        if not self.telemetry_cache_file:
            self.telemetry_cache_file = str(home / f".endpoint-agent-{self.agent_code}.telemetry.json")

    @property
    def base_url(self) -> str:
        return self.server_url.rstrip("/") + self.api_prefix

    # ----------------------------------------------------------------- key files
    def load_ioc_api_key(self) -> str | None:
        return _read_key(self.ioc_api_key_file)

    def save_ioc_api_key(self, api_key: str) -> None:
        _write_key(self.ioc_api_key_file, api_key)

    def load_vuln_api_key(self) -> str | None:
        return _read_key(self.vuln_api_key_file)

    def save_vuln_api_key(self, api_key: str) -> None:
        _write_key(self.vuln_api_key_file, api_key)

    def load_telemetry_api_key(self) -> str | None:
        return _read_key(self.telemetry_api_key_file)

    def save_telemetry_api_key(self, api_key: str) -> None:
        _write_key(self.telemetry_api_key_file, api_key)

    # ------------------------------------------------------------------- caches
    def load_telemetry_cache(self) -> str | None:
        try:
            with open(self.telemetry_cache_file, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return None

    def save_telemetry_cache(self, content: str) -> None:
        with open(self.telemetry_cache_file, "w", encoding="utf-8") as fh:
            fh.write(content)
    def load_inventory_cache(self) -> str | None:
        try:
            with open(self.inventory_cache_file, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return None

    def save_inventory_cache(self, content: str) -> None:
        with open(self.inventory_cache_file, "w", encoding="utf-8") as fh:
            fh.write(content)

    def load_observation_history(self) -> set[str]:
        try:
            with open(self.observation_history_file, "r", encoding="utf-8") as fh:
                return set(line.strip() for line in fh if line.strip())
        except OSError:
            return set()

    def save_observation_history(self, values: set[str]) -> None:
        with open(self.observation_history_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(values)))

    # -------------------------------------------------------------------- yaml
    @classmethod
    def from_yaml(cls, path: str | os.PathLike) -> "EndpointAgentConfig":
        import yaml

        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raise ValueError("config file must contain a mapping")
        mapped = {k.replace("-", "_"): v for k, v in raw.items()}
        return cls(**mapped)

    @classmethod
    def from_env(cls) -> "EndpointAgentConfig":
        config_file = _env("CONFIG", "")
        if config_file and os.path.isfile(config_file):
            cfg = cls.from_yaml(config_file)
        else:
            cfg = cls()
        env_overrides = {
            "server_url": _env("SERVER_URL", ""),
            "api_prefix": _env("API_PREFIX", ""),
            "agent_code": _env("CODE", ""),
            "hostname": _env("HOSTNAME", ""),
            "registration_token": _env("REGISTRATION_TOKEN", ""),
            "ioc_api_key_file": _env("IOC_API_KEY_FILE", ""),
            "vuln_api_key_file": _env("VULN_API_KEY_FILE", ""),
            "telemetry_api_key_file": _env("TELEMETRY_API_KEY_FILE", ""),
            "inventory_cache_file": _env("INVENTORY_CACHE_FILE", ""),
            "observation_history_file": _env("OBSERVATION_HISTORY_FILE", ""),
            "telemetry_cache_file": _env("TELEMETRY_CACHE_FILE", ""),
            "timeout": _env("TIMEOUT", ""),
        }
        for name, value in env_overrides.items():
            if value:
                setattr(cfg, name, float(value) if name == "timeout" else value)
        for int_name in ("max_observations", "inventory_interval", "observation_interval", "heartbeat_interval", "max_connections", "max_listeners", "network_interval", "process_interval", "service_interval"):
            value = _env(int_name.upper(), "")
            if value:
                setattr(cfg, int_name, int(value))
        skip = _env("SKIP_PRIVATE_IPS", "")
        if skip:
            cfg.skip_private_ips = skip.lower() not in ("0", "false", "no")
        demo = _env("DEMO", "")
        if demo:
            cfg.demo = demo.lower() in ("1", "true", "yes")
        for bool_name in ("network_demo", "process_demo", "service_demo"):
            value = _env(bool_name.upper(), "")
            if value:
                setattr(cfg, bool_name, value.lower() in ("1", "true", "yes"))
        return cfg


def _read_key(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
        return value or None
    except OSError:
        return None


def _write_key(path: str, api_key: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(api_key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _guess_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "0.0.0.0"
