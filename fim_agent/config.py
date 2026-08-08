"""FIM agent configuration.

Layered, mirroring the SCA agent: defaults < YAML config file < environment
variables (< CLI flags in cli.py). The per-agent API key returned at
registration is persisted to a local file so the agent does not re-register on
every restart.

By default the agent only monitors ``C:\\FIM-Test`` (a small, dedicated
directory) - it never watches an entire drive.
"""

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

ENV_PREFIX = "FIM_AGENT_"
DEFAULT_MONITORED_PATHS = [r"C:\FIM-Test"]


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"{ENV_PREFIX}{name}", default)


@dataclass
class FimAgentConfig:
    server_url: str = "http://127.0.0.1:8000"
    api_prefix: str = "/api/v1"
    agent_code: str = "fim-win-001"
    hostname: str = ""
    ip_address: str = ""
    registration_token: str | None = None
    api_key_file: str = ""
    baseline_file: str = ""
    monitored_paths: list[str] = field(default_factory=lambda: list(DEFAULT_MONITORED_PATHS))
    exclude_patterns: list[str] = field(default_factory=lambda: ["*.tmp", "~$*", "*.swp"])
    use_watchdog: bool = True
    poll_interval: float = 5.0
    heartbeat_interval: float = 60.0
    timeout: float = 15.0
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        if not self.hostname:
            self.hostname = socket.gethostname()
        if not self.ip_address:
            self.ip_address = _guess_ip()
        if not self.api_key_file:
            self.api_key_file = os.path.join(
                os.path.expanduser("~"), f".fim-agent-{self.agent_code}.key"
            )
        if not self.baseline_file:
            self.baseline_file = os.path.join(
                os.path.expanduser("~"), f".fim-agent-{self.agent_code}.baseline.json"
            )
        self.monitored_paths = [p for p in (self.monitored_paths or []) if p]

    @property
    def base_url(self) -> str:
        return self.server_url.rstrip("/") + self.api_prefix

    # ------------------------------------------------------------------ key file
    def load_api_key(self) -> str | None:
        try:
            with open(self.api_key_file, "r", encoding="utf-8") as fh:
                value = fh.read().strip()
            return value or None
        except OSError:
            return None

    def save_api_key(self, api_key: str) -> None:
        with open(self.api_key_file, "w", encoding="utf-8") as fh:
            fh.write(api_key)
        try:
            os.chmod(self.api_key_file, 0o600)
        except OSError:
            pass

    # -------------------------------------------------------------------- yaml
    @classmethod
    def from_yaml(cls, path: str | os.PathLike) -> "FimAgentConfig":
        import yaml

        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raise ValueError("config file must contain a mapping")
        mapped = {}
        for key, value in raw.items():
            if key in ("monitored_paths", "exclude_patterns") and value is None:
                value = []
            mapped[key.replace("-", "_")] = value
        return cls(**mapped)

    @classmethod
    def from_env(cls) -> "FimAgentConfig":
        config_file = _env("CONFIG", "")
        if config_file and os.path.isfile(config_file):
            cfg = cls.from_yaml(config_file)
        else:
            cfg = cls()
        # Environment overrides the file.
        env_overrides = {
            "server_url": _env("SERVER_URL", ""),
            "api_prefix": _env("API_PREFIX", ""),
            "agent_code": _env("CODE", ""),
            "hostname": _env("HOSTNAME", ""),
            "registration_token": _env("REGISTRATION_TOKEN", ""),
            "api_key_file": _env("API_KEY_FILE", ""),
            "baseline_file": _env("BASELINE_FILE", ""),
            "timeout": _env("TIMEOUT", ""),
            "poll_interval": _env("POLL_INTERVAL", ""),
            "heartbeat_interval": _env("HEARTBEAT_INTERVAL", ""),
        }
        for name, value in env_overrides.items():
            if value:
                if name in ("timeout", "poll_interval", "heartbeat_interval"):
                    setattr(cfg, name, float(value))
                else:
                    setattr(cfg, name, value)
        paths = _env("MONITORED_PATHS", "")
        if paths:
            cfg.monitored_paths = [p.strip() for p in paths.split(";") if p.strip()]
        use_watchdog = _env("WATCHDOG", "")
        if use_watchdog:
            cfg.use_watchdog = use_watchdog.lower() not in ("0", "false", "no")
        return cfg


def _guess_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "0.0.0.0"
