"""Agent configuration.

Environment variables (12-factor), overridable with CLI flags. The API key
returned at registration is persisted to a local file (0o600 on POSIX) so the
agent does not need to re-register on every restart.
"""

import os
import socket
from dataclasses import dataclass

_ENV_PREFIX = "SCA_AGENT_"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"{_ENV_PREFIX}{name}", default)


@dataclass
class AgentConfig:
    server_url: str = "http://127.0.0.1:8000"
    api_prefix: str = "/api/v1"
    agent_code: str = "local-agent"
    hostname: str = ""
    registration_token: str | None = None
    api_key_file: str = ""
    heartbeat_interval: float = 60.0
    timeout: float = 15.0

    def __post_init__(self) -> None:
        if not self.hostname:
            self.hostname = socket.gethostname()
        if not self.api_key_file:
            self.api_key_file = os.path.join(
                os.path.expanduser("~"), f".sca-agent-{self.agent_code}.key"
            )

    @property
    def base_url(self) -> str:
        return self.server_url.rstrip("/") + self.api_prefix

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

    @classmethod
    def from_env(cls) -> "AgentConfig":
        return cls(
            server_url=_env("SERVER_URL", "http://127.0.0.1:8000"),
            api_prefix=_env("API_PREFIX", "/api/v1"),
            agent_code=_env("CODE", "local-agent"),
            hostname=_env("HOSTNAME", "") or socket.gethostname(),
            registration_token=_env("REGISTRATION_TOKEN", "") or None,
            api_key_file=_env("API_KEY_FILE", ""),
            heartbeat_interval=float(_env("HEARTBEAT_INTERVAL", "60")),
            timeout=float(_env("TIMEOUT", "15")),
        )
