"""HTTP transport to the FIM manager (stdlib only).

The agent talks to ``/api/v1/fim/*``: registration with the shared
registration token, heartbeats and SHA-256 evidence submissions authenticated
with the one-time per-agent API key. Secrets travel over HTTPS when the
server URL is https.
"""

import json
import urllib.error
import urllib.request

from fim_agent.config import FimAgentConfig


class TransportError(Exception):
    """Raised when the FIM manager rejects or cannot answer a request."""


class FimTransport:
    def __init__(self, config: FimAgentConfig) -> None:
        self.config = config

    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict:
        url = self.config.base_url + path
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url, data=body, method=method, headers={"Content-Type": "application/json"}
        )
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8")
            except Exception:
                pass
            raise TransportError(f"HTTP {exc.code} from {url}: {detail[:300]}")
        except urllib.error.URLError as exc:
            raise TransportError(f"cannot reach {url}: {exc.reason}")
        if not raw.strip():
            return {}
        return json.loads(raw)

    def register(
        self,
        *,
        os_name: str = "",
        platform: str = "windows",
        version: str = "1.0.0",
        registration_token: str | None = None,
    ) -> dict:
        headers: dict[str, str] = {}
        token = registration_token or self.config.registration_token
        if token:
            headers["X-Registration-Token"] = token
        return self._request(
            "POST",
            "/fim/agents/register",
            payload={
                "agent_code": self.config.agent_code,
                "hostname": self.config.hostname,
                "ip_address": self.config.ip_address,
                "os_name": os_name or _platform_name(),
                "platform": platform,
                "version": version,
            },
            headers=headers,
        )

    def heartbeat(self, api_key: str, status: str = "online") -> dict:
        return self._request(
            "POST",
            f"/fim/agents/{self.config.agent_code}/heartbeat",
            payload={"status": status},
            headers={"X-API-Key": api_key},
        )

    def ingest(self, api_key: str, payload: dict) -> dict:
        return self._request(
            "POST",
            "/fim/ingest",
            payload=payload,
            headers={"X-API-Key": api_key},
        )


def _platform_name() -> str:
    import platform as _platform

    return _platform.platform()
