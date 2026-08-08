"""HTTP transport to the SCA manager (stdlib only).

The agent talks to ``/sca/agents/*`` endpoints: registration with the shared
registration token, then heartbeats authenticated with the one-time API key
the server returns. Secrets are sent over HTTPS when the server URL is https.
"""

import json
import urllib.error
import urllib.request

from agent.config import AgentConfig


class TransportError(Exception):
    """Raised when the SCA manager rejects or cannot answer a request."""


class ScaTransport:
    def __init__(self, config: AgentConfig) -> None:
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
        operating_system: str = "",
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
            "/sca/agents/register",
            payload={
                "agent_code": self.config.agent_code,
                "hostname": self.config.hostname,
                "operating_system": operating_system or _platform_name(),
                "platform": platform,
                "version": version,
            },
            headers=headers,
        )

    def heartbeat(self, api_key: str, status: str = "online") -> dict:
        return self._request(
            "POST",
            f"/sca/agents/{self.config.agent_code}/heartbeat",
            payload={"status": status},
            headers={"X-API-Key": api_key},
        )

    def fetch_job(self, api_key: str) -> dict:
        """Return the next evidence-collection job for this agent."""
        return self._request(
            "GET",
            f"/sca/agents/{self.config.agent_code}/jobs",
            headers={"X-API-Key": api_key},
        )

    def submit_evidence(self, api_key: str, scan_id: str, items: list[dict]) -> dict:
        """Submit collected evidence for a scan; PASS/FAIL is decided server-side."""
        return self._request(
            "POST",
            f"/sca/scans/{scan_id}/evidence",
            payload={"agent_code": self.config.agent_code, "items": items},
            headers={"X-API-Key": api_key},
        )


def _platform_name() -> str:
    import platform as _platform

    return _platform.platform()
