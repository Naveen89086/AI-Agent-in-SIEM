"""HTTP transport to the SIEM manager (stdlib only).

Talks to the IOC, vulnerability and telemetry subsystems:
- register with the shared registration token to obtain per-agent API keys,
- heartbeat all subsystems,
- submit IOC observations and software inventory,
- submit live network/process/service snapshots to the telemetry ingest API,
- submit generic telemetry to the raw-ingest API to feed detection/hunting.

Secrets travel over HTTPS when the server URL is https.
"""

import json
import urllib.error
import urllib.request

from endpoint_agent.config import EndpointAgentConfig


class TransportError(Exception):
    """Raised when the manager rejects or cannot answer a request."""


class EndpointAgentTransport:
    def __init__(self, config: EndpointAgentConfig) -> None:
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

    # -------------------------------------------------------------- registration
    def _machine_identity(self) -> dict:
        """(machine_guid, agent_code, hostname) used in every registration.

        The machine fingerprint comes from the stable identity and is never
        overridable; the agent code honors an explicit config/CLI override so
        heartbeats and ingest always target the same registered code.
        """
        return {
            "machine_guid": self.config.machine_guid,
            "agent_code": self.config.agent_code,
            "hostname": self.config.hostname,
        }

    def register_protected_endpoint(self, registration_token: str | None = None) -> dict:
        """Canonical "register this machine" flow against the single-device model."""
        import platform as _platform

        token = registration_token or self.config.registration_token
        headers = {"X-Registration-Token": token} if token else {}
        identity = self._machine_identity()
        return self._request(
            "POST",
            "/protected-endpoint/register",
            payload={
                "machine_guid": identity["machine_guid"],
                "hostname": self.config.hostname,
                "operating_system": _platform.system(),
                "os_version": _platform.version(),
                "architecture": _platform.machine(),
                "agent_version": "1.0.0",
                "ip_address": self.config.ip_address,
            },
            headers=headers,
        )

    def register_ioc(self, registration_token: str | None = None) -> dict:
        token = registration_token or self.config.registration_token
        headers = {"X-Registration-Token": token} if token else {}
        identity = self._machine_identity()
        return self._request(
            "POST",
            "/ioc/agents/register",
            payload={
                "agent_code": identity["agent_code"],
                "machine_guid": identity["machine_guid"],
                "hostname": self.config.hostname,
                "ip_address": self.config.ip_address,
                "operating_system": _platform_name(),
                "platform": _platform_family(),
                "version": "1.0.0",
            },
            headers=headers,
        )

    def register_vuln(self, registration_token: str | None = None) -> dict:
        token = registration_token or self.config.registration_token
        headers = {"X-Registration-Token": token} if token else {}
        identity = self._machine_identity()
        return self._request(
            "POST",
            "/vulnerabilities/agents/register",
            payload={
                "agent_code": identity["agent_code"],
                "machine_guid": identity["machine_guid"],
                "hostname": self.config.hostname,
                "ip_address": self.config.ip_address,
                "operating_system": _platform_name(),
                "platform": _platform_family(),
                "version": "1.0.0",
            },
            headers=headers,
        )

    def register_telemetry(self, registration_token: str | None = None) -> dict:
        token = registration_token or self.config.registration_token
        headers = {"X-Registration-Token": token} if token else {}
        identity = self._machine_identity()
        return self._request(
            "POST",
            "/telemetry/agents/register",
            payload={
                "agent_code": identity["agent_code"],
                "machine_guid": identity["machine_guid"],
                "hostname": self.config.hostname,
                "ip_address": self.config.ip_address,
                "operating_system": _platform_name(),
                "platform": _platform_family(),
                "version": "1.0.0",
            },
            headers=headers,
        )

    # --------------------------------------------------------------- heartbeats
    def heartbeat_ioc(self, api_key: str, status: str = "online") -> dict:
        return self._request(
            "POST",
            f"/ioc/agents/{self.config.agent_code}/heartbeat",
            payload={"status": status},
            headers={"X-API-Key": api_key},
        )

    def heartbeat_vuln(self, api_key: str, status: str = "online") -> dict:
        return self._request(
            "POST",
            f"/vulnerabilities/agents/{self.config.agent_code}/heartbeat",
            payload={"status": status},
            headers={"X-API-Key": api_key},
        )

    def heartbeat_telemetry(self, api_key: str, status: str = "online") -> dict:
        return self._request(
            "POST",
            f"/telemetry/agents/{self.config.agent_code}/heartbeat",
            payload={"status": status},
            headers={"X-API-Key": api_key},
        )

    # ------------------------------------------------------------------ payloads
    def submit_observations(self, api_key: str, observations: list[dict]) -> dict:
        return self._request(
            "POST",
            "/ioc/ingest",
            payload={"agent_code": self.config.agent_code, "observations": observations},
            headers={"X-API-Key": api_key},
        )

    def submit_inventory(self, api_key: str, items: list[dict]) -> dict:
        return self._request(
            "POST",
            "/vulnerabilities/inventory",
            payload={"agent_code": self.config.agent_code, "items": items},
            headers={"X-API-Key": api_key},
        )

    def submit_telemetry(self, events: list[dict]) -> dict:
        # Raw ingest accepts a batch of events via the ingest API.
        return self._request(
            "POST",
            "/ingest/events",
            payload={"events": events},
        )

    def submit_telemetry_snapshot(
        self,
        api_key: str,
        snapshot: dict,
        *,
        demo: bool = False,
    ) -> dict:
        """Submit a network/process/service snapshot; demo always labeled."""
        return self._request(
            "POST",
            "/telemetry/ingest",
            payload={
                "agent_code": self.config.agent_code,
                "demo": demo,
                "collected_at": snapshot.get("collected_at"),
                "network": snapshot.get("network", {}),
                "processes": snapshot.get("processes", []),
                "services": snapshot.get("services", []),
            },
            headers={"X-API-Key": api_key},
        )


def _platform_name() -> str:
    import platform as _platform

    return _platform.platform()


def _platform_family() -> str:
    import platform as _platform

    system = _platform.system().lower()
    return {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(system, "unknown")
