"""Remote LLM agent provider (function 6).

OpenAI-compatible chat-completions client - works with OpenAI, Groq and
Ollama by pointing base_url/api_key at the right service. The model is asked
for a strict JSON analysis of the alert/incident; any failure raises so the
AgentService can fall back to the offline heuristic provider.
"""

import json
import logging
from typing import Any

import httpx

from app.agents.base import AgentProvider, AgentResponse
from app.core.config import settings

log = logging.getLogger("siem.agent.llm")

_ANALYZE_SYSTEM = (
    "You are a senior SOC analyst. Given an SIEM alert (as JSON), return STRICT JSON "
    'with keys: "analysis" (string, 3-6 sentences), "summary" (string), '
    '"mitre" (array of {tactic, technique, technique_name}), '
    '"recommended_actions" (array of strings), "risk_score" (float 0-10), '
    '"confidence" (float 0-1). No prose outside the JSON.'
)

_SUMMARIZE_SYSTEM = (
    "You are a senior SOC analyst. Given a JSON array of correlated SIEM alerts "
    'forming one incident, return STRICT JSON with keys: "analysis" (string), '
    '"summary" (string), "mitre" (array), "recommended_actions" (array), '
    '"risk_score" (float 0-10), "confidence" (float 0-1). No prose outside the JSON.'
)


_SCA_SYSTEM = (
    "You are a security configuration analyst. Given a failed configuration "
    'check (as JSON), return STRICT JSON with keys: "analysis" (string, 3-6 '
    'sentences), "summary" (string), "recommended_actions" (array of strings), '
    '"risk_score" (float 0-10), "confidence" (float 0-1), and "priority" '
    "(integer 0-4). No prose outside the JSON."
)

_HUNT_SYSTEM = (
    "You are a threat hunter. Given the results of a hunt query against a SIEM "
    'event store (as JSON), return STRICT JSON with keys: "analysis" (string, '
    '3-6 sentences), "summary" (string), "mitre" (array of {tactic, technique, '
    'technique_name}), "recommended_actions" (array of strings), "risk_score" '
    "(float 0-10), \"confidence\" (float 0-1). No prose outside the JSON."
)


class LlmProvider(AgentProvider):
    provider_name = "llm"

    def __init__(self, provider: str | None = None) -> None:
        self.kind = (provider or settings.ai_provider).lower()
        self.base_url, self.api_key, self.model = self._endpoint(self.kind)
        if not self.api_key and self.kind in ("openai", "groq"):
            raise ValueError(f"AI provider '{self.kind}' requires an API key")

    @staticmethod
    def _endpoint(kind: str) -> tuple[str, str | None, str]:
        if kind == "openai":
            return (
                settings.openai_base_url or "https://api.openai.com/v1",
                settings.openai_api_key,
                settings.openai_model,
            )
        if kind == "groq":
            return (
                "https://api.groq.com/openai/v1",
                settings.groq_api_key,
                settings.groq_model,
            )
        if kind == "ollama":
            return (
                f"{settings.ollama_base_url}/v1",
                None,
                settings.ollama_model,
            )
        raise ValueError(f"Unsupported AI provider: {kind}")

    async def _complete(self, system: str, user: str) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        async with httpx.AsyncClient(timeout=settings.ai_timeout_seconds) as client:
            response = await client.post(
                f"{self.base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
        start, end = content.find("{"), content.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("LLM response contained no JSON object")
        data = json.loads(content[start : end + 1])
        return data

    async def analyze_alert(self, alert: dict[str, Any]) -> AgentResponse:
        data = await self._complete(_ANALYZE_SYSTEM, json.dumps(alert, default=str))
        return self._to_response(data)

    async def summarize_incident(
        self, alerts: list[dict[str, Any]], context: str = ""
    ) -> AgentResponse:
        user = json.dumps({"alerts": alerts, "analyst_context": context}, default=str)
        data = await self._complete(_SUMMARIZE_SYSTEM, user)
        return self._to_response(data)

    async def chat(self, prompt: str, context: dict[str, Any] | None = None) -> str:
        system = "You are a helpful SOC analyst assistant. Answer concisely and practically."
        user = prompt
        if context:
            user += "\n\nContext: " + json.dumps(context, default=str)
        data = await self._complete(system, user)
        return str(data.get("analysis") or data.get("summary") or "")

    async def analyze_sca_check(self, context: dict[str, Any]) -> AgentResponse:
        data = await self._complete(_SCA_SYSTEM, json.dumps(context, default=str))
        response = self._to_response(data)
        response.extra["priority"] = data.get("priority")
        return response

    async def analyze_hunt(self, context: dict[str, Any]) -> AgentResponse:
        data = await self._complete(_HUNT_SYSTEM, json.dumps(context, default=str))
        return self._to_response(data)

    @staticmethod
    def _to_response(data: dict[str, Any]) -> AgentResponse:
        return AgentResponse(
            analysis=str(data.get("analysis", "")),
            summary=str(data.get("summary", "")),
            mitre=list(data.get("mitre", []) or []),
            recommended_actions=list(data.get("recommended_actions", []) or []),
            risk_score=float(data.get("risk_score", 0.0)),
            confidence=float(data.get("confidence", 0.0)),
            provider="llm",
        )
