"""AI agent contracts (function 6).

Every provider - offline heuristic or remote LLM - returns the same
structured AgentResponse so downstream consumers (analyst UI, SOAR) never
depend on which provider produced the analysis.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentResponse:
    analysis: str
    summary: str = ""
    mitre: list[dict[str, str]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    risk_score: float = 0.0  # 0..10
    confidence: float = 0.0  # 0..1
    provider: str = "heuristic"
    extra: dict[str, Any] = field(default_factory=dict)


class AgentProvider:
    """Abstract AI analyst. Subclasses implement analyze/summarize/chat."""

    provider_name = "base"

    async def analyze_alert(self, alert: dict[str, Any]) -> AgentResponse:
        raise NotImplementedError

    async def summarize_incident(
        self, alerts: list[dict[str, Any]], context: str = ""
    ) -> AgentResponse:
        raise NotImplementedError

    async def analyze_sca_check(self, context: dict[str, Any]) -> AgentResponse:
        raise NotImplementedError

    async def analyze_hunt(self, context: dict[str, Any]) -> AgentResponse:
        raise NotImplementedError

    async def chat(self, prompt: str, context: dict[str, Any] | None = None) -> str:
        raise NotImplementedError
