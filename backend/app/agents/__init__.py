"""AI agent providers package."""

import logging

from app.agents.base import AgentProvider
from app.core.config import settings

log = logging.getLogger("siem.agent")


def build_provider() -> AgentProvider:
    """Construct the configured AI provider, falling back to heuristic."""
    from app.agents.heuristic import HeuristicProvider

    kind = settings.ai_provider
    if kind in ("openai", "groq", "ollama"):
        try:
            from app.agents.llm_provider import LlmProvider

            return LlmProvider(kind)
        except Exception as exc:
            log.warning("AI provider '%s' unavailable (%s); using heuristic", kind, exc)
    return HeuristicProvider()


__all__ = ["AgentProvider", "build_provider"]
