"""AI agent service (function 6).

Fetches alert data, invokes the configured agent provider (with heuristic
fallback on any failure), and persists analyses for the audit trail.
"""

import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents import build_provider
from app.agents.base import AgentProvider, AgentResponse
from app.core.exceptions import NotFoundError
from app.models.analysis import Analysis
from app.models.alert import Alert

log = logging.getLogger("siem.agent")


class AgentService:
    def __init__(self, db: Session, provider: AgentProvider | None = None) -> None:
        self.db = db
        self.provider = provider or build_provider()

    # ---------------------------------------------------------------- helpers
    def _alert_dict(self, alert: Alert) -> dict[str, Any]:
        from app.services.alert_service import _to_dict

        return _to_dict(alert)

    def _store(
        self,
        *,
        kind: str,
        alert_id: str | None,
        prompt: str | None,
        response: AgentResponse,
    ) -> Analysis:
        record = Analysis(
            kind=kind,
            alert_id=alert_id,
            provider=response.provider,
            prompt=prompt,
            analysis=response.analysis,
            summary=response.summary,
            mitre=json.dumps(response.mitre) if response.mitre else None,
            recommended_actions=json.dumps(response.recommended_actions) if response.recommended_actions else None,
            risk_score=response.risk_score,
            confidence=response.confidence,
            response=json.dumps(response.extra, default=str) if response.extra else None,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    # -------------------------------------------------------------- operations
    async def analyze_alert(self, alert_id: str) -> tuple[AgentResponse, Analysis]:
        alert = self.db.get(Alert, alert_id)
        if alert is None:
            raise NotFoundError(f"Alert {alert_id} not found")
        payload = self._alert_dict(alert)
        try:
            response = await self.provider.analyze_alert(payload)
        except Exception:
            log.exception("AI analyze failed for alert %s; falling back to heuristic", alert_id)
            from app.agents.heuristic import HeuristicProvider

            response = await HeuristicProvider().analyze_alert(payload)
        record = self._store(
            kind="alert_analysis",
            alert_id=alert_id,
            prompt=json.dumps({"alert_id": alert_id}),
            response=response,
        )
        return response, record

    async def summarize_incident(
        self, alert_ids: list[str], context: str = ""
    ) -> tuple[AgentResponse, Analysis]:
        alerts: list[dict[str, Any]] = []
        for alert_id in alert_ids:
            alert = self.db.get(Alert, alert_id)
            if alert is not None:
                alerts.append(self._alert_dict(alert))
        if not alerts:
            raise NotFoundError("None of the provided alert ids exist")
        try:
            response = await self.provider.summarize_incident(alerts, context)
        except Exception:
            log.exception("AI summarize failed; falling back to heuristic")
            from app.agents.heuristic import HeuristicProvider

            response = await HeuristicProvider().summarize_incident(alerts, context)
        record = self._store(
            kind="incident_summary",
            alert_id=alert_ids[0],
            prompt=json.dumps({"alert_ids": alert_ids, "context": context}),
            response=response,
        )
        return response, record

    async def chat(self, message: str, alert_id: str | None = None) -> str:
        context: dict[str, Any] = {}
        if alert_id:
            alert = self.db.get(Alert, alert_id)
            if alert is None:
                raise NotFoundError(f"Alert {alert_id} not found")
            context["alert"] = self._alert_dict(alert)
        try:
            answer = await self.provider.chat(message, context)
        except Exception:
            log.exception("AI chat failed; falling back to heuristic")
            from app.agents.heuristic import HeuristicProvider

            answer = await HeuristicProvider().chat(message, context)
        self._store(
            kind="chat",
            alert_id=alert_id,
            prompt=message,
            response=AgentResponse(analysis=answer, provider=self.provider.provider_name),
        )
        return answer

    # ---------------------------------------------------------------- queries
    def list_analyses(self, *, alert_id: str | None = None, limit: int = 50) -> list[Analysis]:
        query = select(Analysis).order_by(Analysis.created_at.desc())
        if alert_id:
            query = query.where(Analysis.alert_id == alert_id)
        return list(self.db.execute(query.limit(limit)).scalars().all())

    def get(self, analysis_id: str) -> Analysis:
        record = self.db.get(Analysis, analysis_id)
        if record is None:
            raise NotFoundError(f"Analysis {analysis_id} not found")
        return record
