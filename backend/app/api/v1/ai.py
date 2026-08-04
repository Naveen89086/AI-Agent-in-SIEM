"""AI agent API (function 6)."""

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, DbSession
from app.schemas.ai import (
    AgentResponseOut,
    AnalysisRead,
    AnalyzeAlertRequest,
    ChatRequest,
    SummarizeIncidentRequest,
)
from app.services.agent_service import AgentService

router = APIRouter()


def _service(db) -> AgentService:
    return AgentService(db)


@router.post("/analyze-alert", response_model=AgentResponseOut)
async def analyze_alert(
    payload: AnalyzeAlertRequest,
    user: AnalystOrAdmin,
    db: DbSession,
) -> AgentResponseOut:
    response, _ = await _service(db).analyze_alert(payload.alert_id)
    return AgentResponseOut(
        analysis=response.analysis,
        summary=response.summary,
        mitre=response.mitre or [],
        recommended_actions=response.recommended_actions or [],
        risk_score=response.risk_score or 0.0,
        confidence=response.confidence or 0.0,
        provider=response.provider,
    )


@router.post("/summarize-incident", response_model=AgentResponseOut)
async def summarize_incident(
    payload: SummarizeIncidentRequest,
    user: AnalystOrAdmin,
    db: DbSession,
) -> AgentResponseOut:
    response, _ = await _service(db).summarize_incident(payload.alert_ids, payload.context or "")
    return AgentResponseOut(
        analysis=response.analysis,
        summary=response.summary,
        mitre=response.mitre or [],
        recommended_actions=response.recommended_actions or [],
        risk_score=response.risk_score or 0.0,
        confidence=response.confidence or 0.0,
        provider=response.provider,
    )


@router.post("/chat", response_model=dict)
async def chat(
    payload: ChatRequest,
    user: AnalystOrAdmin,
    db: DbSession,
) -> dict:
    answer = await _service(db).chat(payload.message, payload.alert_id)
    return {"reply": answer}


@router.get("/analyses", response_model=list[AnalysisRead])
def list_analyses(
    user: AnalystOrAdmin,
    db: DbSession,
    alert_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[AnalysisRead]:
    return list(_service(db).list_analyses(alert_id=alert_id, limit=limit))


@router.get("/analyses/{analysis_id}", response_model=AnalysisRead)
def get_analysis(
    analysis_id: str,
    user: AnalystOrAdmin,
    db: DbSession,
) -> AnalysisRead:
    return _service(db).get(analysis_id)
