"""Ingestion endpoints (function 1 - log collection)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.api.auth_deps import verify_ingest_auth
from app.api.deps import DbSession
from app.pipeline.bus import build_event_bus
from app.schemas.ingest import IngestRequest, IngestResult
from app.services.ingest_service import IngestService

router = APIRouter()


def _bus(request: Request):
    bus = getattr(request.app.state, "event_bus", None)
    if bus is None:
        bus = build_event_bus()
        request.app.state.event_bus = bus
    return bus


@router.post("/events", response_model=IngestResult)
async def ingest_events(
    payload: IngestRequest,
    request: Request,
    db: DbSession,
    _: Annotated[None, Depends(verify_ingest_auth)] = None,
) -> IngestResult:
    """Collect raw events (HTTP collector). Used by agents and integrations."""
    service = IngestService(db, _bus(request))
    return await service.ingest(payload)
