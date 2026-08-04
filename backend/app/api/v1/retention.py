"""Retention & storage endpoints (function 9)."""

from fastapi import APIRouter

from app.api.deps import AnalystOrAdmin
from app.services.retention_service import RetentionService

router = APIRouter()


@router.get("/status", response_model=dict)
def retention_status(user: AnalystOrAdmin) -> dict:
    return RetentionService().status()


@router.post("/run", response_model=dict)
async def run_retention(user: AnalystOrAdmin) -> dict:
    return await RetentionService().run()


@router.post("/snapshot", response_model=dict)
async def create_snapshot(user: AnalystOrAdmin) -> dict:
    return await RetentionService().snapshot()
