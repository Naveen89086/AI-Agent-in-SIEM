"""Data source registry endpoints."""

from fastapi import APIRouter, Query

from app.api.deps import AnalystOrAdmin, DbSession
from app.api.responses import Page, paginate
from app.models.data_source import DataSource
from app.schemas.ingest import DataSourceCreate, DataSourceRead
from app.services.data_source_service import DataSourceService

router = APIRouter()


@router.get("", response_model=Page[DataSourceRead])
def list_sources(
    user: AnalystOrAdmin,
    db: DbSession,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    sources, total = DataSourceService(db).list(offset=offset, limit=limit)
    return paginate(sources, total, offset, limit)


@router.post("", response_model=DataSourceRead, status_code=201)
def create_source(payload: DataSourceCreate, user: AnalystOrAdmin, db: DbSession) -> DataSource:
    return DataSourceService(db).create(payload)


@router.get("/{source_id}", response_model=DataSourceRead)
def get_source(source_id: str, user: AnalystOrAdmin, db: DbSession) -> DataSource:
    return DataSourceService(db).get(source_id)


@router.patch("/{source_id}", response_model=DataSourceRead)
def update_source(
    source_id: str, payload: DataSourceCreate, user: AnalystOrAdmin, db: DbSession
) -> DataSource:
    return DataSourceService(db).update(source_id, payload)


@router.post("/{source_id}/toggle", response_model=DataSourceRead)
def toggle_source(
    source_id: str, enabled: bool, user: AnalystOrAdmin, db: DbSession
) -> DataSource:
    return DataSourceService(db).toggle(source_id, enabled)
