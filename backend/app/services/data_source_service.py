"""Data source registry service."""

import json
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError
from app.models.data_source import DataSource
from app.schemas.ingest import DataSourceCreate, DataSourceRead


class DataSourceService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list(self, offset: int = 0, limit: int = 50) -> tuple[list[DataSource], int]:
        total = self.db.scalar(select(func.count(DataSource.id))) or 0
        query = select(DataSource).order_by(DataSource.created_at)
        sources = list(self.db.scalars(query.offset(offset).limit(limit)).all())
        return sources, total

    def get(self, source_id: str) -> DataSource:
        source = self.db.get(DataSource, source_id)
        if source is None:
            raise NotFoundError("Data source not found")
        return source

    def create(self, data: DataSourceCreate) -> DataSource:
        if self.db.scalar(select(DataSource).where(DataSource.name == data.name)):
            raise ConflictError(f"Data source '{data.name}' already exists")
        source = DataSource(
            name=data.name,
            source_type=data.source_type,
            format=data.format,
            parser=data.parser,
            host=data.host,
            enabled=data.enabled,
            config=json.dumps(data.config),
        )
        self.db.add(source)
        self.db.commit()
        self.db.refresh(source)
        return source

    def update(self, source_id: str, data: DataSourceCreate) -> DataSource:
        source = self.get(source_id)
        source.name = data.name
        source.source_type = data.source_type
        source.format = data.format
        source.parser = data.parser
        source.host = data.host
        source.enabled = data.enabled
        source.config = json.dumps(data.config)
        self.db.commit()
        self.db.refresh(source)
        return source

    def toggle(self, source_id: str, enabled: bool) -> DataSource:
        source = self.get(source_id)
        source.enabled = enabled
        self.db.commit()
        self.db.refresh(source)
        return source

    def touch(self, source_id: str) -> None:
        source = self.get(source_id)
        source.last_seen_at = datetime.now(timezone.utc)
        self.db.commit()
