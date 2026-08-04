"""Log data source model (function 1 registry)."""

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class DataSource(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A registered log source feeding the SIEM."""

    __tablename__ = "data_sources"

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # syslog|http|file|endpoint
    format: Mapped[str] = mapped_column(String(32), default="syslog", nullable=False)  # syslog|json|keyvalue
    parser: Mapped[str | None] = mapped_column(String(64), nullable=True)  # parser id hint
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    received_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    config: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON config blob

    def __repr__(self) -> str:
        return f"<DataSource {self.name} ({self.source_type})>"
