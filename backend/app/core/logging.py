"""Structured logging setup.

Emits JSON lines when running in production (log aggregation friendly) and
readable console output during development. Also provides a small audit
logger used for security-relevant actions.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings

_RESERVED = {"message", "asctime", "levelname", "name", "exc_info", "exc_text"}


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("event_id", "host", "rule_id", "alert_id", "user", "action"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    if settings.is_production:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
            )
        )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO if settings.is_production else logging.DEBUG)
    # Keep third-party logs quieter.
    for noisy in ("uvicorn.access", "httpx", "elastic_transport"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


class AuditLogger:
    """Writes immutable audit trail records for sensitive operations."""

    def __init__(self) -> None:
        self._logger = logging.getLogger("siem.audit")

    def log(
        self,
        action: str,
        *,
        actor: str | None = None,
        resource: str | None = None,
        resource_id: str | None = None,
        **context: Any,
    ) -> None:
        self._logger.info(
            "%s %s %s",
            action,
            resource or "",
            resource_id or "",
            extra={
                "action": action,
                "user": actor,
                "event_id": resource_id,
                **context,
            },
        )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


audit = AuditLogger()
