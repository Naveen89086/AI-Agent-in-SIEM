"""Component health checks (module 7).

Each check is isolated so one failing dependency does not prevent the others
from reporting. Used by the /health endpoint.
"""

import logging
from typing import Callable

from app.core.config import settings

log = logging.getLogger("siem.health")


def _check_db() -> tuple[bool, str]:
    try:
        from app.db.session import SessionLocal
        from sqlalchemy import text

        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return True, "ok"
    except Exception as exc:  # pragma: no cover - infra dependent
        return False, str(exc)


def _check_bus() -> tuple[bool, str]:
    try:
        from app.pipeline.bus import build_event_bus

        bus = build_event_bus()
        return True, f"ok ({type(bus).__name__})"
    except Exception as exc:  # pragma: no cover - infra dependent
        return False, str(exc)


def _check_log_store() -> tuple[bool, str]:
    try:
        from app.storage.base import build_log_store

        store = build_log_store()
        if hasattr(store, "healthcheck") and callable(getattr(store, "healthcheck")):
            ok, detail = store.healthcheck()
            return ok, detail
        return True, f"ok ({type(store).__name__})"
    except Exception as exc:  # pragma: no cover - infra dependent
        return False, str(exc)


_CHECKS: dict[str, Callable[[], tuple[bool, str]]] = {
    "database": _check_db,
    "event_bus": _check_bus,
    "log_store": _check_log_store,
}


def health_report() -> dict:
    components: dict[str, dict] = {}
    for name, check in _CHECKS.items():
        ok, detail = check()
        components[name] = {"status": "ok" if ok else "degraded", "detail": detail}
    healthy = all(component["status"] == "ok" for component in components.values())
    return {
        "status": "ok" if healthy else "degraded",
        "app": settings.app_name,
        "env": settings.app_env,
        "version": "1.0.0",
        "components": components,
    }
