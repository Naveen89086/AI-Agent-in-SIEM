"""SIEM Platform - FastAPI application entrypoint."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.api.middleware import RequestContextMiddleware
from app.api.v1 import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.health import health_report
from app.core.logging import setup_logging
from app.db.base import Base
from app.db.session import SessionLocal, engine

setup_logging()


DEFAULT_SECRET_KEY = "change-me-to-a-long-random-string"


def verify_startup_config(cfg=settings) -> None:
    """Raise on unsafe production configurations before the app starts."""
    if cfg.is_production and cfg.secret_key == DEFAULT_SECRET_KEY:
        raise RuntimeError(
            "Refusing to start in production with the default SECRET_KEY. "
            "Set SECRET_KEY to a long random value."
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Hardening: never boot in production with the default secret key.
    verify_startup_config()

    # Ensure runtime directories exist.
    import os

    for path in (
        "./data",
        "./data/events",
        settings.ml_model_dir,
        settings.yara_rules_dir,
        "./data/reports",
    ):
        os.makedirs(path, exist_ok=True)

    # Create tables in dev/test; production uses Alembic migrations.
    if not settings.is_production:
        Base.metadata.create_all(bind=engine)

    # Bootstrap the initial administrator account.
    from app.services.auth_service import bootstrap_admin

    with SessionLocal() as db:
        bootstrap_admin(db)

    yield


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description=(
        "AI Agent-Enhanced Endpoint SIEM - real-time threat detection, "
        "alerting, automated incident response and compliance reporting."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.api_v1_prefix}/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(RequestContextMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
    return response


register_exception_handlers(app)

app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", tags=["System"])
def health() -> dict:
    return health_report()
