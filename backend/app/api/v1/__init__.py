"""API v1 package."""

from fastapi import APIRouter

from app.api.v1.ai import router as ai_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.auth import router as auth_router
from app.api.v1.cases import router as cases_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.fim import router as fim_router
from app.api.v1.ingest import router as ingest_router
from app.api.v1.meta import router as meta_router
from app.api.v1.policies import router as policies_router
from app.api.v1.reports import router as reports_router
from app.api.v1.retention import router as retention_router
from app.api.v1.rules import router as rules_router
from app.api.v1.sca import router as sca_router
from app.api.v1.search import router as search_router
from app.api.v1.soar import router as soar_router
from app.api.v1.sources import router as sources_router
from app.api.v1.users import router as users_router

api_router = APIRouter()
api_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users_router, prefix="/users", tags=["Users"])
api_router.include_router(ingest_router, prefix="/ingest", tags=["Log Collection"])
api_router.include_router(sources_router, prefix="/sources", tags=["Data Sources"])
api_router.include_router(alerts_router, prefix="/alerts", tags=["Alerting"])
api_router.include_router(ai_router, prefix="/ai", tags=["AI Agent"])
api_router.include_router(meta_router, prefix="/meta", tags=["System"])
api_router.include_router(search_router, prefix="/search", tags=["Investigation"])
api_router.include_router(cases_router, prefix="/cases", tags=["Investigation"])
api_router.include_router(reports_router, prefix="/reports", tags=["Reporting"])
api_router.include_router(retention_router, prefix="/retention", tags=["Retention"])
api_router.include_router(soar_router, prefix="/soar", tags=["SOAR"])
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(rules_router, prefix="/rules", tags=["Detection Rules"])
api_router.include_router(fim_router, prefix="/fim", tags=["File Integrity Monitoring"])
api_router.include_router(sca_router, prefix="/sca", tags=["Security Configuration Assessment"])
api_router.include_router(policies_router, prefix="/policies", tags=["Configuration Assessment"])
