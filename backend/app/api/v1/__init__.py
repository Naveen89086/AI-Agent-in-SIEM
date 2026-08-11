"""API v1 package."""

from fastapi import APIRouter

from app.api.v1.ai import router as ai_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.auth import router as auth_router
from app.api.v1.cases import router as cases_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.fim import router as fim_router
from app.api.v1.hunting import router as hunting_router
from app.api.v1.ingest import router as ingest_router
from app.api.v1.ioc import router as ioc_router
from app.api.v1.meta import router as meta_router
from app.api.v1.network import router as network_router
from app.api.v1.policies import router as policies_router
from app.api.v1.processes import router as processes_router
from app.api.v1.protected_endpoint import router as protected_endpoint_router
from app.api.v1.reports import router as reports_router
from app.api.v1.retention import router as retention_router
from app.api.v1.rules import router as rules_router
from app.api.v1.sca import router as sca_router
from app.api.v1.search import router as search_router
from app.api.v1.services import router as services_router
from app.api.v1.soar import router as soar_router
from app.api.v1.sources import router as sources_router
from app.api.v1.telemetry import router as telemetry_router
from app.api.v1.users import router as users_router
from app.api.v1.vulnerabilities import router as vulnerabilities_router

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
api_router.include_router(ioc_router, prefix="/ioc", tags=["Threat Intelligence"])
api_router.include_router(hunting_router, prefix="/hunting", tags=["Threat Hunting"])
api_router.include_router(vulnerabilities_router, prefix="/vulnerabilities", tags=["Vulnerability Detection"])
api_router.include_router(telemetry_router, prefix="/telemetry", tags=["Endpoint Telemetry"])
api_router.include_router(network_router, prefix="/network", tags=["Network Monitoring"])
api_router.include_router(processes_router, prefix="/processes", tags=["Process Monitoring"])
api_router.include_router(services_router, prefix="/services", tags=["Service Monitoring"])
api_router.include_router(protected_endpoint_router, prefix="/protected-endpoint", tags=["Protected Endpoint"])
