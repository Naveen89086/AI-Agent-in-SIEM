"""Platform meta endpoint (module 7).

Exposes the implemented SIEM capability map, module versions and discoverable
API prefixes so clients can render capability-aware UIs.
"""

from fastapi import APIRouter

from app.core.config import settings

router = APIRouter()

_CAPABILITIES = [
    {"id": "log_collection", "title": "Log Collection", "module": "M1", "api": "/api/v1/ingest"},
    {"id": "normalization", "title": "Normalization & Parsing", "module": "M2", "api": "/api/v1/ingest"},
    {"id": "correlation", "title": "Event Correlation", "module": "M3", "api": "/api/v1/alerts"},
    {"id": "threat_detection", "title": "Threat Detection", "module": "M4", "api": "/api/v1/alerts"},
    {"id": "alerting", "title": "Real-Time Alerting", "module": "M5", "api": "/api/v1/alerts"},
    {"id": "ai_agent", "title": "AI Agent", "module": "M6", "api": "/api/v1/ai"},
    {"id": "investigation", "title": "Investigation & Forensics", "module": "M9", "api": "/api/v1/cases"},
    {"id": "reporting", "title": "Compliance Reporting", "module": "M10", "api": "/api/v1/reports"},
    {"id": "retention", "title": "Log Retention & Storage", "module": "M11", "api": "/api/v1/retention"},
    {"id": "soar", "title": "Automated Response (SOAR)", "module": "M12", "api": "/api/v1/soar"},
]

_ROUTERS = [
    "/api/v1/auth",
    "/api/v1/users",
    "/api/v1/ingest",
    "/api/v1/sources",
    "/api/v1/alerts",
    "/api/v1/ai",
    "/api/v1/search",
    "/api/v1/cases",
    "/api/v1/reports",
    "/api/v1/retention",
    "/api/v1/soar",
]


@router.get("", tags=["System"])
def meta() -> dict:
    return {
        "app": settings.app_name,
        "version": "1.0.0",
        "api_prefix": settings.api_v1_prefix,
        "capabilities": _CAPABILITIES,
        "routers": _ROUTERS,
    }
