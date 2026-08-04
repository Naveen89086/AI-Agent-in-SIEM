"""Compliance reporting endpoints (function 8)."""

from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, PlainTextResponse

from app.api.deps import AnalystOrAdmin, DbSession
from app.core.exceptions import ValidationError
from app.services.report_service import ReportService
from app.services.report_templates import TEMPLATES

router = APIRouter()


@router.get("/templates", response_model=list[dict])
def list_templates(user: AnalystOrAdmin) -> list[dict]:
    return [
        {"id": key, "title": spec["title"], "framework": spec["framework"]}
        for key, spec in TEMPLATES.items()
    ]


@router.get("/generate/{template}", response_class=HTMLResponse, response_model=None)
def generate_report(
    template: str,
    user: AnalystOrAdmin,
    db: DbSession,
    format: str = Query(default="html", pattern="^(html|pdf)$"),
    org: str = Query(default="Example Corp", max_length=200),
    period: str = Query(default="Current", max_length=100),
):
    if template not in TEMPLATES:
        raise ValidationError(f"Unknown template '{template}'; choose from {list(TEMPLATES)}")
    service = ReportService(db)
    if format == "pdf":
        content = service.render_pdf(template, org=org, period=period)
        return PlainTextResponse(
            content=content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{template}-report.pdf"'
            },
        )
    html = service.render_html(template, org=org, period=period)
    return HTMLResponse(content=html, headers={"Content-Disposition": "inline"})
