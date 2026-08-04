"""Module 10 - compliance reporting tests."""

from app.services.report_templates import TEMPLATES, build_controls


def test_all_templates_available():
    assert set(TEMPLATES) == {"nist", "cis", "gdpr"}


def test_build_controls_status_derivation():
    metrics = {
        "active_sources": 3,
        "total_alerts": 10,
        "open_alerts": 2,
        "total_cases": 4,
        "resolved_cases": 1,
        "detectors": 5,
        "retention_days": 180,
    }
    controls = build_controls("nist", metrics)
    assert controls
    for control in controls:
        assert control.status in ("implemented", "partial", "not_implemented")
    by_id = {c.id: c for c in controls}
    assert by_id["ID.AM-1"].status == "implemented"
    assert by_id["DE.CM-1"].status == "implemented"
    assert by_id["DE.AE-2"].status == "partial"


def test_report_service_html():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.models  # noqa: F401
    from app.db.base import Base
    from app.services.report_service import ReportService

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()

    html = ReportService(session).render_html("cis")
    assert "CIS Controls v8 Compliance Report" in html
    assert "Control assessment" in html
    assert "CIS 8" in html

    session.close()


def test_report_service_pdf():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import app.models  # noqa: F401
    from app.db.base import Base
    from app.services.report_service import ReportService

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()

    pdf = ReportService(session).render_pdf("gdpr")
    assert pdf.startswith(b"%PDF")

    session.close()


def test_api_report_templates(client, admin_headers):
    resp = client.get("/api/v1/reports/templates", headers=admin_headers)
    assert resp.status_code == 200
    ids = {t["id"] for t in resp.json()}
    assert ids == {"nist", "cis", "gdpr"}


def test_api_report_html(client, admin_headers):
    resp = client.get("/api/v1/reports/generate/nist?format=html", headers=admin_headers)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "NIST CSF Compliance Report" in resp.text


def test_api_report_pdf(client, admin_headers):
    resp = client.get("/api/v1/reports/generate/cis?format=pdf", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")


def test_api_report_unknown_template(client, admin_headers):
    resp = client.get("/api/v1/reports/generate/bogus", headers=admin_headers)
    assert resp.status_code == 422


def test_api_reports_require_auth(client):
    assert client.get("/api/v1/reports/templates").status_code == 401
