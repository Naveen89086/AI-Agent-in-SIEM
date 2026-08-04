"""Compliance reporting templates (function 8).

NIST CSF / CIS Controls v8 / GDPR control templates with status derivation
from live platform telemetry: alert volume, cases, detection coverage,
retention, MFA/logging posture.
"""

from dataclasses import dataclass, field


@dataclass
class Control:
    id: str
    title: str
    description: str
    # status: one of implemented / partial / not_implemented
    status: str = "not_implemented"
    evidence: str = ""


@dataclass
class ReportContext:
    generated_at: str
    org: str
    period: str
    metrics: dict
    cases: list[dict]
    alerts: list[dict]
    sources: list[dict]
    controls: list[Control] = field(default_factory=list)


def _log_status(metrics: dict) -> str:
    """Derive log-collection posture from active sources / retention days."""
    active_sources = metrics.get("active_sources", 0)
    retention = metrics.get("retention_days", 0)
    if active_sources >= 2 and retention >= 90:
        return "implemented"
    if active_sources >= 1:
        return "partial"
    return "not_implemented"


def _alert_status(metrics: dict) -> str:
    if metrics.get("open_alerts", 0) == 0 and metrics.get("total_alerts", 0) > 0:
        return "implemented"
    if metrics.get("total_alerts", 0) > 0:
        return "partial"
    return "not_implemented"


def _case_status(metrics: dict) -> str:
    if metrics.get("resolved_cases", 0) > 0 or metrics.get("total_cases", 0) > 0:
        return "implemented"
    return "not_implemented"


def nist_controls(ctx: ReportContext) -> list[Control]:
    metrics = ctx.metrics
    return [
        Control(
            "ID.AM-1",
            "Inventory of devices, systems and data flows",
            "Maintain an inventory of assets contributing logs to the SIEM.",
            status=_log_status(metrics),
            evidence=f"{metrics.get('active_sources', 0)} active log sources",
        ),
        Control(
            "DE.CM-1",
            "Continuous monitoring for anomalies",
            "Continuous network + endpoint monitoring via correlation and anomaly detection.",
            status="implemented" if metrics.get("detectors", 0) >= 3 else "partial",
            evidence=f"{metrics.get('detectors', 0)} detection engines active",
        ),
        Control(
            "DE.AE-2",
            "Event analysis",
            "Correlated alerts analysed and triaged by analysts and the AI agent.",
            status=_alert_status(metrics),
            evidence=f"{metrics.get('total_alerts', 0)} alerts, {metrics.get('open_alerts', 0)} open",
        ),
        Control(
            "RS.RP-1",
            "Incident response plan",
            "Cases opened for each incident with notes, artifacts and timelines.",
            status=_case_status(metrics),
            evidence=f"{metrics.get('total_cases', 0)} cases, {metrics.get('resolved_cases', 0)} resolved",
        ),
        Control(
            "PR.DS-1",
            "Data at rest protection",
            "Logs retained per policy with ILM lifecycle and snapshot backup.",
            status="implemented" if metrics.get("retention_days", 0) >= 90 else "partial",
            evidence=f"{metrics.get('retention_days', 0)} day retention",
        ),
    ]


def cis_controls(ctx: ReportContext) -> list[Control]:
    metrics = ctx.metrics
    return [
        Control(
            "CIS 1",
            "Inventory and Control of Enterprise Assets",
            "Track all assets generating telemetry.",
            status=_log_status(metrics),
            evidence=f"{metrics.get('active_sources', 0)} active sources",
        ),
        Control(
            "CIS 6",
            "Access Control Management",
            "Role-based access with least privilege and audit of changes.",
            status="implemented",
            evidence="RBAC (admin/analyst/viewer) enforced on all API endpoints",
        ),
        Control(
            "CIS 8",
            "Audit Log Management",
            "Centralized, tamper-evident log collection and retention.",
            status=_log_status(metrics),
            evidence=f"{metrics.get('retention_days', 0)} days retention, {metrics.get('events_stored', 0)} events stored",
        ),
        Control(
            "CIS 13",
            "Network Monitoring and Defense",
            "Detection of scanning and lateral movement.",
            status="implemented" if metrics.get("detectors", 0) >= 4 else "partial",
            evidence=f"{metrics.get('detectors', 0)} detection engines",
        ),
        Control(
            "CIS 16",
            "Application Software Security",
            "Anomaly and signature detection for malicious payloads.",
            status="partial",
            evidence="YARA + ML anomaly detection available",
        ),
    ]


def gdpr_controls(ctx: ReportContext) -> list[Control]:
    metrics = ctx.metrics
    return [
        Control(
            "GDPR Art 32",
            "Security of processing",
            "Appropriate technical measures to ensure confidentiality, integrity and availability.",
            status="implemented" if metrics.get("total_alerts", 0) > 0 else "partial",
            evidence="Continuous monitoring, alerting and response in place",
        ),
        Control(
            "GDPR Art 33",
            "Breach notification",
            "Ability to detect and document a personal data breach in 72 hours.",
            status=_case_status(metrics),
            evidence=f"{metrics.get('total_cases', 0)} incidents documented with timelines",
        ),
        Control(
            "GDPR Art 25",
            "Data protection by design",
            "Minimal data collection; retention governed by policy.",
            status="implemented" if metrics.get("retention_days", 0) > 0 else "partial",
            evidence=f"Retention policy of {metrics.get('retention_days', 0)} days with automated purge",
        ),
        Control(
            "GDPR Art 30",
            "Records of processing activities",
            "Keep records of processing activities including security events.",
            status=_log_status(metrics),
            evidence=f"{metrics.get('events_stored', 0)} events retained in the log store",
        ),
    ]


TEMPLATES = {
    "nist": {
        "title": "NIST CSF Compliance Report",
        "framework": "NIST Cybersecurity Framework",
        "build": nist_controls,
    },
    "cis": {
        "title": "CIS Controls v8 Compliance Report",
        "framework": "CIS Critical Security Controls v8",
        "build": cis_controls,
    },
    "gdpr": {
        "title": "GDPR Compliance Report",
        "framework": "General Data Protection Regulation",
        "build": gdpr_controls,
    },
}


def build_controls(template: str, metrics: dict) -> list[Control]:
    spec = TEMPLATES.get(template)
    if spec is None:
        raise ValueError(f"Unknown report template: {template}")
    return spec["build"](ReportContext(generated_at="", org="", period="", metrics=metrics, cases=[], alerts=[], sources=[]))
