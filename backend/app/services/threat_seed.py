"""Deterministic demo seed for the IOC + vulnerability modules.

Demo mode only (``IOC_DEMO_MODE`` / ``VULNERABILITY_DEMO_MODE``). Seeded once
on startup when the tables are empty so the threat-intelligence and
vulnerability dashboards are fully backed by the database. Every row carries
``source_label="demo"`` so it can never be mistaken for a real endpoint finding.

When demo mode is disabled, no demo rows are generated and data comes only from
enrolled endpoint agents through the authenticated ingest APIs.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.ioc import IocAgent, IocIndicator, IocMatch, IocObservation
from app.models.vulnerability import (
    SoftwareInventory,
    VulnerabilityFinding,
    VulnerabilityScan,
    VulnerabilityStatus,
    VulnAgent,
)
from app.services import vulnerability_data
from app.services.ioc_data import canonical_value, offline_indicators

log = logging.getLogger("siem.threat_seed")

# Single-device model: demo IOC + vuln data reflect ONE protected endpoint.
DEMO_IOC_AGENTS = [
    {"agent_code": "ioc-win-001", "hostname": "WORKSTATION-01", "ip_address": "10.10.10.21"},
]

DEMO_VULN_AGENTS = [
    {"agent_code": "vuln-win-001", "hostname": "WORKSTATION-01", "ip_address": "10.10.10.11"},
]

# Demo software inventory with a mix of CVE-covered and unknown products.
DEMO_INVENTORY = {
    "vuln-win-001": [
        {"vendor": "Microsoft", "product": "Windows 10 Pro", "version": "10.0.19041"},
        {"vendor": "Google", "product": "Chrome", "version": "122.0.6261.94"},
        {"vendor": "Adobe", "product": "Acrobat Reader DC", "version": "23.008.20470"},
        {"vendor": "Apache", "product": "Apache HTTP Server", "version": "2.4.54"},
        {"vendor": "Notepad++", "product": "Notepad++", "version": "8.5.8"},
    ],
    "vuln-win-002": [
        {"vendor": "Microsoft", "product": "Windows 10 Enterprise", "version": "10.0.19045"},
        {"vendor": "Mozilla", "product": "Firefox", "version": "123.0.1"},
        {"vendor": "7-Zip", "product": "7-Zip", "version": "23.01"},
    ],
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def seed_ioc_demo(db: Session) -> None:
    if not settings.ioc_demo_mode:
        return
    existing = db.scalar(select(func.count()).select_from(IocAgent))
    if existing:
        return

    # Seed the indicator corpus from the bundled offline list.
    synced = 0
    for entry in offline_indicators():
        exists = db.scalar(
            select(IocIndicator).where(
                IocIndicator.indicator_type == entry["indicator_type"],
                IocIndicator.value == entry["value"],
            )
        )
        if exists is None:
            db.add(
                IocIndicator(
                    indicator_type=entry["indicator_type"],
                    value=entry["value"],
                    source=entry["source"],
                    threat=entry["threat"],
                    severity=entry["severity"],
                    tags=json.dumps(entry.get("tags") or []),
                    reference=entry.get("reference"),
                    active=True,
                )
            )
            synced += 1
    db.flush()

    now = _now()
    for spec in DEMO_IOC_AGENTS:
        agent = IocAgent(
            agent_code=spec["agent_code"],
            hostname=spec["hostname"],
            ip_address=spec["ip_address"],
            operating_system="Windows 10 Pro 22H2",
            platform="windows",
            version="1.0.0",
            status="online",
            last_seen=now - timedelta(minutes=2),
            enabled=True,
            machine_guid="demo-local-device",
        )
        db.add(agent)
        db.flush()

        # Demo observations: a mix of matched (malicious) + unknown indicators.
        observations = [
            {
                "type": "ipv4", "value": "45.83.193.105", "source": "network.connection",
                "context": {"proto": "tcp", "foreign_port": 4444, "pid": 4212},
            },
            {
                "type": "domain", "value": "freemathhelp.ga", "source": "network.dns",
                "context": {"resolver": "system"},
            },
            {
                "type": "filehash",
                "value": "d3a2c1b4e5f60718293a4b5c6d7e8f90123a4b5c6d7e8f90123a4b5c6d7e8f9",
                "source": "file.hash", "context": {"path": "C:\\Temp\\update.exe"},
            },
            {
                "type": "ipv4", "value": "203.0.113.99", "source": "network.connection",
                "context": {"proto": "tcp", "foreign_port": 8443},
            },
        ]
        for idx, obs in enumerate(observations):
            indicator = db.scalar(
                select(IocIndicator).where(
                    IocIndicator.indicator_type == obs["type"],
                    IocIndicator.value == canonical_value(obs["type"], obs["value"]),
                )
            )
            observation = IocObservation(
                agent_id=agent.id,
                observed_at=now - timedelta(minutes=5 * (idx + 1)),
                indicator_type=obs["type"],
                value=obs["value"],
                source=obs["source"],
                context=json.dumps(obs.get("context") or {}),
                source_label="demo",
            )
            db.add(observation)
            db.flush()
            if indicator is not None:
                verdict, severity, threat, confidence = "malicious", indicator.severity, indicator.threat, 0.95
            else:
                verdict, severity, threat, confidence = "unknown", "unknown", None, 0.0
            db.add(
                IocMatch(
                    observation_id=observation.id,
                    agent_id=agent.id,
                    indicator_id=indicator.id if indicator else None,
                    indicator_type=obs["type"],
                    value=obs["value"],
                    verdict=verdict,
                    severity=severity,
                    threat=threat,
                    source=indicator.source if indicator else "bundled",
                    confidence=confidence,
                    detail=indicator.threat if indicator else "not found in any configured threat-intel source",
                    matched_at=observation.observed_at,
                    source_label="demo",
                )
            )
    db.flush()
    log.info("Seeded IOC demo data (%s indicators, %s agents)", synced, len(DEMO_IOC_AGENTS))


def seed_vuln_demo(db: Session) -> None:
    if not settings.vulnerability_demo_mode:
        return
    existing = db.scalar(select(func.count()).select_from(VulnAgent))
    if existing:
        return

    now = _now()
    for spec in DEMO_VULN_AGENTS:
        agent = VulnAgent(
            agent_code=spec["agent_code"],
            hostname=spec["hostname"],
            ip_address=spec["ip_address"],
            operating_system="Windows Server 2019",
            platform="windows",
            version="1.0.0",
            status="online",
            last_seen=now - timedelta(minutes=1),
            enabled=True,
            machine_guid="demo-local-device",
        )
        db.add(agent)
        db.flush()

        for item in DEMO_INVENTORY.get(spec["agent_code"], []):
            db.add(
                SoftwareInventory(
                    agent_id=agent.id,
                    product=item["product"],
                    vendor=item["vendor"],
                    version=item["version"],
                    source="registry",
                    install_date=now - timedelta(days=120),
                    status="active",
                )
            )
        db.flush()

        # Deterministic scan for the seeded inventory.
        scan = VulnerabilityScan(
            agent_id=agent.id,
            status=VulnerabilityStatus.COMPLETED,
            started_at=now - timedelta(hours=6),
            ended_at=now - timedelta(hours=6, minutes=-1),
            source_label="demo",
        )
        db.add(scan)
        db.flush()
        db_missing = not vulnerability_data.database_loaded()
        scan.database_missing = db_missing
        scan.software_count = len(DEMO_INVENTORY.get(spec["agent_code"], []))

        for item in DEMO_INVENTORY.get(spec["agent_code"], []):
            inv = db.scalar(
                select(SoftwareInventory).where(
                    SoftwareInventory.agent_id == agent.id,
                    SoftwareInventory.product == item["product"],
                    SoftwareInventory.vendor == item["vendor"],
                    SoftwareInventory.version == item["version"],
                )
            )
            verdict = vulnerability_data.adjudicate(item["vendor"], item["product"], item["version"])
            finding = VulnerabilityFinding(
                scan_id=scan.id,
                agent_id=agent.id,
                software_id=inv.id if inv else "",
                cve_id=verdict.get("cve_id"),
                description=verdict.get("description"),
                cvss_score=verdict.get("cvss_score"),
                severity=verdict.get("severity", "unknown"),
                status=verdict["status"],
                affected_version=verdict.get("affected_version"),
                known=bool(verdict.get("known", False)),
                reason=verdict.get("reason"),
            )
            db.add(finding)
            if verdict["status"] == "vulnerable":
                scan.matched_count += 1
            elif verdict["status"] == "not_vulnerable":
                scan.not_vulnerable_count += 1
            else:
                scan.unknown_count += 1
        scan.duration = 1.5
    db.flush()
    log.info("Seeded vulnerability demo data (%s agents)", len(DEMO_VULN_AGENTS))


def seed_threat_data(db: Session) -> None:
    """Seed both IOC and vulnerability demo data (demo mode only)."""
    seed_ioc_demo(db)
    seed_vuln_demo(db)
    db.commit()
