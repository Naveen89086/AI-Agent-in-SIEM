"""Demo data generator.

Generates realistic syslog / web / firewall / Windows events (including
malicious patterns that trip the detection rules) and feeds them through the
real pipeline: normalizer -> detectors -> alert service. Optionally runs the
AI agent, creates investigation cases and executes SOAR playbooks so a fresh
deployment has meaningful data to explore.

Usage:
    python -m app.scripts.demo_data --events 40 --cases --ai --soar

Flags:
    --events N      total raw events to generate (default 40)
    --seed N        random seed for reproducible output
    --ai            run AI analysis on generated alerts
    --cases         create one case per high/critical alert
    --soar          execute matching SOAR playbooks for alerts
"""

import argparse
import asyncio
import logging
import random
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

sys.path.insert(0, ".")

from app.core.logging import setup_logging
from app.db.session import SessionLocal
from app.pipeline.bus import EventBus, Topics, build_event_bus, stamp
from app.pipeline.detection import Detection
from app.services.agent_service import AgentService
from app.services.alert_service import AlertService
from app.services.case_service import CaseService
from app.services.detection_service import DetectionService
from app.services.normalizer_service import NormalizerService
from app.services.soar_service import SoarService
from app.schemas.case import CaseCreate
from app.storage.base import build_log_store

setup_logging()
log = logging.getLogger("siem.demo")

ATTACKER_SSH = "185.220.101.34"
ATTACKER_WEB = "203.0.113.66"
ATTACKER_WIN = "198.51.100.23"
ATTACKER_FW = "45.155.205.233"


def _ts(offset_s: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)).isoformat()


# ---------------------------------------------------------------------------
# Event generators
# ---------------------------------------------------------------------------
def _linux_auth(offset_s: int, action: str, ip: str, user: str = "root") -> dict[str, Any]:
    ts = _ts(offset_s)
    if action == "failed":
        msg = (
            f"{ts} webserver01 sshd[10233]: "
            f"Failed password for {user} from {ip} port 53221 ssh2"
        )
    elif action == "invalid":
        msg = f"{ts} webserver01 sshd[10234]: Invalid user {user} from {ip} port 53222"
    elif action == "breakin":
        msg = f"{ts} webserver01 sshd[10235]: Possible break-in attempt! {user} from {ip}"
    elif action == "maxauth":
        msg = (
            f"{ts} webserver01 sshd[10236]: error: maximum authentication "
            f"attempts exceeded for {user} from {ip} port 53223"
        )
    else:  # success
        msg = (
            f"{ts} webserver01 sshd[10237]: Accepted password for {user} "
            f"from {ip} port 53224 ssh2"
        )
    return {
        "source_type": "linux",
        "source_name": "webserver01-sshd",
        "host": "webserver01",
        "message": msg,
        "received_at": ts,
        "extra": {},
        "tags": ["demo"],
    }


def _sudo(offset_s: int, ip: str, command: str) -> dict[str, Any]:
    ts = _ts(offset_s)
    msg = (
        f"{ts} webserver01 sudo[10301]: bob : TTY=pts/0 ; "
        f"PWD=/home/bob ; USER=root ; COMMAND={command}"
    )
    return {
        "source_type": "linux",
        "source_name": "webserver01-sudo",
        "host": "webserver01",
        "message": msg,
        "received_at": ts,
        "extra": {},
        "tags": ["demo"],
    }


def _windows(offset_s: int, event_id: int, ip: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    ts = _ts(offset_s)
    base = {
        "event_id": event_id,
        "computer": "DC-01",
        "provider": "microsoft-windows-security-auditing",
        "time_created": ts,
    }
    base.update(extra or {})
    return {
        "source_type": "windows",
        "source_name": "DC-01-security",
        "host": "DC-01",
        "message": "",
        "received_at": ts,
        "extra": base,
        "tags": ["demo"],
    }


def _web(offset_s: int, ip: str, status: int, path: str = "/admin/login.php") -> dict[str, Any]:
    ts = datetime.now(timezone.utc) + timedelta(seconds=offset_s)
    stamp_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    msg = (
        f'{ip} - - [{stamp_str}] "POST {path} HTTP/1.1" {status} 5321 '
        f'"{path}" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    )
    return {
        "source_type": "web",
        "source_name": "webserver01-apache",
        "host": "webserver01",
        "message": msg,
        "received_at": ts.isoformat(),
        "extra": {},
        "tags": ["demo"],
    }

def _firewall(offset_s: int, ip: str, dpt: int) -> dict[str, Any]:
    ts = _ts(offset_s)
    msg = (
        f"{ts} fw01 kernel: [29952.1145] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:ab:cd:ef "
        f"SRC={ip} DST=10.0.0.4 LEN=40 TOS=0x00 PREC=0x00 TTL=111 ID=54321 "
        f"PROTO=TCP SPT=40000 DPT={dpt}"
    )
    return {
        "source_type": "firewall",
        "source_name": "fw01-ufw",
        "host": "fw01",
        "message": msg,
        "received_at": ts,
        "extra": {},
        "tags": ["demo"],
    }

def build_scenarios(count: int) -> list[dict[str, Any]]:
    """Build a mixed bag of benign + malicious raw events (roughly `count`)."""
    events: list[dict[str, Any]] = []
    t = 0
    rng = random.Random(42)

    # SSH brute force: 8 failures from one IP within 60s
    for i in range(8):
        events.append(_linux_auth(t - 30 + i * 3, "failed", ATTACKER_SSH))
    t += 40
    # break-in attempt fired by sshd afterwards
    events.append(_linux_auth(t, "breakin", ATTACKER_SSH))

    # Windows logon failure spray: 12 x 4625
    for i in range(12):
        events.append(
            _windows(
                t + 5 + i * 2,
                4625,
                ATTACKER_WIN,
                {"target_user": "Administrator", "source_ip": ATTACKER_WIN, "log_name": "Security", "record_id": 9000 + i},
            )
        )
    t += 30
    # rogue account created (persistence) + audit log cleared
    events.append(
        _windows(t, 4720, "10.0.0.5", {"target_user": "svc_backdoor", "log_name": "Security", "record_id": 9012})
    )
    events.append(
        _windows(t + 5, 1102, "10.0.0.5", {"log_name": "Security", "record_id": 9013})
    )

    # Web admin credential stuffing: 22 x 401
    for i in range(22):
        events.append(_web(t + 40 + i, ATTACKER_WEB, 401 if i % 2 else 403))
    t += 70

    # Firewall port scan: 12 blocks against distinct ports
    for i in range(12):
        events.append(_firewall(t + 10 + i * 2, ATTACKER_FW, 1024 + i * 10))
    t += 40

    # Privilege escalation via sudo
    events.append(_sudo(t, "10.0.0.9", "/usr/bin/cat /etc/shadow"))
    events.append(_sudo(t + 3, "10.0.0.9", "/usr/bin/chmod 4755 /bin/bash"))

    # Benign background traffic
    benign_users = ["alice", "bob", "carol"]
    for i in range(count - len(events)):
        t += 2
        roll = rng.random()
        ip = f"10.1.{rng.randint(0, 20)}.{rng.randint(2, 250)}"
        if roll < 0.4:
            events.append(_linux_auth(t, "success", ip, benign_users[i % 3]))
        elif roll < 0.55:
            events.append(_sudo(t, ip, "/usr/bin/less /var/log/syslog"))
        elif roll < 0.75:
            events.append(_web(t, ip, 200, "/index.html"))
        else:
            events.append(_firewall(t, ip, 53))
    return events


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------
async def run_pipeline(events: list[dict[str, Any]], *, do_ai: bool, do_cases: bool, do_soar: bool) -> None:
    db = SessionLocal()
    bus = build_event_bus()
    store = build_log_store()
    normalizer = NormalizerService(bus, store)
    detectors = DetectionService(bus)
    alerts = AlertService(db, bus)
    agent = AgentService(db) if do_ai else None
    cases = CaseService(db) if do_cases else None
    soar = SoarService(db) if do_soar else None

    alert_ids: list[str] = []
    raw_count = accepted = normalized = 0
    for raw in events:
        raw_count += 1
        raw = stamp(raw)
        await bus.publish(Topics.RAW_EVENTS, raw)
        accepted += 1
        event = await normalizer.process(raw)
        if event is None:
            continue
        normalized += 1
        found: list[Detection] = await detectors.process_event(event)
        for detection in found:
            alert = await alerts.process_detection(detection)
            if alert.id not in alert_ids:
                alert_ids.append(alert.id)

    print(f"\nIngested {accepted}/{raw_count} raw events, normalized {normalized}.")

    for alert_id in alert_ids:
        if agent is not None:
            try:
                _, record = await agent.analyze_alert(alert_id)
                print(f"AI  alert={alert_id} provider={record.provider} risk={record.risk_score}")
            except Exception:
                log.exception("AI analysis failed for %s", alert_id)
        if cases is not None:
            from app.models.alert import Alert

            alert = db.get(Alert, alert_id)
            case = cases.create(
                CaseCreate(
                    title=f"[Demo] {alert.rule_title}",
                    description=f"Auto-created from demo alert {alert_id}.",
                    severity=alert.severity,
                    tags=["demo"],
                    alert_ids=[alert_id],
                )
            )
            print(f"Case {case.id} <- alert {alert_id}")
        if soar is not None:
            from app.services.alert_service import _to_dict

            alert_obj = db.get(Alert, alert_id)
            records = await soar.execute_for_alert(_to_dict(alert_obj))
            for rec in records:
                print(f"SOAR {rec.playbook_id} -> {rec.action_type} [{rec.status}]")

    from app.models.alert import Alert
    from sqlalchemy import func, select

    total = db.scalar(select(func.count(Alert.id))) or 0
    print(f"\nAlerts now in database: {total}")
    print("Demo data generation complete.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate demo SIEM data.")
    parser.add_argument("--events", type=int, default=40)
    parser.add_argument("--ai", action="store_true")
    parser.add_argument("--cases", action="store_true")
    parser.add_argument("--soar", action="store_true")
    args = parser.parse_args()

    events = build_scenarios(args.events)
    asyncio.run(
        run_pipeline(
            events,
            do_ai=args.ai,
            do_cases=args.cases,
            do_soar=args.soar,
        )
    )


if __name__ == "__main__":
    main()
