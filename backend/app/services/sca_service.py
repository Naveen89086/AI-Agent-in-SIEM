"""Security Configuration Assessment (SCA) service.

Agents registry, scan lifecycle, events, drift, AI analysis and the
human-approved remediation workflow. Demo-mode scans are deterministic and
labeled as demo; real-mode scans collect endpoint evidence and evaluate it.
"""

import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.agents import build_provider
from app.core.config import settings
from app.core.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)
from app.models.analysis import Analysis
from app.models.sca import (
    Agent,
    CheckResult,
    CheckRule,
    ComplianceReference,
    ConfigurationDrift,
    Policy,
    PolicyCheck,
    PolicyScan,
    RemediationAction,
    RemediationStatus,
    ScaEvent,
)

log = logging.getLogger("siem.sca.service")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def _hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class ScaService:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ================================================================== agents
    def agents(self) -> list[dict]:
        rows = self.db.execute(
            select(Agent).order_by(Agent.agent_code)
        ).scalars().all()
        return [self._agent_dict(a) for a in rows]

    def agent(self, agent_id: str) -> Agent:
        agent = self.db.get(Agent, agent_id)
        if agent is None:
            raise NotFoundError(f"Agent {agent_id} not found")
        return agent

    def register_agent(
        self,
        *,
        agent_code: str,
        hostname: str,
        operating_system: str,
        platform: str,
        version: str,
        registration_token: str | None = None,
    ) -> dict:
        if settings.sca_registration_token:
            if not registration_token or not secrets.compare_digest(
                registration_token, settings.sca_registration_token
            ):
                raise UnauthorizedError(
                    "Invalid registration token", code="invalid_registration_token"
                )
        agent_code = agent_code.strip()
        if not agent_code or len(agent_code) > 64:
            raise ValidationError("agent_code is required (max 64 chars)")

        api_key = secrets.token_urlsafe(32)
        existing = self.db.scalar(
            select(Agent).where(Agent.agent_code == agent_code)
        )
        if existing is not None:
            raise ConflictError(f"Agent '{agent_code}' already registered")

        agent = Agent(
            agent_code=agent_code,
            hostname=hostname or agent_code,
            operating_system=operating_system,
            platform=platform or "windows",
            version=version or "1.0.0",
            status="online",
            last_seen=_now(),
            api_key_hash=_hash_api_key(api_key),
            enabled=True,
        )
        self.db.add(agent)
        self.db.commit()
        self.db.refresh(agent)
        data = self._agent_dict(agent)
        data["api_key"] = api_key  # returned once; only the hash is stored
        return data

    def heartbeat(self, agent_code: str, api_key: str, status: str = "online") -> dict:
        agent = self.db.scalar(select(Agent).where(Agent.agent_code == agent_code))
        if agent is None:
            raise NotFoundError(f"Agent '{agent_code}' not registered")
        if not agent.api_key_hash or not secrets.compare_digest(
            _hash_api_key(api_key), agent.api_key_hash
        ):
            raise UnauthorizedError("Invalid agent API key", code="invalid_api_key")

        new_status = status if status in ("online", "offline") else "online"
        was_offline = agent.status == "offline"
        agent.status = new_status
        agent.last_seen = _now()
        if was_offline and new_status == "online":
            self.db.add(
                ScaEvent(
                    event_type="agent_online",
                    agent_id=agent.id,
                    severity="info",
                    message=f"Agent '{agent.hostname}' is back online",
                    occurred_at=_now(),
                )
            )
        elif not was_offline and new_status == "offline":
            self.db.add(
                ScaEvent(
                    event_type="agent_offline",
                    agent_id=agent.id,
                    severity="high",
                    message=f"Agent '{agent.hostname}' went offline",
                    occurred_at=_now(),
                )
            )
        self.db.commit()
        return self._agent_dict(agent)

    def _agent_dict(self, agent: Agent) -> dict:
        scan_stats = self.db.execute(
            select(
                PolicyScan.policy_id,
                func.count(PolicyScan.id),
                func.max(PolicyScan.end_scan),
            )
            .where(
                PolicyScan.agent_id == agent.id,
                PolicyScan.status == "completed",
            )
            .group_by(PolicyScan.policy_id)
        ).all()
        return {
            "id": agent.id,
            "agent_code": agent.agent_code,
            "hostname": agent.hostname,
            "operating_system": agent.operating_system,
            "platform": agent.platform,
            "version": agent.version,
            "status": agent.status,
            "last_seen": _iso(agent.last_seen),
            "enabled": agent.enabled,
            "scans": sum(count for _, count, _ in scan_stats),
            "demo": settings.sca_demo_mode,
        }

    # =================================================================== scans
    def create_scan(self, *, policy_id: str, agent_id: str) -> dict:
        policy = self.db.get(Policy, policy_id)
        if policy is None:
            raise NotFoundError(f"Policy {policy_id} not found")
        if not policy.enabled:
            raise ConflictError(f"Policy '{policy.policy_id}' is disabled")
        agent = self.db.get(Agent, agent_id)
        if agent is None:
            raise NotFoundError(f"Agent {agent_id} not found")
        if not agent.enabled:
            raise ConflictError(f"Agent '{agent.agent_code}' is disabled")

        active = self.db.scalar(
            select(func.count())
            .select_from(PolicyScan)
            .where(
                PolicyScan.policy_id == policy.id,
                PolicyScan.agent_id == agent.id,
                PolicyScan.status.in_(("queued", "running", "collecting", "evaluating")),
            )
        )
        if active:
            raise ConflictError("a scan is already running for this policy/agent")

        scan = PolicyScan(
            policy_id=policy.id,
            agent_id=agent.id,
            policy_version=policy.version,
            status="queued",
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)

        from app.sca.queue import get_scan_queue

        get_scan_queue().enqueue(scan.id)
        return self._scan_dict(scan)

    # -------------------------------------------------------- agent transport
    def pending_job(self, agent_code: str) -> dict:
        """Return the next evidence-collection job for an endpoint agent.

        The job lists the enabled rules of the policy whose scan is waiting for
        that agent (status collecting/running). The agent collects evidence and
        submits it; evaluation stays on the server.
        """
        agent = self.db.scalar(select(Agent).where(Agent.agent_code == agent_code))
        if agent is None:
            raise NotFoundError(f"Agent '{agent_code}' not found")
        scan = self.db.scalar(
            select(PolicyScan)
            .where(
                PolicyScan.agent_id == agent.id,
                PolicyScan.status.in_(("collecting", "running", "evaluating")),
            )
            .order_by(PolicyScan.created_at)
            .limit(1)
        )
        if scan is None:
            return {"job": None, "demo": settings.sca_demo_mode}

        policy = self.db.get(Policy, scan.policy_id)
        checks = list(
            self.db.execute(
                select(PolicyCheck)
                .where(PolicyCheck.policy_id == policy.id, PolicyCheck.enabled.is_(True))
                .order_by(PolicyCheck.check_id)
            ).scalars().all()
        )
        rules: list[dict] = []
        for check in checks:
            rule = self.db.scalar(
                select(CheckRule)
                .where(
                    CheckRule.policy_check_id == check.id,
                    CheckRule.enabled.is_(True),
                )
                .order_by(CheckRule.created_at)
                .limit(1)
            )
            if rule is None:
                continue
            rules.append(
                {
                    "check_id": check.check_id,
                    "title": check.title,
                    "rule_type": rule.rule_type,
                    "command": rule.command,
                    "file_path": rule.file_path,
                    "directory_path": rule.directory_path,
                    "registry_path": rule.registry_path,
                    "registry_value": rule.registry_value,
                    "process_name": rule.process_name,
                    "service_name": rule.service_name,
                }
            )
        return {
            "demo": settings.sca_demo_mode,
            "job": {
                "scan_id": scan.id,
                "policy_id": policy.policy_id,
                "policy": policy.name,
                "policy_version": scan.policy_version,
                "agent_code": agent.agent_code,
                "platform": agent.platform,
                "rules": rules,
            },
        }

    def submit_evidence(self, *, scan_id: str, agent_code: str, items: list[dict]) -> dict:
        """Accept evidence from an endpoint agent and finalize the scan.

        The agent never decides PASS/FAIL: the server re-evaluates every
        record against the stored rule definitions.
        """
        agent = self.db.scalar(select(Agent).where(Agent.agent_code == agent_code))
        if agent is None:
            raise NotFoundError(f"Agent '{agent_code}' not found")
        scan = self.db.get(PolicyScan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found")
        if scan.agent_id != agent.id:
            raise ForbiddenError("evidence submitted for a different agent")
        if scan.status not in ("collecting", "running", "evaluating"):
            raise ConflictError(f"scan is '{scan.status}', not awaiting evidence")

        records: list[dict] = []
        for item in items or []:
            if not isinstance(item, dict):
                raise ValidationError("evidence items must be objects")
            try:
                check_id = int(item["check_id"])
            except (KeyError, TypeError, ValueError):
                raise ValidationError("evidence item requires a numeric check_id")
            records.append(
                {
                    "check_id": check_id,
                    "collected": bool(item.get("collected")),
                    "actual_value": item.get("actual_value"),
                    "not_applicable": bool(item.get("not_applicable")),
                    "evidence": item.get("evidence"),
                    "message": item.get("message"),
                }
            )

        from app.sca.engine import ScanEngine

        ScanEngine(self.db).finalize_remote(scan, records)
        return self._scan_dict(scan)

    def scans(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        agent_id: str | None = None,
        policy_id: str | None = None,
        status: str | None = None,
    ) -> dict:
        query = select(PolicyScan)
        if agent_id:
            query = query.where(PolicyScan.agent_id == agent_id)
        if policy_id:
            query = query.where(PolicyScan.policy_id == policy_id)
        if status:
            query = query.where(PolicyScan.status == status)

        total = self.db.scalar(
            select(func.count()).select_from(query.subquery())
        ) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        rows = self.db.execute(
            query.order_by(PolicyScan.created_at.desc())
            .offset((safe_page - 1) * per_page)
            .limit(per_page)
        ).scalars().all()

        agent_names = self._agent_names()
        policy_names = self._policy_names()
        return {
            "items": [
                self._scan_dict(s, agent_names=agent_names, policy_names=policy_names)
                for s in rows
            ],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
            "demo": settings.sca_demo_mode,
        }

    def scan_detail(self, scan_id: str) -> dict:
        scan = self.db.get(PolicyScan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found")
        return self._scan_dict(scan)

    def scan_results(
        self,
        *,
        scan_id: str,
        page: int = 1,
        per_page: int = 20,
        result: str | None = None,
        search: str = "",
    ) -> dict:
        scan = self.db.get(PolicyScan, scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found")

        query = (
            select(CheckResult, PolicyCheck)
            .join(PolicyCheck, PolicyCheck.id == CheckResult.policy_check_id)
            .where(CheckResult.scan_id == scan_id)
        )
        q = search.strip().lower()
        if result:
            query = query.where(CheckResult.result == result)
        if q:
            query = query.where(
                or_(
                    PolicyCheck.title.ilike(f"%{q}%"),
                    PolicyCheck.check_id.ilike(f"%{q}%"),
                    PolicyCheck.category.ilike(f"%{q}%"),
                )
            )

        total = self.db.scalar(
            select(func.count()).select_from(query.subquery())
        ) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        rows = self.db.execute(
            query.order_by(PolicyCheck.check_id)
            .offset((safe_page - 1) * per_page)
            .limit(per_page)
        ).all()

        return {
            "items": [
                self._result_dict(cr, check)
                for cr, check in rows
            ],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
            "demo": settings.sca_demo_mode,
        }

    # ================================================================== events
    def events(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        agent_id: str | None = None,
        event_type: str | None = None,
    ) -> dict:
        query = select(ScaEvent)
        if agent_id:
            query = query.where(ScaEvent.agent_id == agent_id)
        if event_type:
            query = query.where(ScaEvent.event_type == event_type)

        total = self.db.scalar(
            select(func.count()).select_from(query.subquery())
        ) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        rows = self.db.execute(
            query.order_by(ScaEvent.occurred_at.desc())
            .offset((safe_page - 1) * per_page)
            .limit(per_page)
        ).scalars().all()
        agent_names = self._agent_names()
        policy_names = self._policy_names()
        return {
            "items": [
                self._event_dict(e, agent_names=agent_names, policy_names=policy_names)
                for e in rows
            ],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
            "demo": settings.sca_demo_mode,
        }

    def drifts(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        agent_id: str | None = None,
        policy_id: str | None = None,
    ) -> dict:
        query = select(ConfigurationDrift)
        if agent_id:
            query = query.where(ConfigurationDrift.agent_id == agent_id)
        if policy_id:
            query = query.where(ConfigurationDrift.policy_id == policy_id)

        total = self.db.scalar(
            select(func.count()).select_from(query.subquery())
        ) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        rows = self.db.execute(
            query.order_by(ConfigurationDrift.detected_at.desc())
            .offset((safe_page - 1) * per_page)
            .limit(per_page)
        ).scalars().all()
        check_titles = self._check_titles([d.check_id for d in rows])
        agent_names = self._agent_names()
        return {
            "items": [
                self._drift_dict(
                    d,
                    title=check_titles.get(d.check_id),
                    agent_names=agent_names,
                )
                for d in rows
            ],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
            "demo": settings.sca_demo_mode,
        }

    # ================================================================ dashboard
    def dashboard(self) -> dict:
        agents = list(self.db.execute(select(Agent)).scalars().all())
        online = sum(1 for a in agents if a.status == "online")
        policies = self.db.scalar(
            select(func.count()).select_from(Policy).where(Policy.enabled.is_(True))
        ) or 0

        scans = self.db.execute(
            select(PolicyScan).where(PolicyScan.status == "completed")
        ).scalars().all()
        total_scans = len(scans)
        total_checks = sum(s.total_checks for s in scans)
        total_passed = sum(s.passed for s in scans)
        total_failed = sum(s.failed for s in scans)
        total_na = sum(s.not_applicable for s in scans)
        avg_score = round(sum(s.score for s in scans) / total_scans) if scans else 0
        avg_risk = round(sum(s.risk_score for s in scans) / total_scans) if scans else 0

        events_today = self.db.scalar(
            select(func.count())
            .select_from(ScaEvent)
            .where(ScaEvent.occurred_at >= _now().replace(hour=0, minute=0, second=0, microsecond=0))
        ) or 0
        drift_total = self.db.scalar(
            select(func.count()).select_from(ConfigurationDrift)
        ) or 0
        pending_remediation = self.db.scalar(
            select(func.count())
            .select_from(RemediationAction)
            .where(RemediationAction.status == RemediationStatus.PENDING)
        ) or 0

        # Top failing checks (severity-weighted).
        failed = self.db.execute(
            select(
                PolicyCheck.id,
                PolicyCheck.check_id,
                PolicyCheck.title,
                PolicyCheck.severity,
                PolicyCheck.category,
                func.count(CheckResult.id).label("failures"),
            )
            .join(CheckResult, CheckResult.policy_check_id == PolicyCheck.id)
            .where(CheckResult.result == "failed")
            .group_by(PolicyCheck.id)
            .order_by(func.count(CheckResult.id).desc())
            .limit(10)
        ).all()
        weight = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
        top_failures = [
            {
                "id": c.id,
                "check_id": c.check_id,
                "title": c.title,
                "severity": c.severity,
                "category": c.category,
                "failures": c.failures,
                "risk": weight.get(c.severity, 1),
            }
            for c in failed
        ]

        # Risk distribution across latest scan per agent/policy.
        latest_scans = self.db.execute(
            select(PolicyScan)
            .where(PolicyScan.status == "completed")
            .order_by(PolicyScan.created_at.desc())
        ).scalars().all()
        buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        seen: set[tuple[str, str]] = set()
        for scan in latest_scans:
            key = (scan.policy_id, scan.agent_id)
            if key in seen:
                continue
            seen.add(key)
            if scan.risk_score >= 80:
                buckets["critical"] += 1
            elif scan.risk_score >= 60:
                buckets["high"] += 1
            elif scan.risk_score >= 30:
                buckets["medium"] += 1
            else:
                buckets["low"] += 1

        latest_events = self.db.execute(
            select(ScaEvent).order_by(ScaEvent.occurred_at.desc()).limit(10)
        ).scalars().all()
        agent_names = self._agent_names()
        policy_names = self._policy_names()

        return {
            "demo": settings.sca_demo_mode,
            "agents_total": len(agents),
            "agents_online": online,
            "policies_active": policies,
            "scans_total": total_scans,
            "checks_total": total_checks,
            "checks_passed": total_passed,
            "checks_failed": total_failed,
            "checks_not_applicable": total_na,
            "average_score": avg_score,
            "average_risk": avg_risk,
            "events_today": events_today,
            "drift_total": drift_total,
            "pending_remediation": pending_remediation,
            "top_failures": top_failures,
            "risk_distribution": buckets,
            "latest_events": [
                self._event_dict(e, agent_names=agent_names, policy_names=policy_names)
                for e in latest_events
            ],
        }

    # ================================================================= analysis
    async def analyze_check(self, check_result_id: str, *, force: bool = False) -> dict:
        result = self.db.get(CheckResult, check_result_id)
        if result is None:
            raise NotFoundError(f"Check result {check_result_id} not found")

        existing = self.db.scalar(
            select(Analysis).where(
                Analysis.kind == "sca_check_analysis",
                Analysis.reference_id == check_result_id,
            )
        )
        if existing is not None and not force:
            return self._analysis_dict(existing)

        check = self.db.get(PolicyCheck, result.policy_check_id)
        agent = self.db.get(Agent, result.agent_id)
        scan = self.db.get(PolicyScan, result.scan_id)
        policy = self.db.get(Policy, scan.policy_id) if scan else None

        refs = self.db.execute(
            select(ComplianceReference)
            .where(ComplianceReference.policy_check_id == result.policy_check_id)
        ).scalars().all()
        related = self.db.execute(
            select(ConfigurationDrift)
            .where(ConfigurationDrift.check_id == result.policy_check_id)
            .order_by(ConfigurationDrift.detected_at.desc())
            .limit(5)
        ).scalars().all()

        context = {
            "check_id": check.check_id if check else None,
            "title": check.title if check else "Unknown check",
            "description": check.description if check else None,
            "rationale": check.rationale if check else None,
            "remediation": check.remediation if check else None,
            "severity": check.severity if check else "medium",
            "category": check.category if check else "General",
            "result": result.result,
            "actual": result.actual_value,
            "expected": result.expected_value,
            "policy": policy.name if policy else "",
            "policy_id": policy.policy_id if policy else None,
            "agent": agent.hostname if agent else "",
            "platform": agent.platform if agent else "",
            "evidence": self._parse_json(result.evidence),
            "compliance": [
                {"framework": r.framework, "control_id": r.control_id} for r in refs
            ],
            "related_findings": [
                {
                    "previous_result": d.previous_result,
                    "current_result": d.current_result,
                    "detected_at": _iso(d.detected_at),
                }
                for d in related
            ],
        }

        provider = build_provider()
        try:
            response = await provider.analyze_sca_check(context)
        except Exception:
            log.exception("AI analyze_sca_check failed; falling back to heuristic")
            from app.agents.heuristic import HeuristicProvider

            response = await HeuristicProvider().analyze_sca_check(context)

        record = Analysis(
            kind="sca_check_analysis",
            reference_id=check_result_id,
            provider=response.provider,
            prompt=json.dumps(context, default=str),
            analysis=response.analysis,
            summary=response.summary,
            recommended_actions=json.dumps(response.recommended_actions)
            if response.recommended_actions
            else None,
            risk_score=response.risk_score,
            confidence=response.confidence,
            response=json.dumps(response.extra, default=str) if response.extra else None,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return self._analysis_dict(record)

    def list_analyses(self, *, check_result_id: str | None = None, limit: int = 50) -> list[dict]:
        query = select(Analysis).where(Analysis.kind == "sca_check_analysis")
        if check_result_id:
            query = query.where(Analysis.reference_id == check_result_id)
        rows = self.db.execute(query.order_by(Analysis.created_at.desc()).limit(limit)).scalars().all()
        return [self._analysis_dict(r) for r in rows]

    # ============================================================== remediation
    def remediations(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        status: str | None = None,
        agent_id: str | None = None,
    ) -> dict:
        query = select(RemediationAction)
        if status:
            query = query.where(RemediationAction.status == status)
        if agent_id:
            query = query.where(RemediationAction.agent_id == agent_id)
        total = self.db.scalar(
            select(func.count()).select_from(query.subquery())
        ) or 0
        total_pages = max(1, -(-total // per_page))
        safe_page = min(max(1, page), total_pages)
        rows = self.db.execute(
            query.order_by(RemediationAction.created_at.desc())
            .offset((safe_page - 1) * per_page)
            .limit(per_page)
        ).scalars().all()
        check_titles = self._check_titles([r.check_id for r in rows])
        agent_names = self._agent_names()
        return {
            "items": [
                self._remediation_dict(r, title=check_titles.get(r.check_id), agent_names=agent_names)
                for r in rows
            ],
            "total": total,
            "page": safe_page,
            "perPage": per_page,
            "totalPages": total_pages,
            "demo": settings.sca_demo_mode,
        }

    def request_remediation(self, *, check_result_id: str, description: str | None, user: Any) -> dict:
        result = self.db.get(CheckResult, check_result_id)
        if result is None:
            raise NotFoundError(f"Check result {check_result_id} not found")
        check = self.db.get(PolicyCheck, result.policy_check_id)
        existing = self.db.scalar(
            select(RemediationAction).where(
                RemediationAction.check_id == result.policy_check_id,
                RemediationAction.status.in_(
                    (RemediationStatus.PENDING, RemediationStatus.APPROVED, RemediationStatus.EXECUTING)
                ),
            )
        )
        if existing is not None:
            raise ConflictError("a remediation is already pending for this check")

        action = RemediationAction(
            check_id=result.policy_check_id,
            agent_id=result.agent_id,
            action_type="apply_benchmark_setting",
            description=description or (check.remediation if check else None),
            requested_by=user.username,
            status=RemediationStatus.PENDING,
        )
        self.db.add(action)
        self.db.commit()
        self.db.refresh(action)
        return self._remediation_dict(
            action,
            title=check.title if check else None,
            agent_names=self._agent_names(),
        )

    def approve_remediation(self, remediation_id: str, user: Any) -> dict:
        action = self.db.get(RemediationAction, remediation_id)
        if action is None:
            raise NotFoundError(f"Remediation {remediation_id} not found")
        if action.status != RemediationStatus.PENDING:
            raise ConflictError(f"remediation is '{action.status}', not pending")
        action.status = RemediationStatus.APPROVED
        action.approved_by = user.username
        self.db.commit()
        self.db.refresh(action)
        return self._remediation_dict(action, title=self._title_for(action.check_id), agent_names=self._agent_names())

    def reject_remediation(self, remediation_id: str, user: Any) -> dict:
        action = self.db.get(RemediationAction, remediation_id)
        if action is None:
            raise NotFoundError(f"Remediation {remediation_id} not found")
        if action.status != RemediationStatus.PENDING:
            raise ConflictError(f"remediation is '{action.status}', not pending")
        action.status = RemediationStatus.REJECTED
        action.approved_by = user.username
        self.db.commit()
        self.db.refresh(action)
        return self._remediation_dict(action, title=self._title_for(action.check_id), agent_names=self._agent_names())

    def execute_remediation(self, remediation_id: str, user: Any) -> dict:
        action = self.db.get(RemediationAction, remediation_id)
        if action is None:
            raise NotFoundError(f"Remediation {remediation_id} not found")
        if action.status != RemediationStatus.APPROVED:
            raise ConflictError("remediation must be approved before execution")

        action.status = RemediationStatus.EXECUTING
        self.db.commit()

        if settings.sca_demo_mode:
            action.result = "demo: remediation applied for the requested setting"
            action.status = RemediationStatus.COMPLETED
            action.executed_at = _now()
        else:
            # Real dispatch to the agent transport is agent-side; the server
            # records intent. The agent polls the result via the transport.
            action.result = "dispatched to agent for execution"
            action.status = RemediationStatus.EXECUTING
        self.db.commit()

        # Verification rescan after remediation completes.
        if action.status == RemediationStatus.COMPLETED:
            result = self.db.scalar(
                select(CheckResult).where(CheckResult.policy_check_id == action.check_id).order_by(CheckResult.created_at.desc()).limit(1)
            )
            if result is not None:
                scan = self.db.get(PolicyScan, result.scan_id)
                if scan is not None:
                    from app.sca.queue import get_scan_queue

                    verification = PolicyScan(
                        policy_id=scan.policy_id,
                        agent_id=action.agent_id,
                        policy_version=scan.policy_version,
                        status="queued",
                    )
                    self.db.add(verification)
                    self.db.commit()
                    self.db.refresh(verification)
                    get_scan_queue().enqueue(verification.id)

        self.db.refresh(action)
        return self._remediation_dict(action, title=self._title_for(action.check_id), agent_names=self._agent_names())

    # ============================================================== serializers
    def _agent_names(self) -> dict[str, str]:
        return {
            a.id: f"{a.hostname} ({a.agent_code})"
            for a in self.db.execute(select(Agent)).scalars().all()
        }

    def _policy_names(self) -> dict[str, str]:
        return {
            p.id: p.name
            for p in self.db.execute(select(Policy)).scalars().all()
        }

    def _check_titles(self, ids: list[str]) -> dict[str, str]:
        if not ids:
            return {}
        rows = self.db.execute(
            select(PolicyCheck.id, PolicyCheck.title).where(PolicyCheck.id.in_(ids))
        ).all()
        return {row[0]: row[1] for row in rows}

    def _title_for(self, check_id: str) -> str | None:
        check = self.db.get(PolicyCheck, check_id)
        return check.title if check else None

    @staticmethod
    def _parse_json(value: str | None) -> Any:
        if not value:
            return None
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return value

    def _scan_dict(
        self,
        scan: PolicyScan,
        *,
        agent_names: dict[str, str] | None = None,
        policy_names: dict[str, str] | None = None,
    ) -> dict:
        agent_names = agent_names or self._agent_names()
        policy_names = policy_names or self._policy_names()
        return {
            "id": scan.id,
            "policy_id": scan.policy_id,
            "policy": policy_names.get(scan.policy_id, scan.policy_id),
            "policy_version": scan.policy_version,
            "agent_id": scan.agent_id,
            "agent": agent_names.get(scan.agent_id, scan.agent_id),
            "status": scan.status,
            "demo": settings.sca_demo_mode,
            "started_at": _iso(scan.started_at),
            "end_scan": _iso(scan.end_scan),
            "total_checks": scan.total_checks,
            "passed": scan.passed,
            "failed": scan.failed,
            "not_applicable": scan.not_applicable,
            "error_count": scan.error_count,
            "score": scan.score,
            "risk_score": scan.risk_score,
            "critical_failures": scan.critical_failures,
            "high_failures": scan.high_failures,
            "medium_failures": scan.medium_failures,
            "low_failures": scan.low_failures,
            "duration": round(scan.duration, 2),
            "error_message": scan.error_message,
            "created_at": _iso(scan.created_at),
        }

    def _result_dict(self, result: CheckResult, check: PolicyCheck) -> dict:
        return {
            "id": result.id,
            "scan_id": result.scan_id,
            "check_id": check.check_id,
            "check_result_id": result.id,
            "title": check.title,
            "target": check.target,
            "category": check.category,
            "severity": check.severity,
            "result": result.result,
            "expected_value": result.expected_value,
            "actual_value": result.actual_value,
            "evidence": self._parse_json(result.evidence),
            "error_message": result.error_message,
            "executed_at": _iso(result.executed_at),
        }

    def _event_dict(self, event: ScaEvent, *, agent_names=None, policy_names=None) -> dict:
        agent_names = agent_names or self._agent_names()
        policy_names = policy_names or self._policy_names()
        return {
            "id": event.id,
            "event_type": event.event_type,
            "agent_id": event.agent_id,
            "agent": agent_names.get(event.agent_id) if event.agent_id else None,
            "policy_id": event.policy_id,
            "policy": policy_names.get(event.policy_id) if event.policy_id else None,
            "scan_id": event.scan_id,
            "check_id": event.check_id,
            "severity": event.severity,
            "message": event.message,
            "payload": self._parse_json(event.payload),
            "occurred_at": _iso(event.occurred_at),
        }

    def _drift_dict(self, drift: ConfigurationDrift, *, title=None, agent_names=None) -> dict:
        agent_names = agent_names or self._agent_names()
        return {
            "id": drift.id,
            "agent_id": drift.agent_id,
            "agent": agent_names.get(drift.agent_id),
            "policy_id": drift.policy_id,
            "check_id": drift.check_id,
            "title": title,
            "previous_result": drift.previous_result,
            "current_result": drift.current_result,
            "previous_value": drift.previous_value,
            "current_value": drift.current_value,
            "detected_at": _iso(drift.detected_at),
            "severity": drift.severity,
            "description": drift.description,
        }

    def _remediation_dict(self, action: RemediationAction, *, title=None, agent_names=None) -> dict:
        agent_names = agent_names or self._agent_names()
        return {
            "id": action.id,
            "check_id": action.check_id,
            "check_title": title,
            "agent_id": action.agent_id,
            "agent": agent_names.get(action.agent_id),
            "action_type": action.action_type,
            "description": action.description,
            "requested_by": action.requested_by,
            "approved_by": action.approved_by,
            "status": action.status,
            "result": action.result,
            "executed_at": _iso(action.executed_at),
            "created_at": _iso(action.created_at),
        }

    def _analysis_dict(self, record: Analysis) -> dict:
        return {
            "id": record.id,
            "kind": record.kind,
            "reference_id": record.reference_id,
            "provider": record.provider,
            "analysis": record.analysis,
            "summary": record.summary,
            "recommended_actions": self._parse_json(record.recommended_actions),
            "risk_score": record.risk_score,
            "confidence": record.confidence,
            "extra": self._parse_json(record.response),
            "created_at": _iso(record.created_at),
        }
