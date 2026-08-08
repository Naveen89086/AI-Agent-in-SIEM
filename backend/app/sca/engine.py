"""SCA scan engine.

Executes a ``PolicyScan`` job: for every enabled check of the policy it either
collects real endpoint evidence and evaluates it deterministically (real mode)
or produces the deterministic demo outcome (demo mode), persists one
``CheckResult`` per check, finalizes the scan totals and then emits scan
events and configuration drift records.

Real mode never fabricates a PASS/FAIL/evidence value: missing or failed
collection is recorded as ``error``. With ``sca_agent_mode=remote`` the engine
defers collection to the endpoint agent (status ``collecting``) and finalizes
only when the agent submits evidence, which is always evaluated server-side.
"""

import json
import logging
import time
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.sca import (
    Agent,
    CheckResult,
    CheckRule,
    ConfigurationDrift,
    Policy,
    PolicyCheck,
    PolicyScan,
    ScanStatus,
    ScaEvent,
)
from app.sca.collectors import collect_evidence
from app.sca.evaluator import evaluate_rule

log = logging.getLogger("siem.sca.engine")

_SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}


def risk_score(severity_counts: dict[str, int], total_checks: int) -> int:
    """Weighted failures as a fraction of the worst-case posture (0-100)."""
    weighted = sum(
        count * _SEVERITY_WEIGHTS.get(sev, 0)
        for sev, count in severity_counts.items()
    )
    if not total_checks:
        return 0
    return min(100, round(weighted * 100 / (10 * total_checks)))


def compliance_score(passed: int, failed: int) -> int:
    """Compliance % excludes not-applicable and error checks (0-100)."""
    total = passed + failed
    if not total:
        return 0
    return round(passed * 100 / total)


class ScanEngine:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------ run
    def run(self, scan: PolicyScan) -> None:
        started = time.monotonic()
        now = datetime.now(timezone.utc)

        scan.status = ScanStatus.RUNNING
        scan.started_at = now
        self.db.commit()

        policy = self.db.get(Policy, scan.policy_id)
        agent = self.db.get(Agent, scan.agent_id)
        if policy is None or agent is None:
            self._fail(scan, "policy or agent not found", started)
            return

        if self._remote_mode():
            # The endpoint agent collects the evidence: mark the scan as
            # collecting and wait for the agent to submit evidence. The scan
            # is finalized by ``finalize_remote`` when evidence arrives.
            scan.status = ScanStatus.COLLECTING
            self.db.commit()
            return

        self._run_local(scan, policy, agent, started)

    @staticmethod
    def _remote_mode() -> bool:
        return not settings.sca_demo_mode and settings.sca_agent_mode == "remote"

    def _run_local(self, scan, policy, agent, started) -> None:
        checks = list(
            self.db.execute(
                select(PolicyCheck)
                .where(PolicyCheck.policy_id == policy.id, PolicyCheck.enabled.is_(True))
                .order_by(PolicyCheck.check_id)
            ).scalars().all()
        )
        rules = self._rules_by_check(checks)

        counts = {"passed": 0, "failed": 0, "not_applicable": 0, "error": 0}
        severity_failures = {sev: 0 for sev in _SEVERITY_WEIGHTS}

        if not settings.sca_demo_mode:
            scan.status = ScanStatus.COLLECTING
            self.db.commit()
            scan.status = ScanStatus.EVALUATING
            self.db.commit()

        try:
            for check in checks:
                result, actual, evidence, message = self._evaluate(
                    check, rules.get(check.id), agent, policy.platform
                )
                counts[result] += 1
                if result == "failed":
                    severity_failures[check.severity] = (
                        severity_failures.get(check.severity, 0) + 1
                    )
                rule = (rules.get(check.id) or [None])[0]
                self.db.add(
                    CheckResult(
                        scan_id=scan.id,
                        policy_check_id=check.id,
                        agent_id=agent.id,
                        result=result,
                        expected_value=rule.expected_value if rule else None,
                        actual_value=actual,
                        evidence=evidence,
                        error_message=message,
                        executed_at=datetime.now(timezone.utc),
                        execution_duration=0.0,
                    )
                )
            self.db.flush()
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("scan %s failed mid-run", scan.id)
            self.db.rollback()
            self._fail(scan, f"scan aborted: {exc}", started)
            return

        self._finalize(scan, policy, agent, len(checks), counts, severity_failures, started)

    def _finalize(
        self,
        scan: PolicyScan,
        policy: Policy,
        agent: Agent,
        total_checks: int,
        counts: dict[str, int],
        severity_failures: dict[str, int],
        started: float,
    ) -> None:
        passed, failed = counts["passed"], counts["failed"]
        scan.status = ScanStatus.COMPLETED
        scan.policy_version = policy.version
        scan.total_checks = total_checks
        scan.passed = passed
        scan.failed = failed
        scan.not_applicable = counts["not_applicable"]
        scan.error_count = counts["error"]
        scan.score = compliance_score(passed, failed)
        scan.risk_score = risk_score(severity_failures, total_checks)
        scan.critical_failures = severity_failures["critical"]
        scan.high_failures = severity_failures["high"]
        scan.medium_failures = severity_failures["medium"]
        scan.low_failures = severity_failures["low"]
        scan.end_scan = datetime.now(timezone.utc)
        scan.duration = time.monotonic() - started
        scan.error_message = None
        self.db.commit()

        self._emit_events_and_drift(scan, policy, agent)

    def finalize_remote(self, scan: PolicyScan, records: list[dict]) -> None:
        """Evaluate evidence submitted by an endpoint agent and finalize.

        The agent only collects - every PASS/FAIL/not_applicable/error is
        decided here against the stored rule definitions, never by the agent.
        """
        started = time.monotonic()
        policy = self.db.get(Policy, scan.policy_id)
        agent = self.db.get(Agent, scan.agent_id)
        if policy is None or agent is None:
            self._fail(scan, "policy or agent not found", started)
            return

        checks = list(
            self.db.execute(
                select(PolicyCheck)
                .where(PolicyCheck.policy_id == policy.id, PolicyCheck.enabled.is_(True))
                .order_by(PolicyCheck.check_id)
            ).scalars().all()
        )
        check_by_id = {check.check_id: check for check in checks}
        rules = self._rules_by_check(checks)

        counts = {"passed": 0, "failed": 0, "not_applicable": 0, "error": 0}
        severity_failures = {sev: 0 for sev in _SEVERITY_WEIGHTS}
        now = datetime.now(timezone.utc)

        scan.status = ScanStatus.EVALUATING
        self.db.commit()

        try:
            for record in records:
                check = check_by_id.get(record.get("check_id"))
                if check is None:
                    counts["error"] += 1
                    continue
                rule = (rules.get(check.id) or [None])[0]
                result, actual, evidence, message = self._evaluate_evidence(
                    check, rule, record
                )
                counts[result] += 1
                if result == "failed":
                    severity_failures[check.severity] = (
                        severity_failures.get(check.severity, 0) + 1
                    )
                self.db.add(
                    CheckResult(
                        scan_id=scan.id,
                        policy_check_id=check.id,
                        agent_id=agent.id,
                        result=result,
                        expected_value=rule.expected_value if rule else None,
                        actual_value=actual,
                        evidence=evidence,
                        error_message=message,
                        executed_at=now,
                        execution_duration=0.0,
                    )
                )
            self.db.flush()
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("scan %s evidence failed", scan.id)
            self.db.rollback()
            self._fail(scan, f"evidence rejected: {exc}", started)
            return

        self._finalize(scan, policy, agent, len(checks), counts, severity_failures, started)

    def _fail(self, scan: PolicyScan, message: str, started: float) -> None:
        scan.status = "failed"
        scan.error_message = message[:500]
        scan.end_scan = datetime.now(timezone.utc)
        scan.duration = time.monotonic() - started
        self.db.commit()
        self.db.add(
            ScaEvent(
                event_type="scan_failed",
                agent_id=scan.agent_id,
                policy_id=scan.policy_id,
                scan_id=scan.id,
                severity="high",
                message=message,
                occurred_at=datetime.now(timezone.utc),
            )
        )
        self.db.commit()

    # ------------------------------------------------------------- evaluate
    def _rules_by_check(self, checks: list[PolicyCheck]) -> dict[str, list[CheckRule]]:
        ids = [c.id for c in checks]
        rows = self.db.execute(
            select(CheckRule).where(
                CheckRule.policy_check_id.in_(ids),
                CheckRule.enabled.is_(True),
            )
        ).scalars().all()
        grouped: dict[str, list[CheckRule]] = {}
        for rule in rows:
            grouped.setdefault(rule.policy_check_id, []).append(rule)
        return grouped

    def _evaluate(self, check, rules, agent, platform):
        rule = (rules or [None])[0]
        if rule is None:
            return "error", None, None, "no rule defined for check"
        try:
            if settings.sca_demo_mode:
                return self._demo_result(check, rule, agent)
            evidence = collect_evidence(rule, platform)
            payload = json.dumps(evidence.raw, default=str)
            if evidence.not_applicable:
                return "not_applicable", evidence.actual_value, payload, evidence.message or None
            if not evidence.collected:
                return "error", evidence.actual_value, payload, evidence.message or "collection failed"
            ok = evaluate_rule(rule, evidence.actual_value)
            return ("passed" if ok else "failed"), evidence.actual_value, payload, None
        except Exception as exc:
            return (
                "error",
                None,
                json.dumps({"error": str(exc)}, default=str),
                str(exc)[:300],
            )

    def _evaluate_evidence(self, check, rule, record):
        """Server-side evaluation of evidence collected by an endpoint agent."""
        if rule is None:
            return "error", None, None, "no rule defined for check"
        collected = bool(record.get("collected"))
        actual = record.get("actual_value")
        not_applicable = bool(record.get("not_applicable"))
        payload = json.dumps(record.get("evidence") or {}, default=str)
        if not_applicable:
            return "not_applicable", actual, payload, record.get("message")
        if not collected:
            return "error", actual, payload, record.get("message") or "collection failed"
        ok = evaluate_rule(rule, actual)
        return ("passed" if ok else "failed"), actual, payload, None

    def _demo_result(self, check, rule, agent):
        """Deterministic demo outcome + evidence (matches the seed data)."""
        from app.services.endpoint_seed import _outcome_for

        outcome = _outcome_for(check.check_id, agent.agent_code)
        expected = rule.expected_value
        if outcome == "passed":
            actual = expected
        elif outcome == "not_applicable":
            actual = "N/A"
        else:
            actual = "Disabled" if check.check_id % 2 == 0 else "0"
        evidence = json.dumps(
            {"source": "Demo collector", "check_id": check.check_id, "title": check.title}
        )
        return outcome, actual, evidence, None

    # ------------------------------------------------------- events + drift
    def _emit_events_and_drift(self, scan: PolicyScan, policy: Policy, agent: Agent) -> None:
        now = datetime.now(timezone.utc)
        self.db.add(
            ScaEvent(
                event_type="scan_completed",
                agent_id=agent.id,
                policy_id=policy.id,
                scan_id=scan.id,
                severity="info",
                message=(
                    f"Scan completed for {policy.name} on {agent.hostname}: "
                    f"{scan.passed} passed, {scan.failed} failed, {scan.not_applicable} n/a"
                ),
                payload=json.dumps(
                    {"passed": scan.passed, "failed": scan.failed, "score": scan.score}
                ),
                occurred_at=now,
            )
        )
        if scan.critical_failures:
            self.db.add(
                ScaEvent(
                    event_type="critical_check_failed",
                    agent_id=agent.id,
                    policy_id=policy.id,
                    scan_id=scan.id,
                    severity="critical",
                    message=f"{scan.critical_failures} critical check(s) failed",
                    occurred_at=now,
                )
            )
        self.db.commit()
        self._detect_drift(scan, agent, policy)

    def _detect_drift(self, scan: PolicyScan, agent: Agent, policy: Policy) -> None:
        prev = self.db.scalar(
            select(PolicyScan)
            .where(
                PolicyScan.policy_id == scan.policy_id,
                PolicyScan.agent_id == scan.agent_id,
                PolicyScan.id != scan.id,
                PolicyScan.status == "completed",
            )
            .order_by(PolicyScan.end_scan.desc())
            .limit(1)
        )
        if prev is None:
            return

        prev_results = {
            r.policy_check_id: r
            for r in self.db.execute(
                select(CheckResult).where(CheckResult.scan_id == prev.id)
            ).scalars().all()
        }
        current_results = {
            r.policy_check_id: r
            for r in self.db.execute(
                select(CheckResult).where(CheckResult.scan_id == scan.id)
            ).scalars().all()
        }
        check_ids = list(current_results) + list(prev_results)
        severities = {
            pc.id: pc.severity
            for pc in self.db.execute(
                select(PolicyCheck).where(PolicyCheck.id.in_(check_ids))
            ).scalars().all()
        }
        now = datetime.now(timezone.utc)
        for check_id, cur in current_results.items():
            old = prev_results.get(check_id)
            if old is None or old.result == cur.result:
                continue
            if old.result not in ("passed", "failed") or cur.result not in ("passed", "failed"):
                continue
            severity = severities.get(check_id, "medium")
            self.db.add(
                ConfigurationDrift(
                    agent_id=agent.id,
                    policy_id=policy.id,
                    check_id=check_id,
                    previous_result=old.result,
                    current_result=cur.result,
                    previous_value=old.actual_value,
                    current_value=cur.actual_value,
                    detected_at=now,
                    severity=severity,
                    description=(
                        f"check outcome changed from {old.result} to {cur.result}"
                        f" between scans {prev.id[:8]} and {scan.id[:8]}"
                    ),
                )
            )
            self.db.add(
                ScaEvent(
                    event_type="configuration_changed",
                    agent_id=agent.id,
                    policy_id=policy.id,
                    scan_id=scan.id,
                    check_id=check_id,
                    severity=severity,
                    message=f"check {check_id[:8]} outcome changed {old.result} -> {cur.result}",
                    occurred_at=now,
                )
            )
        self.db.commit()
