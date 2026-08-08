"""SCA - real (non-demo) evaluation and endpoint agent dispatch tests.

Real mode must genuinely collect endpoint evidence and evaluate it
deterministically (never fabricate). The remote path defers collection to an
authenticated endpoint agent and re-evaluates its evidence server-side.
``net accounts`` / ``tasklist`` / ``sc`` tests run for real on Windows hosts.
"""

import json
import sys

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.sca import (
    Agent,
    CheckResult,
    CheckRule,
    Policy,
    PolicyCheck,
    PolicyScan,
)
from app.sca.collectors import (
    CommandCollector,
    ProcessCollector,
    ServiceCollector,
    CollectorError,
)
from app.sca.evaluator import evaluate_rule, extract_value
from app.sca.engine import ScanEngine
from app.services.sca_service import ScaService

is_windows = sys.platform == "win32"


# ------------------------------------------------------------------ evaluator
def test_extract_value_first_capture_group():
    actual = "Length of password history maintained:        24"
    assert extract_value(r"Length of password history maintained:\s+(\d+)", actual) == "24"


def test_extract_value_whole_match_when_no_groups():
    assert extract_value(r"Audit Logon", "Audit Logon: Success and Failure") == "Audit Logon"


def test_extract_value_no_match_returns_none():
    assert extract_value(r"Maximum password age \(days\):\s+(\d+)", "nope") is None
    assert extract_value("[invalid", "x") is None


def test_evaluate_rule_with_pattern_compares_extracted_value():
    class Rule:
        operator = "gte"
        expected_value = "24"
        pattern = r"Length of password history maintained:\s+(\d+)"

    assert evaluate_rule(Rule(), "Length of password history maintained:        24") is True
    assert evaluate_rule(Rule(), "Length of password history maintained:        10") is False
    assert evaluate_rule(Rule(), "unrelated output") is False


def test_evaluate_rule_without_pattern_uses_operator_directly():
    class Rule:
        operator = "eq"
        expected_value = "enabled"
        pattern = None

    assert evaluate_rule(Rule(), " Enabled ") is True


# ---------------------------------------------------------------- collectors
def test_process_collector_rejects_injection_names():
    with pytest.raises(CollectorError):
        ProcessCollector().collect(
            type("R", (), {"process_name": "svchost.exe or imagename eq cmd"})(), "windows"
        )
    with pytest.raises(CollectorError):
        ServiceCollector().collect(
            type("R", (), {"service_name": "x && del"})(), "windows"
        )


@pytest.mark.skipif(not is_windows, reason="requires a Windows endpoint")
def test_process_collector_reads_real_state():
    evidence = ProcessCollector().collect(
        type("R", (), {"process_name": "svchost.exe"})(), "windows"
    )
    assert evidence.collected is True
    assert evidence.actual_value in ("running", "not running")


@pytest.mark.skipif(not is_windows, reason="requires a Windows endpoint")
def test_service_collector_missing_service_is_not_applicable():
    evidence = ServiceCollector().collect(
        type("R", (), {"service_name": "sca_no_such_service_xyz"})(), "windows"
    )
    assert evidence.collected is True
    assert evidence.not_applicable is True
    assert evidence.actual_value == "absent"


# ---------------------------------------------------------------- real engine
def _make_policy(db, slug: str) -> Policy:
    policy = Policy(
        policy_id=slug,
        slug=slug,
        name=f"Test policy {slug}",
        platform="windows",
        framework="CIS",
        version="v3.0.0",
        enabled=True,
    )
    db.add(policy)
    db.flush()
    return policy


def _make_check(db, policy: Policy, check_id: int = 1, title: str = "Enforce password history") -> PolicyCheck:
    check = PolicyCheck(
        policy_id=policy.id,
        check_id=check_id,
        title=title,
        target="net.exe accounts",
        severity="high",
        category="Password Policy",
        enabled=True,
    )
    db.add(check)
    db.flush()
    return check


def _make_password_history_rule(db, check: PolicyCheck) -> CheckRule:
    rule = CheckRule(
        policy_check_id=check.id,
        rule_type="command",
        command="net.exe accounts",
        pattern=r"Length of password history maintained:\s+(\d+)",
        operator="gte",
        expected_value="24",
        enabled=True,
    )
    db.add(rule)
    db.flush()
    return rule


def _make_scan(db, policy: Policy, agent: Agent) -> PolicyScan:
    scan = PolicyScan(policy_id=policy.id, agent_id=agent.id, status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@pytest.mark.skipif(not is_windows, reason="requires a Windows endpoint")
def test_engine_real_mode_evaluates_net_accounts(db, monkeypatch):
    monkeypatch.setattr(settings, "sca_demo_mode", False)
    monkeypatch.setattr(settings, "sca_agent_mode", "local")

    agent = Agent(
        agent_code="real-local-agent",
        hostname="test-host",
        operating_system="Windows 11",
        platform="windows",
        status="online",
    )
    db.add(agent)
    policy = _make_policy(db, "real-local-policy")
    check = _make_check(db, policy)
    _make_password_history_rule(db, check)
    db.commit()
    scan = _make_scan(db, policy, agent)

    ScanEngine(db).run(scan)

    assert scan.status == "completed"
    assert scan.total_checks == 1
    result = db.scalar(
        select(CheckResult).where(CheckResult.scan_id == scan.id)
    )
    assert result is not None
    assert result.result in ("passed", "failed")
    assert "Length of password history" in (result.evidence or "")


def test_engine_real_mode_honest_error_without_rule(db, monkeypatch):
    """A check without an enabled rule is an error, never a fabricated pass."""
    monkeypatch.setattr(settings, "sca_demo_mode", False)
    monkeypatch.setattr(settings, "sca_agent_mode", "local")

    agent = Agent(
        agent_code="real-no-rule",
        hostname="t",
        operating_system="Windows 11",
        platform="windows",
        status="online",
    )
    db.add(agent)
    policy = _make_policy(db, "real-no-rule-policy")
    check = _make_check(db, policy)
    db.commit()
    scan = _make_scan(db, policy, agent)

    ScanEngine(db).run(scan)

    assert scan.status == "completed"
    result = db.scalar(select(CheckResult).where(CheckResult.scan_id == scan.id))
    assert result.result == "error"
    assert "no rule defined" in (result.error_message or "")


# -------------------------------------------------------------- remote flow
def test_remote_job_and_evidence_flow(db, monkeypatch):
    monkeypatch.setattr(settings, "sca_demo_mode", False)
    monkeypatch.setattr(settings, "sca_agent_mode", "remote")

    agent = Agent(
        agent_code="real-remote-agent",
        hostname="endpoint",
        operating_system="Windows 11",
        platform="windows",
        status="online",
    )
    db.add(agent)
    policy = _make_policy(db, "real-remote-policy")
    check = _make_check(db, policy, check_id=30001)
    _make_password_history_rule(db, check)
    db.commit()
    scan = _make_scan(db, policy, agent)

    # The engine defers to the agent: the scan waits in "collecting".
    ScanEngine(db).run(scan)
    assert scan.status == "collecting"

    service = ScaService(db)
    job_payload = service.pending_job(agent.agent_code)
    assert job_payload["job"] is not None
    assert job_payload["demo"] is False
    job = job_payload["job"]
    assert job["scan_id"] == scan.id
    assert {r["check_id"] for r in job["rules"]} == {check.check_id}
    rule_spec = job["rules"][0]
    assert rule_spec["rule_type"] == "command"
    assert rule_spec["command"] == "net.exe accounts"

    # The agent collects real evidence (server still evaluates).
    rule = db.scalar(
        select(CheckRule).where(CheckRule.policy_check_id == check.id)
    )
    evidence = CommandCollector().collect(rule, "windows")
    item = {
        "check_id": check.check_id,
        "collected": evidence.collected,
        "actual_value": evidence.actual_value,
        "not_applicable": evidence.not_applicable,
        "evidence": evidence.raw,
        "message": evidence.message,
    }
    submitted = service.submit_evidence(
        scan_id=scan.id, agent_code=agent.agent_code, items=[item]
    )
    assert submitted["status"] == "completed"

    result = db.scalar(select(CheckResult).where(CheckResult.scan_id == scan.id))
    assert result is not None
    assert result.result in ("passed", "failed")
    payload = json.loads(result.evidence)
    assert payload["command"] == "net.exe accounts"


def test_remote_evidence_wrong_agent_rejected(db, monkeypatch):
    monkeypatch.setattr(settings, "sca_demo_mode", False)
    monkeypatch.setattr(settings, "sca_agent_mode", "remote")

    agent = Agent(
        agent_code="real-other-agent",
        hostname="other",
        operating_system="Windows 11",
        platform="windows",
        status="online",
    )
    db.add(agent)
    policy = _make_policy(db, "real-wrong-agent-policy")
    check = _make_check(db, policy, check_id=30002)
    _make_password_history_rule(db, check)
    db.commit()
    scan = _make_scan(db, policy, agent)
    ScanEngine(db).run(scan)

    from app.core.exceptions import ForbiddenError

    with pytest.raises(ForbiddenError):
        ScaService(db).submit_evidence(
            scan_id=scan.id, agent_code="001", items=[{"check_id": check.check_id}]
        )


# ---------------------------------------------------------------- demo flag
def test_demo_flag_reflects_mode(client, admin_headers, db):
    assert client.get("/api/v1/sca/dashboard", headers=admin_headers).json()["demo"] is True
    scans = client.get("/api/v1/sca/scans", headers=admin_headers).json()
    assert scans["demo"] is True
    assert all(a["demo"] is True for a in client.get("/api/v1/sca/agents", headers=admin_headers).json())


def test_jobs_and_evidence_endpoints_require_valid_api_key(client, db):
    assert client.get("/api/v1/sca/agents/001/jobs", headers={"X-API-Key": "bogus"}).status_code == 401
    assert (
        client.post(
            "/api/v1/sca/scans/whatever/evidence",
            json={"agent_code": "001", "items": []},
            headers={"X-API-Key": "bogus"},
        ).status_code
        == 401
    )
