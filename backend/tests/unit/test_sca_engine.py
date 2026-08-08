"""SCA - scan engine scores and drift detection tests."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.models.sca import (
    Agent,
    CheckResult,
    ConfigurationDrift,
    Policy,
    PolicyCheck,
    PolicyScan,
    ScaEvent,
)
from app.sca.engine import ScanEngine, compliance_score, risk_score


# -------------------------------------------------------------------- scoring
def test_compliance_score_excludes_na_and_zero_safe():
    assert compliance_score(120, 355) == 25
    assert compliance_score(0, 0) == 0
    assert compliance_score(200, 0) == 100


def test_risk_score_weights():
    # one critical failure out of 100 checks -> (10/1000)*100 = 1
    assert risk_score({"critical": 1, "high": 0, "medium": 0, "low": 0}, 100) == 1
    # one low failure out of 100 -> (1/1000)*100 = 0.1 -> 0
    assert risk_score({"low": 1, "high": 0, "medium": 0, "critical": 0}, 100) == 0
    # all critical -> 100
    assert risk_score({"critical": 100}, 100) == 100
    assert risk_score({"high": 100}, 100) == 60
    # zero total -> 0
    assert risk_score({"critical": 1}, 0) == 0
    # saturates at 100
    assert risk_score({"critical": 200}, 100) == 100
    # unknown severities are ignored
    assert risk_score({"critical": 1, "bogus": 99}, 100) == 1


def test_risk_score_mixed():
    counts = {"critical": 3, "high": 5, "medium": 2, "low": 1}
    weighted = 3 * 10 + 5 * 6 + 2 * 3 + 1 * 1
    assert risk_score(counts, 100) == round(weighted * 100 / (10 * 100))


# --------------------------------------------------------------------- drift
def _scan(db, *, policy_id, agent_id, status="completed", end_offset=0):
    scan = PolicyScan(
        policy_id=policy_id,
        agent_id=agent_id,
        status=status,
        end_scan=datetime.now(timezone.utc) - timedelta(seconds=end_offset),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _reset_scan_times(db, policy_id, agent_id):
    """Age every other completed scan for the pair so our test scans are newest.

    Other tests create scans through the API whose worker thread completes them
    with a real (current) end_scan; drift detection compares against the newest
    completed scan, so we push those rows into the past.
    """
    from sqlalchemy import update

    db.execute(
        update(PolicyScan)
        .where(
            PolicyScan.policy_id == policy_id,
            PolicyScan.agent_id == agent_id,
            PolicyScan.status == "completed",
        )
        .values(end_scan=datetime.now(timezone.utc) - timedelta(days=1))
    )
    db.commit()


def _result(db, scan, check_id, result, value):
    db.add(
        CheckResult(
            scan_id=scan.id,
            policy_check_id=check_id,
            agent_id=scan.agent_id,
            result=result,
            actual_value=value,
            executed_at=datetime.now(timezone.utc),
        )
    )


def test_drift_detected_only_on_outcome_changes(client, db):
    policy = db.execute(
        select(Policy).where(Policy.enabled.is_(True)).limit(1)
    ).scalar_one()
    agent = db.execute(
        select(Agent).where(Agent.agent_code == "001")
    ).scalar_one()
    checks = db.execute(
        select(PolicyCheck)
        .where(PolicyCheck.policy_id == policy.id)
        .order_by(PolicyCheck.check_id)
        .limit(3)
    ).scalars().all()
    c_ok, c_improve, c_regress = checks

    _reset_scan_times(db, policy.id, agent.id)
    previous = _scan(db, policy_id=policy.id, agent_id=agent.id, end_offset=120)
    _result(db, previous, c_ok.id, "passed", "enabled")
    _result(db, previous, c_improve.id, "failed", "disabled")
    _result(db, previous, c_regress.id, "passed", "enabled")
    db.commit()

    current = _scan(db, policy_id=policy.id, agent_id=agent.id)
    _result(db, current, c_ok.id, "passed", "enabled")
    _result(db, current, c_improve.id, "passed", "enabled")  # improvement
    _result(db, current, c_regress.id, "failed", "disabled")  # regression
    db.commit()

    ScanEngine(db)._detect_drift(current, agent, policy)
    db.commit()

    drifts = db.execute(select(ConfigurationDrift)).scalars().all()
    changed = {(d.check_id, d.previous_result, d.current_result) for d in drifts}
    assert (c_improve.id, "failed", "passed") in changed
    assert (c_regress.id, "passed", "failed") in changed
    assert (c_ok.id, "passed", "passed") not in changed

    events = db.execute(
        select(ScaEvent).where(ScaEvent.event_type == "configuration_changed")
    ).scalars().all()
    changed_event_checks = {e.check_id for e in events if e.scan_id == current.id}
    assert {c_improve.id, c_regress.id}.issubset(changed_event_checks)
    assert c_ok.id not in changed_event_checks


def test_drift_ignores_na_and_error_transitions(client, db):
    policy = db.execute(
        select(Policy).where(Policy.enabled.is_(True)).limit(1)
    ).scalar_one()
    agent = db.execute(
        select(Agent).where(Agent.agent_code == "001")
    ).scalar_one()
    check = db.execute(
        select(PolicyCheck)
        .where(PolicyCheck.policy_id == policy.id)
        .order_by(PolicyCheck.check_id)
        .limit(1)
    ).scalar_one()

    previous = _scan(db, policy_id=policy.id, agent_id=agent.id, end_offset=60)
    _result(db, previous, check.id, "not_applicable", "absent")
    db.commit()

    current = _scan(db, policy_id=policy.id, agent_id=agent.id)
    _result(db, current, check.id, "passed", "enabled")
    db.commit()

    ScanEngine(db)._detect_drift(current, agent, policy)
    drifts = db.execute(select(ConfigurationDrift)).scalars().all()
    assert all(d.check_id != check.id for d in drifts)


def test_drift_none_when_first_scan(client, db):
    policy = db.execute(
        select(Policy).where(Policy.enabled.is_(True)).limit(1)
    ).scalar_one()
    agent = db.execute(
        select(Agent).where(Agent.agent_code == "001")
    ).scalar_one()
    check = db.execute(
        select(PolicyCheck)
        .where(PolicyCheck.policy_id == policy.id)
        .order_by(PolicyCheck.check_id)
        .limit(1)
    ).scalar_one()
    before = db.execute(
        select(func.count()).select_from(ConfigurationDrift)
    ).scalar_one()
    scan = _scan(db, policy_id=policy.id, agent_id=agent.id)
    _result(db, scan, check.id, "passed", "enabled")
    db.commit()
    ScanEngine(db)._detect_drift(scan, agent, policy)
    db.commit()
    after = db.execute(
        select(func.count()).select_from(ConfigurationDrift)
    ).scalar_one()
    assert after == before
