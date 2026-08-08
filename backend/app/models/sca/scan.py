"""SCA scan and per-check result models.

``PolicyScan`` holds one scan run of a policy against one agent (scan states:
queued / running / collecting / evaluating / completed / failed / cancelled).
``CheckResult`` stores the per-check outcome with evidence so every scan has a
full, immutable history.
"""

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ScanStatus:
    QUEUED = "queued"
    RUNNING = "running"
    COLLECTING = "collecting"
    EVALUATING = "evaluating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    CHOICES = (QUEUED, RUNNING, COLLECTING, EVALUATING, COMPLETED, FAILED, CANCELLED)

    ACTIVE = (QUEUED, RUNNING, COLLECTING, EVALUATING)


class PolicyScan(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """One scan run of a policy against an agent."""

    __tablename__ = "policy_scans"

    policy_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    # Policy version captured at scan time so historical scans stay comparable.
    policy_version: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(16), default=ScanStatus.QUEUED, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_scan: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_checks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    passed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    not_applicable: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(String, nullable=True)

    def __repr__(self) -> str:
        return f"<PolicyScan {self.status} policy={self.policy_id} agent={self.agent_id}>"


class CheckResult(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """The outcome and evidence of one check within one scan."""

    __tablename__ = "check_results"

    scan_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    policy_check_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    result: Mapped[str] = mapped_column(String(16), nullable=False)  # passed|failed|not_applicable|error
    expected_value: Mapped[str | None] = mapped_column(String, nullable=True)
    actual_value: Mapped[str | None] = mapped_column(String, nullable=True)
    evidence: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON dict
    error_message: Mapped[str | None] = mapped_column(String, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_duration: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    def __repr__(self) -> str:
        return f"<CheckResult {self.result} check={self.policy_check_id} scan={self.scan_id}>"
