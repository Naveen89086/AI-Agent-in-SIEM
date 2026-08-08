"""Security Configuration Assessment policy models.

An SCA ``Policy`` is a versioned security benchmark (CIS, NIST-aligned,
custom). Each policy contains ``PolicyCheck`` definitions; every check can
carry one or more ``CheckRule`` records that tell a collector what to read on
the endpoint and what to compare it against. ``ComplianceReference`` maps
checks to external framework controls (CIS, NIST, ISO 27001, PCI DSS).
"""

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

SEVERITIES = ("critical", "high", "medium", "low", "info")

RULE_TYPES = (
    "command",
    "registry",
    "file",
    "directory",
    "process",
    "service",
    "configuration",
)

FRAMEWORKS = ("CIS", "NIST", "ISO 27001", "PCI DSS")


class Policy(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A configuration benchmark (e.g. CIS Microsoft Windows 11 v3.0.0)."""

    __tablename__ = "policies"

    policy_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    framework: Mapped[str] = mapped_column(String(32), default="CIS", nullable=False)
    version: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    platform: Mapped[str] = mapped_column(String(32), default="windows", nullable=False)
    benchmark: Mapped[str | None] = mapped_column(String(256), nullable=True)
    publisher: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)  # active|retired|draft
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    rows_per_page: Mapped[int] = mapped_column(Integer, default=15, nullable=False)

    def __repr__(self) -> str:
        return f"<Policy {self.policy_id} v{self.version} ({self.platform})>"


class PolicyCheck(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A single check inside a policy benchmark."""

    __tablename__ = "policy_checks"

    policy_id: Mapped[str] = mapped_column(
        String(36), index=True, nullable=False
    )
    check_id: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    rationale: Mapped[str | None] = mapped_column(String, nullable=True)
    remediation: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="General", nullable=False)
    platform: Mapped[str] = mapped_column(String(32), default="windows", nullable=False)
    version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    target: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    # Demo/last-known result. Real scan outcomes live in CheckResult.
    result: Mapped[str | None] = mapped_column(String(16), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<PolicyCheck {self.check_id} ({self.severity})>"


class CheckRule(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """A rule telling a collector what to read and how to evaluate it."""

    __tablename__ = "check_rules"

    policy_check_id: Mapped[str] = mapped_column(
        String(36), index=True, nullable=False
    )
    rule_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str | None] = mapped_column(String(256), nullable=True)
    operator: Mapped[str] = mapped_column(String(16), default="eq", nullable=False)
    # Extraction regex: when set, the engine extracts the first capture group
    # (or the whole match) from the collected value and compares it against
    # ``expected_value`` with ``operator`` (e.g. net accounts -> history >= 24).
    pattern: Mapped[str | None] = mapped_column(String(512), nullable=True)
    expected_value: Mapped[str | None] = mapped_column(String, nullable=True)
    command: Mapped[str | None] = mapped_column(String(512), nullable=True)
    registry_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    registry_value: Mapped[str | None] = mapped_column(String(256), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    directory_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    configuration_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    condition: Mapped[str | None] = mapped_column(String, nullable=True)  # JSON dict
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<CheckRule {self.rule_type}:{self.target} {self.operator} {self.expected_value}>"


class ComplianceReference(Base, TimestampMixin, UUIDPrimaryKeyMixin):
    """Mapping of a policy check to an external framework control."""

    __tablename__ = "compliance_references"

    policy_check_id: Mapped[str] = mapped_column(
        String(36), index=True, nullable=False
    )
    framework: Mapped[str] = mapped_column(String(32), nullable=False)
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    control_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    def __repr__(self) -> str:
        return f"<ComplianceReference {self.framework}:{self.control_id}>"
