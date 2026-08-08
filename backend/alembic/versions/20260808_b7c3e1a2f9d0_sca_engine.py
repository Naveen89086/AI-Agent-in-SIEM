"""SCA engine: policy/scan models + agent, rules, results, drift, remediation.

Upgrade Configuration Assessment into the full SCA subsystem:
  - extends policies / policy_checks / policy_scans with new columns
  - adds sca_agents, check_rules, compliance_references, check_results,
    configuration_drifts, sca_events, remediation_actions
  - backfills sca_agents from the existing syscheck agents and repoints
    historical policy_scans at the SCA agent rows.

The migration is adaptive: it works on a fresh (empty) database created only
through Alembic as well as on an existing development database where the
policy tables were created earlier via Base.metadata.create_all.

Revision ID: b7c3e1a2f9d0
Revises: 8a426d08d796
Create Date: 2026-08-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b7c3e1a2f9d0"
down_revision: str | None = "8a426d08d796"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _tables() -> tuple[set[str], dict[str, set[str]]]:
    """Return (table names, column names per table) from the live connection."""
    insp = sa.inspect(op.get_bind())
    names = set(insp.get_table_names())
    cols = {name: {c["name"] for c in insp.get_columns(name)} for name in names}
    return names, cols


def _add_column(table: str, column: sa.Column) -> None:
    names, cols = _tables()
    if table in names and column.name not in cols[table]:
        op.add_column(table, column)


def upgrade() -> None:
    tables, cols = _tables()

    # ------------------------------------------------------------- policies
    if "policies" not in tables:
        op.create_table(
            "policies",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("policy_id", sa.String(64), nullable=False, unique=True),
            sa.Column("name", sa.String(256), nullable=False),
            sa.Column("slug", sa.String(64), nullable=False, unique=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("framework", sa.String(32), nullable=False, server_default="CIS"),
            sa.Column("version", sa.String(16), nullable=False, server_default=""),
            sa.Column("platform", sa.String(32), nullable=False, server_default="windows"),
            sa.Column("benchmark", sa.String(256), nullable=True),
            sa.Column("publisher", sa.String(128), nullable=True),
            sa.Column("status", sa.String(16), nullable=False, server_default="active"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("rows_per_page", sa.Integer(), nullable=False, server_default="15"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_policies_policy_id", "policies", ["policy_id"])
        op.create_index("ix_policies_slug", "policies", ["slug"])
    else:
        _add_column(
            "policies",
            sa.Column("policy_id", sa.String(64), nullable=True),
        )
        _add_column("policies", sa.Column("description", sa.Text(), nullable=True))
        _add_column(
            "policies",
            sa.Column("framework", sa.String(32), nullable=False, server_default="CIS"),
        )
        _add_column(
            "policies",
            sa.Column("version", sa.String(16), nullable=False, server_default=""),
        )
        _add_column(
            "policies",
            sa.Column("platform", sa.String(32), nullable=False, server_default="windows"),
        )
        _add_column("policies", sa.Column("benchmark", sa.String(256), nullable=True))
        _add_column("policies", sa.Column("publisher", sa.String(128), nullable=True))
        _add_column(
            "policies",
            sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        )
        _add_column(
            "policies",
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        )
        if "policy_id" not in cols["policies"]:
            op.execute("UPDATE policies SET policy_id = slug WHERE policy_id IS NULL OR policy_id = ''")

    # --------------------------------------------------------- policy_checks
    if "policy_checks" not in tables:
        op.create_table(
            "policy_checks",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("policy_id", sa.String(36), nullable=False),
            sa.Column("check_id", sa.Integer(), nullable=False),
            sa.Column("title", sa.String(256), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("rationale", sa.Text(), nullable=True),
            sa.Column("remediation", sa.Text(), nullable=True),
            sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
            sa.Column("category", sa.String(64), nullable=False, server_default="General"),
            sa.Column("platform", sa.String(32), nullable=False, server_default="windows"),
            sa.Column("version", sa.String(16), nullable=True),
            sa.Column("target", sa.String(128), nullable=False, server_default=""),
            sa.Column("result", sa.String(16), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_policy_checks_policy_id", "policy_checks", ["policy_id"])
    else:
        _add_column("policy_checks", sa.Column("description", sa.Text(), nullable=True))
        _add_column("policy_checks", sa.Column("rationale", sa.Text(), nullable=True))
        _add_column("policy_checks", sa.Column("remediation", sa.Text(), nullable=True))
        _add_column(
            "policy_checks",
            sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
        )
        _add_column(
            "policy_checks",
            sa.Column("category", sa.String(64), nullable=False, server_default="General"),
        )
        _add_column(
            "policy_checks",
            sa.Column("platform", sa.String(32), nullable=False, server_default="windows"),
        )
        _add_column("policy_checks", sa.Column("version", sa.String(16), nullable=True))
        _add_column(
            "policy_checks",
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        )

    # ------------------------------------------------------------ policy_scans
    if "policy_scans" not in tables:
        op.create_table(
            "policy_scans",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("policy_id", sa.String(36), nullable=False),
            sa.Column("agent_id", sa.String(36), nullable=False),
            sa.Column("policy_version", sa.String(16), nullable=False, server_default=""),
            sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("end_scan", sa.DateTime(timezone=True), nullable=True),
            sa.Column("total_checks", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("passed", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("failed", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("not_applicable", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("critical_failures", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("high_failures", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("medium_failures", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("low_failures", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("duration", sa.Float(), nullable=False, server_default="0"),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_policy_scans_policy_id", "policy_scans", ["policy_id"])
        op.create_index("ix_policy_scans_agent_id", "policy_scans", ["agent_id"])
    else:
        _add_column("policy_scans", sa.Column("policy_version", sa.String(16), nullable=False, server_default=""))
        _add_column("policy_scans", sa.Column("status", sa.String(16), nullable=False, server_default="queued"))
        _add_column("policy_scans", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
        _add_column("policy_scans", sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"))
        _add_column("policy_scans", sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"))
        _add_column("policy_scans", sa.Column("critical_failures", sa.Integer(), nullable=False, server_default="0"))
        _add_column("policy_scans", sa.Column("high_failures", sa.Integer(), nullable=False, server_default="0"))
        _add_column("policy_scans", sa.Column("medium_failures", sa.Integer(), nullable=False, server_default="0"))
        _add_column("policy_scans", sa.Column("low_failures", sa.Integer(), nullable=False, server_default="0"))
        _add_column("policy_scans", sa.Column("duration", sa.Float(), nullable=False, server_default="0"))
        _add_column("policy_scans", sa.Column("error_message", sa.Text(), nullable=True))

    # ------------------------------------------------------------- new tables
    if "sca_agents" not in tables:
        op.create_table(
            "sca_agents",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("agent_code", sa.String(64), nullable=False, unique=True),
            sa.Column("hostname", sa.String(255), nullable=False),
            sa.Column("ip_address", sa.String(64), nullable=True),
            sa.Column("operating_system", sa.String(255), nullable=False),
            sa.Column("platform", sa.String(32), nullable=False, server_default="windows"),
            sa.Column("version", sa.String(32), nullable=True),
            sa.Column("status", sa.String(16), nullable=False, server_default="unknown"),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("transport_url", sa.String(512), nullable=True),
            sa.Column("api_key_hash", sa.String(128), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_sca_agents_agent_code", "sca_agents", ["agent_code"])

    if "check_rules" not in tables:
        op.create_table(
            "check_rules",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("policy_check_id", sa.String(36), nullable=False),
            sa.Column("rule_type", sa.String(32), nullable=False),
            sa.Column("target", sa.String(256), nullable=True),
            sa.Column("operator", sa.String(16), nullable=False, server_default="eq"),
            sa.Column("expected_value", sa.Text(), nullable=True),
            sa.Column("command", sa.String(512), nullable=True),
            sa.Column("registry_path", sa.String(512), nullable=True),
            sa.Column("registry_value", sa.String(256), nullable=True),
            sa.Column("file_path", sa.String(512), nullable=True),
            sa.Column("directory_path", sa.String(512), nullable=True),
            sa.Column("process_name", sa.String(256), nullable=True),
            sa.Column("service_name", sa.String(256), nullable=True),
            sa.Column("configuration_key", sa.String(256), nullable=True),
            sa.Column("condition", sa.Text(), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_check_rules_policy_check_id", "check_rules", ["policy_check_id"])

    if "compliance_references" not in tables:
        op.create_table(
            "compliance_references",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("policy_check_id", sa.String(36), nullable=False),
            sa.Column("framework", sa.String(32), nullable=False),
            sa.Column("control_id", sa.String(64), nullable=False),
            sa.Column("control_name", sa.String(256), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_compliance_references_policy_check_id", "compliance_references", ["policy_check_id"])

    if "check_results" not in tables:
        op.create_table(
            "check_results",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("scan_id", sa.String(36), nullable=False),
            sa.Column("policy_check_id", sa.String(36), nullable=False),
            sa.Column("agent_id", sa.String(36), nullable=False),
            sa.Column("result", sa.String(16), nullable=False),
            sa.Column("expected_value", sa.Text(), nullable=True),
            sa.Column("actual_value", sa.Text(), nullable=True),
            sa.Column("evidence", sa.Text(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("execution_duration", sa.Float(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_check_results_scan_id", "check_results", ["scan_id"])
        op.create_index("ix_check_results_policy_check_id", "check_results", ["policy_check_id"])
        op.create_index("ix_check_results_agent_id", "check_results", ["agent_id"])

    if "configuration_drifts" not in tables:
        op.create_table(
            "configuration_drifts",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("agent_id", sa.String(36), nullable=False),
            sa.Column("policy_id", sa.String(36), nullable=False),
            sa.Column("check_id", sa.String(36), nullable=False),
            sa.Column("previous_result", sa.String(16), nullable=False),
            sa.Column("current_result", sa.String(16), nullable=False),
            sa.Column("previous_value", sa.Text(), nullable=True),
            sa.Column("current_value", sa.Text(), nullable=True),
            sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_configuration_drifts_agent_id", "configuration_drifts", ["agent_id"])
        op.create_index("ix_configuration_drifts_policy_id", "configuration_drifts", ["policy_id"])
        op.create_index("ix_configuration_drifts_check_id", "configuration_drifts", ["check_id"])

    if "sca_events" not in tables:
        op.create_table(
            "sca_events",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("event_type", sa.String(32), nullable=False),
            sa.Column("agent_id", sa.String(36), nullable=True),
            sa.Column("policy_id", sa.String(36), nullable=True),
            sa.Column("scan_id", sa.String(36), nullable=True),
            sa.Column("check_id", sa.String(36), nullable=True),
            sa.Column("severity", sa.String(16), nullable=False, server_default="info"),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("payload", sa.Text(), nullable=True),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_sca_events_event_type", "sca_events", ["event_type"])
        op.create_index("ix_sca_events_agent_id", "sca_events", ["agent_id"])
        op.create_index("ix_sca_events_policy_id", "sca_events", ["policy_id"])

    if "remediation_actions" not in tables:
        op.create_table(
            "remediation_actions",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("check_id", sa.String(36), nullable=False),
            sa.Column("agent_id", sa.String(36), nullable=False),
            sa.Column("action_type", sa.String(64), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("requested_by", sa.String(128), nullable=False),
            sa.Column("approved_by", sa.String(128), nullable=True),
            sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
            sa.Column("result", sa.Text(), nullable=True),
            sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_remediation_actions_check_id", "remediation_actions", ["check_id"])
        op.create_index("ix_remediation_actions_agent_id", "remediation_actions", ["agent_id"])

    # --------------------------------------------------- analyses.reference_id
    _add_column("analyses", sa.Column("reference_id", sa.String(36), nullable=True))

    # ------------------------------------------------ demo data backfill
    tables, _ = _tables()
    if "syscheck_agents" in tables and "sca_agents" in tables:
        has_syscheck = op.get_bind().scalar(sa.text("SELECT COUNT(*) FROM syscheck_agents"))
        has_sca = op.get_bind().scalar(sa.text("SELECT COUNT(*) FROM sca_agents"))
        if has_syscheck and not has_sca:
            op.execute(
                sa.text(
                    """
                    INSERT INTO sca_agents (id, agent_code, hostname, operating_system, platform,
                                             status, enabled, created_at, updated_at)
                    SELECT
                        lower(hex(randomblob(16))), code, name, os_name, platform,
                        CASE WHEN status = 'active' THEN 'online' ELSE 'offline' END,
                        1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                    FROM syscheck_agents
                    """
                )
            )
        # Repoint historical policy_scans at SCA agents where the FK still
        # targets a syscheck_agents row.
        try:
            sca_map = op.get_bind().execute(
                sa.text(
                    "SELECT sa.agent_code, sa.id AS sca_id FROM sca_agents sa "
                    "JOIN syscheck_agents sy ON sy.code = sa.agent_code"
                )
            ).all()
            for agent_code, sca_id in sca_map:
                op.execute(
                    sa.text(
                        "UPDATE policy_scans SET agent_id = :sca_id "
                        "WHERE agent_id IN (SELECT id FROM syscheck_agents WHERE code = :code)"
                    ).bindparams(code=agent_code, sca_id=sca_id)
                )
        except Exception:  # pragma: no cover - best-effort data fixup
            pass


def downgrade() -> None:
    for table in (
        "remediation_actions",
        "sca_events",
        "configuration_drifts",
        "check_results",
        "compliance_references",
        "check_rules",
        "sca_agents",
    ):
        op.drop_table(table)
    # Column removals are intentionally skipped (SQLite support is limited).
