"""Threat intelligence + vulnerability detection tables.

Adds the IOC (agents/indicators/observations/matches), vulnerability
(agents/inventory/scans/findings) and threat-hunting (queries/results) tables.

Revision ID: a1b2c3d4e5f6
Revises: f5d6c7a8b9e2
Create Date: 2026-08-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "f5d6c7a8b9e2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _pk_columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
    ]


def upgrade() -> None:
    # --------------------------------------------------------------- ioc_agents
    op.create_table(
        "ioc_agents",
        *_pk_columns(),
        sa.Column("agent_code", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("operating_system", sa.String(length=255), nullable=False),
        sa.Column("platform", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("api_key_hash", sa.String(length=128), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ioc_agents_agent_code"), "ioc_agents", ["agent_code"], unique=True)

    # ---------------------------------------------------------- ioc_indicators
    op.create_table(
        "ioc_indicators",
        *_pk_columns(),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("threat", sa.String(length=255), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("tags", sa.Text(), nullable=True),
        sa.Column("reference", sa.String(length=512), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ioc_indicators_indicator_type"), "ioc_indicators", ["indicator_type"], unique=False)
    op.create_index(op.f("ix_ioc_indicators_value"), "ioc_indicators", ["value"], unique=False)

    # --------------------------------------------------------- ioc_observations
    op.create_table(
        "ioc_observations",
        *_pk_columns(),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("context", sa.Text(), nullable=True),
        sa.Column("source_label", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ioc_observations_agent_id"), "ioc_observations", ["agent_id"], unique=False)
    op.create_index(op.f("ix_ioc_observations_observed_at"), "ioc_observations", ["observed_at"], unique=False)

    # ---------------------------------------------------------------- ioc_matches
    op.create_table(
        "ioc_matches",
        *_pk_columns(),
        sa.Column("observation_id", sa.String(length=36), nullable=False),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("indicator_id", sa.String(length=36), nullable=True),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("threat", sa.String(length=255), nullable=True),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_label", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ioc_matches_observation_id"), "ioc_matches", ["observation_id"], unique=False)
    op.create_index(op.f("ix_ioc_matches_agent_id"), "ioc_matches", ["agent_id"], unique=False)
    op.create_index(op.f("ix_ioc_matches_matched_at"), "ioc_matches", ["matched_at"], unique=False)

    # ---------------------------------------------------------------- vuln_agents
    op.create_table(
        "vuln_agents",
        *_pk_columns(),
        sa.Column("agent_code", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("operating_system", sa.String(length=255), nullable=False),
        sa.Column("platform", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("api_key_hash", sa.String(length=128), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_vuln_agents_agent_code"), "vuln_agents", ["agent_code"], unique=True)

    # -------------------------------------------------------- software_inventory
    op.create_table(
        "software_inventory",
        *_pk_columns(),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("product", sa.String(length=255), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("install_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_software_inventory_agent_id"), "software_inventory", ["agent_id"], unique=False)

    # ---------------------------------------------------------- vulnerability_scans
    op.create_table(
        "vulnerability_scans",
        *_pk_columns(),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("software_count", sa.Integer(), nullable=False),
        sa.Column("matched_count", sa.Integer(), nullable=False),
        sa.Column("unknown_count", sa.Integer(), nullable=False),
        sa.Column("not_vulnerable_count", sa.Integer(), nullable=False),
        sa.Column("database_missing", sa.Boolean(), nullable=False),
        sa.Column("duration", sa.Float(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("source_label", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_vulnerability_scans_agent_id"), "vulnerability_scans", ["agent_id"], unique=False)

    # ----------------------------------------------------- vulnerability_findings
    op.create_table(
        "vulnerability_findings",
        *_pk_columns(),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("software_id", sa.String(length=36), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("affected_version", sa.String(length=128), nullable=True),
        sa.Column("known", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_vulnerability_findings_scan_id"), "vulnerability_findings", ["scan_id"], unique=False)
    op.create_index(op.f("ix_vulnerability_findings_agent_id"), "vulnerability_findings", ["agent_id"], unique=False)
    op.create_index(op.f("ix_vulnerability_findings_software_id"), "vulnerability_findings", ["software_id"], unique=False)
    op.create_index(op.f("ix_vulnerability_findings_status"), "vulnerability_findings", ["status"], unique=False)

    # ---------------------------------------------------------------- hunt_queries
    op.create_table(
        "hunt_queries",
        *_pk_columns(),
        sa.Column("hunt_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("mitre_techniques", sa.Text(), nullable=True),
        sa.Column("time_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("time_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("filters", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("matched_events", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_hunt_queries_hunt_id"), "hunt_queries", ["hunt_id"], unique=False)

    # ---------------------------------------------------------------- hunt_results
    op.create_table(
        "hunt_results",
        *_pk_columns(),
        sa.Column("hunt_id", sa.String(length=36), nullable=False),
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("source_type", sa.String(length=64), nullable=True),
        sa.Column("source_name", sa.String(length=128), nullable=True),
        sa.Column("event_category", sa.String(length=64), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("event_fields", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_hunt_results_hunt_id"), "hunt_results", ["hunt_id"], unique=False)
    op.create_index(op.f("ix_hunt_results_event_id"), "hunt_results", ["event_id"], unique=False)
    op.create_index(op.f("ix_hunt_results_timestamp"), "hunt_results", ["timestamp"], unique=False)


def downgrade() -> None:
    op.drop_table("hunt_results")
    op.drop_table("hunt_queries")
    op.drop_table("vulnerability_findings")
    op.drop_table("vulnerability_scans")
    op.drop_table("software_inventory")
    op.drop_table("vuln_agents")
    op.drop_table("ioc_matches")
    op.drop_table("ioc_observations")
    op.drop_table("ioc_indicators")
    op.drop_table("ioc_agents")
