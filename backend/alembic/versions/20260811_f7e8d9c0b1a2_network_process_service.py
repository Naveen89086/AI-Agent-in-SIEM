"""Network + Process/Service monitoring tables.

Adds the shared telemetry agent registry plus the live-state tables for the
network (connections/listeners/interfaces/statistics), process and service
monitoring dashboards. Lifecycle transitions are emitted as structured events
through the existing ingest pipeline (no event tables here).

Revision ID: f7e8d9c0b1a2
Revises: a1b2c3d4e5f6
Create Date: 2026-08-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f7e8d9c0b1a2"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _pk_columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
    ]


def upgrade() -> None:
    # ---------------------------------------------------------- telemetry_agents
    op.create_table(
        "telemetry_agents",
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
        sa.Column("demo", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_telemetry_agents_agent_code"), "telemetry_agents", ["agent_code"], unique=True)

    # -------------------------------------------------------- network_connections
    op.create_table(
        "network_connections",
        *_pk_columns(),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("conn_key", sa.String(length=255), nullable=False),
        sa.Column("proto", sa.String(length=8), nullable=False),
        sa.Column("local_ip", sa.String(length=64), nullable=False),
        sa.Column("local_port", sa.Integer(), nullable=False),
        sa.Column("foreign_ip", sa.String(length=64), nullable=False),
        sa.Column("foreign_port", sa.Integer(), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("user", sa.String(length=128), nullable=True),
        sa.Column("executable", sa.String(length=512), nullable=True),
        sa.Column("is_private", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_label", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_network_connections_agent_id"), "network_connections", ["agent_id"], unique=False)
    op.create_index(op.f("ix_network_connections_conn_key"), "network_connections", ["conn_key"], unique=False)
    op.create_index(op.f("ix_network_connections_status"), "network_connections", ["status"], unique=False)

    # --------------------------------------------------------- network_listeners
    op.create_table(
        "network_listeners",
        *_pk_columns(),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("listen_key", sa.String(length=255), nullable=False),
        sa.Column("proto", sa.String(length=8), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("user", sa.String(length=128), nullable=True),
        sa.Column("executable", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_label", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_network_listeners_agent_id"), "network_listeners", ["agent_id"], unique=False)
    op.create_index(op.f("ix_network_listeners_listen_key"), "network_listeners", ["listen_key"], unique=False)
    op.create_index(op.f("ix_network_listeners_status"), "network_listeners", ["status"], unique=False)

    # --------------------------------------------------------- network_interfaces
    op.create_table(
        "network_interfaces",
        *_pk_columns(),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("mac", sa.String(length=32), nullable=True),
        sa.Column("addresses", sa.Text(), nullable=True),
        sa.Column("mtu", sa.Integer(), nullable=True),
        sa.Column("speed_mbps", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_label", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_network_interfaces_agent_id"), "network_interfaces", ["agent_id"], unique=False)

    # -------------------------------------------------------- network_statistics
    op.create_table(
        "network_statistics",
        *_pk_columns(),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("bytes_sent", sa.BigInteger(), nullable=False),
        sa.Column("bytes_recv", sa.BigInteger(), nullable=False),
        sa.Column("packets_sent", sa.BigInteger(), nullable=False),
        sa.Column("packets_recv", sa.BigInteger(), nullable=False),
        sa.Column("tx_kbps", sa.Float(), nullable=False),
        sa.Column("rx_kbps", sa.Float(), nullable=False),
        sa.Column("connections_total", sa.Integer(), nullable=False),
        sa.Column("listeners_total", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_label", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_network_statistics_agent_id"), "network_statistics", ["agent_id"], unique=True)

    # ------------------------------------------------------------- process_records
    op.create_table(
        "process_records",
        *_pk_columns(),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("executable", sa.String(length=512), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column("parent_pid", sa.Integer(), nullable=True),
        sa.Column("parent_name", sa.String(length=255), nullable=True),
        sa.Column("user", sa.String(length=128), nullable=True),
        sa.Column("cpu_percent", sa.Float(), nullable=False),
        sa.Column("memory_rss_mb", sa.Float(), nullable=False),
        sa.Column("threads", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("terminated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_label", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_process_records_agent_id"), "process_records", ["agent_id"], unique=False)
    op.create_index(op.f("ix_process_records_pid"), "process_records", ["pid"], unique=False)
    op.create_index(op.f("ix_process_records_status"), "process_records", ["status"], unique=False)

    # -------------------------------------------------------------- service_records
    op.create_table(
        "service_records",
        *_pk_columns(),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("start_type", sa.String(length=32), nullable=True),
        sa.Column("account", sa.String(length=255), nullable=True),
        sa.Column("binary_path", sa.Text(), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("last_event", sa.String(length=32), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_label", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_service_records_agent_id"), "service_records", ["agent_id"], unique=False)
    op.create_index(op.f("ix_service_records_name"), "service_records", ["name"], unique=False)


def downgrade() -> None:
    op.drop_table("service_records")
    op.drop_table("process_records")
    op.drop_table("network_statistics")
    op.drop_table("network_interfaces")
    op.drop_table("network_listeners")
    op.drop_table("network_connections")
    op.drop_table("telemetry_agents")
