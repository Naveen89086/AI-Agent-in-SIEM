"""Real FIM: syscheck agent enrollment + baseline + real event fields.

Extends the existing FIM tables so a real Windows collector agent can enroll
with a per-agent API key, persist an authoritative file baseline and submit
deterministic SHA-256 events that the server verifies and classifies.

All additions are nullable / backward compatible - the demo seeded rows and the
existing FIM GET APIs keep working unchanged.

Revision ID: f5d6c7a8b9e2
Revises: e9c4b3d2a1f0
Create Date: 2026-08-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f5d6c7a8b9e2"
down_revision: str | None = "e9c4b3d2a1f0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _tables() -> tuple[set[str], dict[str, set[str]]]:
    insp = sa.inspect(op.get_bind())
    names = set(insp.get_table_names())
    cols = {name: {c["name"] for c in insp.get_columns(name)} for name in names}
    return names, cols


def _add_column(table: str, column: sa.Column) -> None:
    names, cols = _tables()
    if table in names and column.name not in cols[table]:
        op.add_column(table, column)


def _pk_columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
    ]


def _ensure_syscheck_tables() -> None:
    """Create the syscheck tables when missing (fresh databases).

    Migrations are the schema source of truth; the runtime ``create_all`` only
    runs in dev/test, so a fresh production database would otherwise never get
    these tables and the protected-endpoint migration (machine_guid ALTERs)
    would fail.
    """
    names, _ = _tables()
    if "syscheck_agents" not in names:
        op.create_table(
            "syscheck_agents",
            *_pk_columns(),
            sa.Column("code", sa.String(length=16), nullable=False),
            sa.Column("name", sa.String(length=64), nullable=False),
            sa.Column("platform", sa.String(length=32), nullable=False),
            sa.Column("os_name", sa.String(length=128), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("registry_entries", sa.Integer(), nullable=False),
            sa.Column("hostname", sa.String(length=255), nullable=True),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("version", sa.String(length=32), nullable=True),
            sa.Column("api_key_hash", sa.String(length=128), nullable=True),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_syscheck_agents_code"), "syscheck_agents", ["code"], unique=True)
    if "syscheck_files" not in names:
        op.create_table(
            "syscheck_files",
            *_pk_columns(),
            sa.Column("agent_id", sa.String(length=36), nullable=False),
            sa.Column("file_path", sa.String(length=512), nullable=False),
            sa.Column("last_modified", sa.DateTime(timezone=True), nullable=False),
            sa.Column("user", sa.String(length=64), nullable=False),
            sa.Column("user_id", sa.String(length=128), nullable=False),
            sa.Column("size", sa.Integer(), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=True),
            sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
            sa.Column("owner", sa.String(length=128), nullable=True),
            sa.Column("permissions", sa.String(length=32), nullable=True),
            sa.Column("file_type", sa.String(length=32), nullable=True),
            sa.Column("status", sa.String(length=16), nullable=True),
            sa.ForeignKeyConstraint(["agent_id"], ["syscheck_agents.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_syscheck_files_agent_id"), "syscheck_files", ["agent_id"], unique=False)
    if "syscheck_events" not in names:
        op.create_table(
            "syscheck_events",
            *_pk_columns(),
            sa.Column("agent_id", sa.String(length=36), nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
            sa.Column("path", sa.String(length=512), nullable=False),
            sa.Column("event", sa.String(length=16), nullable=False),
            sa.Column("user", sa.String(length=64), nullable=False),
            sa.Column("rule", sa.String(length=128), nullable=False),
            sa.Column("level", sa.Integer(), nullable=False),
            sa.Column("rule_id", sa.Integer(), nullable=False),
            sa.Column("manager_name", sa.String(length=64), nullable=False),
            sa.Column("event_id", sa.String(length=64), nullable=True),
            sa.Column("event_type", sa.String(length=16), nullable=True),
            sa.Column("old_path", sa.String(length=512), nullable=True),
            sa.Column("old_sha256", sa.String(length=64), nullable=True),
            sa.Column("new_sha256", sa.String(length=64), nullable=True),
            sa.Column("sha256", sa.String(length=64), nullable=True),
            sa.Column("owner", sa.String(length=128), nullable=True),
            sa.Column("size", sa.Integer(), nullable=True),
            sa.Column("source", sa.String(length=32), nullable=True),
            sa.Column("evidence", sa.Text(), nullable=True),
            sa.Column("severity", sa.String(length=16), nullable=True),
            sa.ForeignKeyConstraint(["agent_id"], ["syscheck_agents.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_syscheck_events_agent_id"), "syscheck_events", ["agent_id"], unique=False)
        op.create_index(op.f("ix_syscheck_events_timestamp"), "syscheck_events", ["timestamp"], unique=False)
        op.create_index(op.f("ix_syscheck_events_event"), "syscheck_events", ["event"], unique=False)
        op.create_index(op.f("ix_syscheck_events_event_id"), "syscheck_events", ["event_id"], unique=False)


def upgrade() -> None:
    _ensure_syscheck_tables()
    tables, cols = _tables()

    # ------------------------------------------------------- syscheck_agents
    if "syscheck_agents" in tables:
        _add_column("syscheck_agents", sa.Column("hostname", sa.String(255), nullable=True))
        _add_column("syscheck_agents", sa.Column("ip_address", sa.String(64), nullable=True))
        _add_column("syscheck_agents", sa.Column("version", sa.String(32), nullable=True))
        _add_column("syscheck_agents", sa.Column("api_key_hash", sa.String(128), nullable=True))
        _add_column("syscheck_agents", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
        _add_column("syscheck_agents", sa.Column("enabled", sa.Boolean(), nullable=True))

    # ---------------------------------------------------------- syscheck_files
    if "syscheck_files" in tables:
        _add_column("syscheck_files", sa.Column("sha256", sa.String(64), nullable=True))
        _add_column("syscheck_files", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
        _add_column("syscheck_files", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
        _add_column("syscheck_files", sa.Column("owner", sa.String(128), nullable=True))
        _add_column("syscheck_files", sa.Column("permissions", sa.String(32), nullable=True))
        _add_column("syscheck_files", sa.Column("file_type", sa.String(32), nullable=True))
        _add_column("syscheck_files", sa.Column("status", sa.String(16), nullable=True))

    # --------------------------------------------------------- syscheck_events
    if "syscheck_events" in tables:
        _add_column("syscheck_events", sa.Column("event_id", sa.String(64), nullable=True))
        _add_column("syscheck_events", sa.Column("event_type", sa.String(16), nullable=True))
        _add_column("syscheck_events", sa.Column("old_path", sa.String(512), nullable=True))
        _add_column("syscheck_events", sa.Column("old_sha256", sa.String(64), nullable=True))
        _add_column("syscheck_events", sa.Column("new_sha256", sa.String(64), nullable=True))
        _add_column("syscheck_events", sa.Column("sha256", sa.String(64), nullable=True))
        _add_column("syscheck_events", sa.Column("owner", sa.String(128), nullable=True))
        _add_column("syscheck_events", sa.Column("size", sa.Integer(), nullable=True))
        _add_column("syscheck_events", sa.Column("source", sa.String(32), nullable=True))
        _add_column("syscheck_events", sa.Column("evidence", sa.Text(), nullable=True))
        _add_column("syscheck_events", sa.Column("severity", sa.String(16), nullable=True))
        index_names = {i["name"] for i in sa.inspect(op.get_bind()).get_indexes("syscheck_events")}
        if "ix_syscheck_events_event_id" not in index_names:
            op.create_index("ix_syscheck_events_event_id", "syscheck_events", ["event_id"])

    # Existing demo rows: normalize status to 'active' so the inventory filter
    # keeps showing them.
    if "syscheck_files" in tables and "status" in cols.get("syscheck_files", set()):
        op.execute(
            "UPDATE syscheck_files SET status = 'active' WHERE status IS NULL"
        )


def downgrade() -> None:
    # Column removals are intentionally skipped (SQLite support is limited).
    pass
