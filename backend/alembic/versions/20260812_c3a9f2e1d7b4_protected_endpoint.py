"""Single protected endpoint.

Adds the canonical ``protected_endpoints`` table (the one PC this product
protects) and the stable machine fingerprint (``machine_guid``) on every
subsystem agent registry so the backend can reject a second, different device
with error code ``single_endpoint_limit``.

Revision ID: c3a9f2e1d7b4
Revises: f7e8d9c0b1a2
Create Date: 2026-08-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c3a9f2e1d7b4"
down_revision: str | None = "f7e8d9c0b1a2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _pk_columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "protected_endpoints",
        *_pk_columns(),
        sa.Column("machine_guid", sa.String(length=128), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("operating_system", sa.String(length=255), nullable=False),
        sa.Column("os_version", sa.String(length=128), nullable=True),
        sa.Column("architecture", sa.String(length=32), nullable=True),
        sa.Column("agent_version", sa.String(length=32), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("ip_addresses", sa.Text(), nullable=True),
        sa.Column("mac_addresses", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("demo", sa.Boolean(), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_protected_endpoints_machine_guid"),
        "protected_endpoints",
        ["machine_guid"],
        unique=True,
    )

    # --- stable machine fingerprint on every subsystem agent registry ---
    op.add_column("telemetry_agents", sa.Column("machine_guid", sa.String(length=128), nullable=True))
    op.create_index(op.f("ix_telemetry_agents_machine_guid"), "telemetry_agents", ["machine_guid"], unique=False)

    op.add_column("ioc_agents", sa.Column("machine_guid", sa.String(length=128), nullable=True))
    op.create_index(op.f("ix_ioc_agents_machine_guid"), "ioc_agents", ["machine_guid"], unique=False)

    op.add_column("vuln_agents", sa.Column("machine_guid", sa.String(length=128), nullable=True))
    op.create_index(op.f("ix_vuln_agents_machine_guid"), "vuln_agents", ["machine_guid"], unique=False)

    op.add_column("sca_agents", sa.Column("machine_guid", sa.String(length=128), nullable=True))
    op.create_index(op.f("ix_sca_agents_machine_guid"), "sca_agents", ["machine_guid"], unique=False)

    op.add_column("syscheck_agents", sa.Column("machine_guid", sa.String(length=128), nullable=True))
    op.create_index(op.f("ix_syscheck_agents_machine_guid"), "syscheck_agents", ["machine_guid"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_syscheck_agents_machine_guid"), table_name="syscheck_agents")
    op.drop_column("syscheck_agents", "machine_guid")

    op.drop_index(op.f("ix_sca_agents_machine_guid"), table_name="sca_agents")
    op.drop_column("sca_agents", "machine_guid")

    op.drop_index(op.f("ix_vuln_agents_machine_guid"), table_name="vuln_agents")
    op.drop_column("vuln_agents", "machine_guid")

    op.drop_index(op.f("ix_ioc_agents_machine_guid"), table_name="ioc_agents")
    op.drop_column("ioc_agents", "machine_guid")

    op.drop_index(op.f("ix_telemetry_agents_machine_guid"), table_name="telemetry_agents")
    op.drop_column("telemetry_agents", "machine_guid")

    op.drop_index(op.f("ix_protected_endpoints_machine_guid"), table_name="protected_endpoints")
    op.drop_table("protected_endpoints")
