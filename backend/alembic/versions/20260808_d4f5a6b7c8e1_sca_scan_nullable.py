"""Relax policy_scans started_at/end_scan nullability for queued scans.

The pre-SCA table was created with ``end_scan`` NOT NULL; queued scans have no
completion time. Batch-recreates the table with nullable timestamps, preserving
all rows.

Revision ID: d4f5a6b7c8e1
Revises: b7c3e1a2f9d0
Create Date: 2026-08-08
"""

import sqlalchemy as sa
from alembic import op

revision = "d4f5a6b7c8e1"
down_revision = "b7c3e1a2f9d0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("policy_scans", schema=None) as batch_op:
        batch_op.alter_column(
            "end_scan", existing_type=sa.DateTime(timezone=True), nullable=True
        )
        batch_op.alter_column(
            "started_at", existing_type=sa.DateTime(timezone=True), nullable=True
        )


def downgrade() -> None:
    with op.batch_alter_table("policy_scans", schema=None) as batch_op:
        batch_op.alter_column(
            "end_scan", existing_type=sa.DateTime(timezone=True), nullable=False
        )
        batch_op.alter_column(
            "started_at", existing_type=sa.DateTime(timezone=True), nullable=False
        )
