"""Add CheckRule.pattern for regex-extract-then-compare evaluation.

The pattern column lets a rule extract a value from collected evidence (e.g.
"Length of password history maintained: <n>" from ``net accounts`` output)
and compare it against ``expected_value`` using ``operator``. No rows are
changed; the column is nullable.

Revision ID: e9c4b3d2a1f0
Revises: d4f5a6b7c8e1
Create Date: 2026-08-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e9c4b3d2a1f0"
down_revision: str | None = "d4f5a6b7c8e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    tables = set(insp.get_table_names())
    cols = {
        name: {c["name"] for c in insp.get_columns(name)}
        for name in tables
    }
    if "check_rules" in tables and "pattern" not in cols["check_rules"]:
        op.add_column(
            "check_rules",
            sa.Column("pattern", sa.String(512), nullable=True),
        )


def downgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "check_rules" in set(insp.get_table_names()):
        op.drop_column("check_rules", "pattern")
