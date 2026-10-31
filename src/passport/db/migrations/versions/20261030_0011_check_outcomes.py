"""Per-claim check outcomes for check runs (U11).

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from passport.db.rls import org_isolation_policy

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "check_outcomes",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid,
            sa.ForeignKey("orgs.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "check_run_id",
            sa.Uuid,
            sa.ForeignKey("check_runs.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "claim_id",
            sa.Uuid,
            sa.ForeignKey("claims.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("outcome", sa.String(30), nullable=False),
        sa.Column("observation_ids", JSONB, nullable=False, server_default="[]"),
        sa.Column("detail", JSONB, nullable=False, server_default="{}"),
        sa.Column("checked_at", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.UniqueConstraint("check_run_id", "claim_id"),
        sa.CheckConstraint(
            "outcome IN ('current', 'contradicted', 'check_failed', 'not_checkable')",
            name="outcome",
        ),
    )
    for stmt in org_isolation_policy("check_outcomes"):
        op.execute(stmt)


def downgrade() -> None:
    op.drop_table("check_outcomes")
