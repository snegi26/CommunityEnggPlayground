"""Weekly reports.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from passport.db.rls import org_isolation_policy

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "weekly_reports",
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
            unique=True,
        ),
        sa.Column("sent_at", TS),
        sa.Column("snapshot", JSONB, nullable=False, server_default="{}"),
        sa.Column("sections", JSONB, nullable=False, server_default="{}"),
        sa.Column("coverage", JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_index("ix_weekly_reports_org_sent", "weekly_reports", ["org_id", "sent_at"])
    for stmt in org_isolation_policy("weekly_reports"):
        op.execute(stmt)


def downgrade() -> None:
    op.drop_table("weekly_reports")
