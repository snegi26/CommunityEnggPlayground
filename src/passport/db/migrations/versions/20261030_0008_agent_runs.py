"""Agent run records for claim drafting (U9).

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from passport.db.rls import org_isolation_policy

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid,
            sa.ForeignKey("orgs.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "document_version_id",
            sa.Uuid,
            sa.ForeignKey("document_versions.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("model_id", sa.String(100), nullable=False),
        sa.Column("prompt_version", sa.String(100), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("counts", JSONB, nullable=False, server_default="{}"),
        sa.Column("suggested_review_on", sa.Date),
        sa.Column("suggested_review_source", sa.Text),
        sa.Column("failure_reason", sa.Text),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("finished_at", TS),
        sa.CheckConstraint("status IN ('running', 'succeeded', 'failed')", name="status"),
    )
    for stmt in org_isolation_policy("agent_runs"):
        op.execute(stmt)


def downgrade() -> None:
    op.drop_table("agent_runs")
