"""Parsed document spans with their version diff marks.

Revision ID: 0005
Revises: 0003
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from passport.db.rls import org_isolation_policy

revision: str = "0005"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "document_spans",
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
        sa.Column("span_id", sa.String(200), nullable=False),
        sa.Column("section_path", JSONB, nullable=False),
        sa.Column("paragraph_index", sa.Integer, nullable=False),
        sa.Column("char_start", sa.Integer, nullable=False),
        sa.Column("char_end", sa.Integer, nullable=False),
        sa.Column("text", sa.Text, nullable=False),
        sa.Column("text_key", sa.String(64), nullable=False),
        sa.Column("change_kind", sa.String(10), nullable=False),
        sa.Column("previous_id", sa.Uuid, sa.ForeignKey("document_spans.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("document_version_id", "span_id"),
        sa.CheckConstraint("change_kind IN ('unchanged', 'changed', 'new')", name="change_kind"),
    )
    for stmt in org_isolation_policy("document_spans"):
        op.execute(stmt)


def downgrade() -> None:
    op.drop_table("document_spans")
