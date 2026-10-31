"""Connections and the envelope-encrypted credential vault.

Revision ID: 0006
Revises: 0003
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from passport.db.rls import org_isolation_policy

revision: str = "0006"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)
TABLES = ["connections", "vault_entries"]


def _org() -> sa.Column[object]:
    return sa.Column(
        "org_id", sa.Uuid, sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )


def upgrade() -> None:
    op.create_table(
        "connections",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("config", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("disconnected_at", TS),
        sa.Column("created_at", TS, nullable=False),
        sa.CheckConstraint("kind IN ('aws', 'google_workspace', 'github')", name="kind"),
        sa.CheckConstraint("status IN ('active', 'disconnected')", name="status"),
    )
    op.create_table(
        "vault_entries",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column(
            "connection_id",
            sa.Uuid,
            sa.ForeignKey("connections.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("key_id", sa.String(300), nullable=False),
        sa.Column("wrapped_key", sa.LargeBinary, nullable=False),
        sa.Column("nonce", sa.LargeBinary, nullable=False),
        sa.Column("ciphertext", sa.LargeBinary, nullable=False),
        sa.Column("created_at", TS, nullable=False),
    )
    for table in TABLES:
        for stmt in org_isolation_policy(table):
            op.execute(stmt)


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE {table} CASCADE")
