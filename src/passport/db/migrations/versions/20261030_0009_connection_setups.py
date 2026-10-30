"""Pending connector setups, and one active org per GitHub App installation (U7).

``connection_setups`` holds the server-side state of a setup in progress: the
GitHub/Google OAuth ``state`` (hashed) bound to the browser session and org, and
the AWS external id we generated. It is org-scoped and RLS-isolated.

Every customer installs the same GitHub App, so an installation id must never be
bound to two orgs. Row-level security hides other orgs' connections, so the check
cannot be a SELECT. Instead a partial unique index on active GitHub connections'
``installation_id`` enforces it below the application: unique indexes apply across
all rows regardless of RLS, and the violation reveals one bit (bound elsewhere)
without exposing which org holds it. Disconnecting releases the binding.

Revision ID: 0009
Revises: 0007
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from passport.db.rls import org_isolation_policy

revision: str = "0009"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "connection_setups",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column(
            "org_id",
            sa.Uuid,
            sa.ForeignKey("orgs.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "user_id", sa.Uuid, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("session_key_hash", sa.String(64), nullable=False),
        sa.Column("payload", JSONB, nullable=False, server_default="{}"),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.CheckConstraint("kind IN ('aws', 'google_workspace', 'github')", name="kind"),
    )
    for stmt in org_isolation_policy("connection_setups"):
        op.execute(stmt)
    op.execute(
        "CREATE UNIQUE INDEX uq_connections_github_installation_active "
        "ON connections ((config->>'installation_id')) "
        "WHERE kind = 'github' AND status = 'active'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_connections_github_installation_active")
    op.execute("DROP TABLE connection_setups CASCADE")
