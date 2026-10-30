"""Tenancy and auth tables, row-level security, and the narrow pre-org paths (KTD5).

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from passport.db.rls import current_org_sql, current_user_sql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ROLE = sa.Enum("owner", "approver", "viewer", name="membership_role")
TS = sa.DateTime(timezone=True)


def _id() -> sa.Column[object]:
    return sa.Column("id", sa.Uuid, primary_key=True)


def upgrade() -> None:
    op.create_table(
        "users",
        _id(),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("password_hash", sa.String(200), nullable=False),
        sa.Column("totp_secret", sa.String(64)),
        sa.Column("totp_enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "orgs",
        _id(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "memberships",
        _id(),
        sa.Column("org_id", sa.Uuid, sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "user_id", sa.Uuid, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("role", ROLE, nullable=False),
        sa.Column("external", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", TS, nullable=False),
        sa.UniqueConstraint("org_id", "user_id"),
    )
    op.create_table(
        "invitations",
        _id(),
        sa.Column("org_id", sa.Uuid, sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("role", ROLE, nullable=False),
        sa.Column("external", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("accepted_at", TS),
        sa.Column("invited_by", sa.Uuid, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "auth_sessions",
        _id(),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "user_id", sa.Uuid, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("mfa_verified", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "recovery_codes",
        _id(),
        sa.Column(
            "user_id", sa.Uuid, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("used_at", TS),
    )
    op.create_table(
        "password_reset_tokens",
        _id(),
        sa.Column(
            "user_id", sa.Uuid, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "login_attempts",
        _id(),
        sa.Column("key", sa.String(400), nullable=False, index=True),
        sa.Column("created_at", TS, nullable=False),
    )

    org = current_org_sql()
    user = current_user_sql()
    # Identity tables use ENABLE (not FORCE) so the owner-defined functions below can
    # serve login and scheduling; the app role is never the owner, so policies always
    # apply to it.
    for stmt in [
        "ALTER TABLE orgs ENABLE ROW LEVEL SECURITY",
        f"CREATE POLICY orgs_visible ON orgs FOR SELECT USING (id = {org} OR id IN "
        f"(SELECT org_id FROM memberships WHERE user_id = {user}))",
        "CREATE POLICY orgs_insert ON orgs FOR INSERT WITH CHECK (true)",
        f"CREATE POLICY orgs_update ON orgs FOR UPDATE USING (id = {org})",
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY",
        f"CREATE POLICY users_visible ON users FOR SELECT USING (id = {user} OR id IN "
        f"(SELECT user_id FROM memberships WHERE org_id = {org}))",
        "CREATE POLICY users_insert ON users FOR INSERT WITH CHECK (true)",
        f"CREATE POLICY users_update ON users FOR UPDATE USING (id = {user} OR id IN "
        f"(SELECT user_id FROM memberships WHERE org_id = {org}))",
        "ALTER TABLE memberships ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE memberships FORCE ROW LEVEL SECURITY",
        f"CREATE POLICY memberships_visible ON memberships "
        f"USING (user_id = {user} OR org_id = {org}) WITH CHECK (org_id = {org})",
        "ALTER TABLE invitations ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE invitations FORCE ROW LEVEL SECURITY",
        f"CREATE POLICY invitations_visible ON invitations USING (org_id = {org} OR "
        "token_hash = current_setting('app.invite_token_hash', true)) "
        f"WITH CHECK (org_id = {org})",
        # Login: look a user up by email before any user or org context exists.
        """
        CREATE FUNCTION passport_login_lookup(p_email text)
        RETURNS TABLE (id uuid, password_hash text, totp_enabled boolean)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
          SELECT id, password_hash, totp_enabled FROM users WHERE email = lower(p_email)
        $$
        """,
        # Scheduler: org ids and nothing else.
        """
        CREATE FUNCTION passport_all_org_ids()
        RETURNS SETOF uuid
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
          SELECT id FROM orgs ORDER BY id
        $$
        """,
        "REVOKE ALL ON FUNCTION passport_login_lookup(text) FROM PUBLIC",
        "REVOKE ALL ON FUNCTION passport_all_org_ids() FROM PUBLIC",
    ]:
        op.execute(stmt)
    from passport.settings import get_settings

    app_role = get_settings().app_db_role
    op.execute(f"GRANT EXECUTE ON FUNCTION passport_login_lookup(text) TO {app_role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION passport_all_org_ids() TO {app_role}")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS passport_all_org_ids()")
    op.execute("DROP FUNCTION IF EXISTS passport_login_lookup(text)")
    for table in [
        "login_attempts",
        "password_reset_tokens",
        "recovery_codes",
        "auth_sessions",
        "invitations",
        "memberships",
        "orgs",
        "users",
    ]:
        op.execute(f"DROP TABLE {table} CASCADE")
    ROLE.drop(op.get_bind(), checkfirst=True)
