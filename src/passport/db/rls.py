"""Per-transaction tenant context for row-level security (KTD5).

Every domain table's policy compares its ``org_id`` with ``app.org_id``. The three
narrow pre-org paths use ``app.user_id`` (users, memberships) and
``app.invite_token_hash`` (invitations). Settings are transaction-local, so a
pooled connection never carries one request's tenant into the next.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session


def set_org_context(session: Session, org_id: uuid.UUID) -> None:
    session.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org_id)})


def set_user_context(session: Session, user_id: uuid.UUID) -> None:
    session.execute(text("SELECT set_config('app.user_id', :v, true)"), {"v": str(user_id)})


def set_invite_context(session: Session, token_hash: str) -> None:
    session.execute(text("SELECT set_config('app.invite_token_hash', :v, true)"), {"v": token_hash})


def current_org_sql() -> str:
    """SQL expression for the active org id, NULL when unset."""
    return "NULLIF(current_setting('app.org_id', true), '')::uuid"


def current_user_sql() -> str:
    return "NULLIF(current_setting('app.user_id', true), '')::uuid"


def org_isolation_policy(table: str) -> list[str]:
    """DDL enabling the standard org-keyed policy on a domain table."""
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"CREATE POLICY {table}_org_isolation ON {table} "
        f"USING (org_id = {current_org_sql()}) WITH CHECK (org_id = {current_org_sql()})",
    ]
