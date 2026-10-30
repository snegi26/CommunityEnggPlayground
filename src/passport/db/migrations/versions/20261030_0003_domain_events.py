"""Core domain tables and the append-only event log (U3).

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from passport.db.rls import org_isolation_policy
from passport.settings import get_settings

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)
CLAIM_STATE = sa.Enum(
    "unconfirmed", "needs_review", "confirmed", "rejected", "dismissed", name="claim_state"
)
RUN_STATUS = sa.Enum("queued", "running", "succeeded", "failed", name="run_status")

DOMAIN_TABLES = [
    "documents",
    "document_versions",
    "evidence_items",
    "claims",
    "check_bindings",
    "check_runs",
    "observations",
    "item_statuses",
    "events",
    "event_chain_heads",
]


def _org() -> sa.Column[object]:
    return sa.Column(
        "org_id", sa.Uuid, sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )


def _approval() -> list[sa.Column[object]]:
    return [
        sa.Column("last_approved_by", sa.Uuid, sa.ForeignKey("users.id")),
        sa.Column("approved_at", TS),
        sa.Column("approved_on_behalf", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("review_due_on", sa.Date),
    ]


def upgrade() -> None:
    op.create_table(
        "documents",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "document_versions",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column(
            "document_id",
            sa.Uuid,
            sa.ForeignKey("documents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer, nullable=False),
        sa.Column("filename", sa.String(300), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("storage_key", sa.String(500), nullable=False),
        *_approval(),
        sa.Column("created_at", TS, nullable=False),
        sa.UniqueConstraint("document_id", "version_number"),
    )
    op.create_table(
        "evidence_items",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("filename", sa.String(300), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("storage_key", sa.String(500), nullable=False),
        sa.Column("source", sa.String(300), nullable=False),
        sa.Column("collected_at", TS, nullable=False),
        sa.Column("user_asserted", sa.Boolean, nullable=False, server_default=sa.true()),
        *_approval(),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "claims",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column(
            "document_version_id",
            sa.Uuid,
            sa.ForeignKey("document_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("span_id", sa.String(200), nullable=False),
        sa.Column("quote", sa.Text, nullable=False),
        sa.Column("predicate_id", sa.String(100)),
        sa.Column("predicate_version", sa.Integer),
        sa.Column("parameters", JSONB, nullable=False, server_default="{}"),
        sa.Column("check_description", sa.Text),
        sa.Column("state", CLAIM_STATE, nullable=False),
        sa.Column("needs_review_reason", sa.Text),
        sa.Column("revision_of", sa.Uuid, sa.ForeignKey("claims.id")),
        sa.Column("confirmed_by", sa.Uuid, sa.ForeignKey("users.id")),
        sa.Column("confirmed_on_behalf", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("confirmed_at", TS),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "check_bindings",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column(
            "claim_id", sa.Uuid, sa.ForeignKey("claims.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("connection_id", sa.Uuid, nullable=False),
        sa.Column("capability", sa.String(100), nullable=False),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "check_runs",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column("trigger", sa.String(20), nullable=False),
        sa.Column("status", RUN_STATUS, nullable=False),
        sa.Column("started_at", TS),
        sa.Column("finished_at", TS),
        sa.Column("failure_reason", sa.Text),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "observations",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column("check_run_id", sa.Uuid, sa.ForeignKey("check_runs.id", ondelete="SET NULL")),
        sa.Column("connection_id", sa.Uuid),
        sa.Column("capability", sa.String(100), nullable=False),
        sa.Column("outcome", sa.String(30), nullable=False),
        sa.Column("endpoint", sa.String(500), nullable=False),
        sa.Column("parameters", JSONB, nullable=False, server_default="{}"),
        sa.Column("row_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_count", sa.Integer),
        sa.Column("complete", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("response_sha256", sa.String(64), nullable=False),
        sa.Column("raw_response", JSONB),
        sa.Column("scope", JSONB, nullable=False, server_default="[]"),
        sa.Column("collector_version", sa.String(50), nullable=False),
        sa.Column("collected_at", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False),
    )
    op.create_table(
        "item_statuses",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column("item_kind", sa.String(20), nullable=False),
        sa.Column("item_id", sa.Uuid, nullable=False),
        sa.Column("framework", sa.String(30), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("trusted", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("causes", JSONB, nullable=False, server_default="[]"),
        sa.Column("computed_at", TS, nullable=False),
        sa.UniqueConstraint("item_kind", "item_id", "framework"),
    )
    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        _org(),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("subject_kind", sa.String(50), nullable=False),
        sa.Column("subject_id", sa.String(100), nullable=False),
        sa.Column("actor_kind", sa.String(10), nullable=False),
        sa.Column("actor_user_id", sa.Uuid),
        sa.Column("on_behalf_of_org", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("agent_run_id", sa.Uuid),
        sa.Column("model_id", sa.String(100)),
        sa.Column("prompt_version", sa.String(100)),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.UniqueConstraint("org_id", "seq"),
    )
    op.create_table(
        "event_chain_heads",
        sa.Column(
            "org_id", sa.Uuid, sa.ForeignKey("orgs.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("hash", sa.String(64), nullable=False),
    )

    for table in DOMAIN_TABLES:
        for stmt in org_isolation_policy(table):
            op.execute(stmt)
    # The event log is append-only for the application role (KTD8).
    app_role = get_settings().app_db_role
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON events FROM {app_role}")


def downgrade() -> None:
    for table in reversed(DOMAIN_TABLES):
        op.execute(f"DROP TABLE {table} CASCADE")
    RUN_STATUS.drop(op.get_bind(), checkfirst=True)
    CLAIM_STATE.drop(op.get_bind(), checkfirst=True)
