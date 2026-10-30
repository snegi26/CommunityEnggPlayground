"""Control catalogs, item mappings, framework settings, and scope inventory (U4).

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from passport.controls.service import catalog_rows
from passport.db.rls import org_isolation_policy
from passport.settings import get_settings

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)
ORG_TABLES = ["control_mappings", "org_framework_settings", "scope_entries"]


def _org() -> sa.Column[object]:
    return sa.Column(
        "org_id", sa.Uuid, sa.ForeignKey("orgs.id", ondelete="CASCADE"), nullable=False, index=True
    )


def upgrade() -> None:
    controls = op.create_table(
        "controls",
        sa.Column("framework", sa.String(30), primary_key=True),
        sa.Column("control_id", sa.String(20), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("position", sa.Integer, nullable=False),
        sa.CheckConstraint("framework IN ('soc2', 'iso27001')", name="framework"),
    )
    op.bulk_insert(controls, catalog_rows())

    op.create_table(
        "control_mappings",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column("item_kind", sa.String(20), nullable=False),
        sa.Column("item_id", sa.Uuid, nullable=False),
        sa.Column("framework", sa.String(30), nullable=False),
        sa.Column("control_id", sa.String(20), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.UniqueConstraint("org_id", "item_kind", "item_id", "framework", "control_id"),
        sa.ForeignKeyConstraint(
            ["framework", "control_id"], ["controls.framework", "controls.control_id"]
        ),
        sa.CheckConstraint("item_kind IN ('document', 'evidence')", name="item_kind"),
    )
    op.create_index("ix_control_mappings_item", "control_mappings", ["item_kind", "item_id"])
    op.create_table(
        "org_framework_settings",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column("framework", sa.String(30), nullable=False),
        sa.Column("audit_type", sa.String(30), nullable=False),
        sa.Column("as_of_date", sa.Date),
        sa.Column("window_start", sa.Date),
        sa.Column("window_end", sa.Date),
        sa.Column("policy_review_days", sa.Integer, nullable=False),
        sa.Column("access_review_days", sa.Integer, nullable=False),
        sa.Column("expiring_soon_days", sa.Integer, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.UniqueConstraint("org_id", "framework"),
        sa.CheckConstraint(
            "(framework = 'soc2' AND audit_type IN ('soc2_type1', 'soc2_type2')) OR "
            "(framework = 'iso27001' AND audit_type = 'iso27001_certification')",
            name="audit_type",
        ),
        sa.CheckConstraint(
            "window_start IS NULL OR window_end IS NULL OR window_end > window_start",
            name="window_order",
        ),
        sa.CheckConstraint(
            "audit_type <> 'soc2_type1' OR (window_start IS NULL AND window_end IS NULL)",
            name="type1_single_date",
        ),
        sa.CheckConstraint(
            "policy_review_days > 0 AND access_review_days > 0 AND expiring_soon_days >= 0",
            name="positive_cadences",
        ),
    )
    op.create_table(
        "scope_entries",
        sa.Column("id", sa.Uuid, primary_key=True),
        _org(),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("identifier", sa.String(200), nullable=False),
        sa.Column("label", sa.String(200), nullable=False, server_default=""),
        sa.Column("production", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", TS, nullable=False),
        sa.UniqueConstraint("org_id", "kind", "identifier"),
        sa.CheckConstraint(
            "kind IN ('aws_account', 'github_org', 'workspace_domain')", name="kind"
        ),
    )

    for table in ORG_TABLES:
        for stmt in org_isolation_policy(table):
            op.execute(stmt)
    # The catalog is global reference data: readable by every org, changed only by migrations.
    app_role = get_settings().app_db_role
    op.execute(f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON controls FROM {app_role}")


def downgrade() -> None:
    for table in reversed(ORG_TABLES):
        op.execute(f"DROP TABLE {table} CASCADE")
    op.drop_table("controls")
