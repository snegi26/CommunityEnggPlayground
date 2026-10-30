"""Baseline: application role privileges and the job queue schema.

Revision ID: 0001
Revises:
Create Date: 2026-10-30
"""

from collections.abc import Sequence

from alembic import op
from procrastinate.schema import SchemaManager

from passport.settings import get_settings

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    app_role = get_settings().app_db_role
    # Every table the owner creates is usable by the app role; tables that must be
    # append-only (the event log) revoke UPDATE and DELETE in their own migration.
    op.execute(f"GRANT USAGE ON SCHEMA public TO {app_role}")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {app_role}"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {app_role}"
    )
    op.execute(SchemaManager.get_schema())


def downgrade() -> None:
    op.execute(
        """
        DO $$
        DECLARE r record;
        BEGIN
          FOR r IN SELECT tablename FROM pg_tables
                   WHERE schemaname = 'public' AND tablename LIKE 'procrastinate%' LOOP
            EXECUTE format('DROP TABLE IF EXISTS %I CASCADE', r.tablename);
          END LOOP;
          FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p
                   JOIN pg_namespace n ON n.oid = p.pronamespace
                   WHERE n.nspname = 'public' AND p.proname LIKE 'procrastinate%' LOOP
            EXECUTE format('DROP FUNCTION IF EXISTS %s CASCADE', r.sig);
          END LOOP;
          FOR r IN SELECT t.typname FROM pg_type t
                   JOIN pg_namespace n ON n.oid = t.typnamespace
                   WHERE n.nspname = 'public' AND t.typname LIKE 'procrastinate%'
                     AND t.typtype IN ('e', 'c') LOOP
            EXECUTE format('DROP TYPE IF EXISTS %I CASCADE', r.typname);
          END LOOP;
        END $$;
        """
    )
    app_role = get_settings().app_db_role
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM {app_role}")
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM {app_role}")
