"""Alembic environment. Migrations always run as the table-owner role (KTD5)."""

from alembic import context
from sqlalchemy import create_engine

from passport.settings import get_settings

config = context.config


def run_migrations_online() -> None:
    url = config.attributes.get("url") or get_settings().migration_database_url
    engine = create_engine(url)
    with engine.connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
