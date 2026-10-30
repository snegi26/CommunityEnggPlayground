"""Shared fixtures: a fresh database migrated by the owner role, used by the app role."""

import os
from collections.abc import Iterator

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from psycopg import sql

from passport.db.engine import get_engine, get_sessionmaker
from passport.settings import Settings, get_settings, libpq_url

TEST_DB = "passport_test"


def _with_database(url: str, database: str) -> str:
    return url.rsplit("/", 1)[0] + "/" + database


def alembic_config(url: str) -> Config:
    config = Config("alembic.ini")
    config.attributes["url"] = url
    return config


@pytest.fixture(scope="session")
def database_urls() -> Iterator[dict[str, str]]:
    base = Settings()
    owner_url = _with_database(base.migration_database_url, TEST_DB)
    app_url = _with_database(base.database_url, TEST_DB)
    admin = libpq_url(_with_database(base.migration_database_url, "postgres"))
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(
            sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(TEST_DB))
        )
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(TEST_DB)))

    os.environ["DATABASE_URL"] = app_url
    os.environ["MIGRATION_DATABASE_URL"] = owner_url
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()

    command.upgrade(alembic_config(owner_url), "head")
    yield {"owner": owner_url, "app": app_url}
    get_engine().dispose()
