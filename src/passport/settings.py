"""Runtime configuration loaded from environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Non-owner application role without BYPASSRLS (KTD5). Used by web and worker.
    database_url: str = "postgresql+psycopg://passport_app:app@localhost:5432/passport"
    # Table-owner role used only by Alembic and test fixtures.
    migration_database_url: str = (
        "postgresql+psycopg://passport_owner:owner@localhost:5432/passport"
    )
    # Name of the application role that migrations grant privileges to.
    app_db_role: str = "passport_app"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def libpq_url(sqlalchemy_url: str) -> str:
    """Strip the SQLAlchemy driver suffix so psycopg can use the URL directly."""
    return sqlalchemy_url.replace("postgresql+psycopg://", "postgresql://", 1)
