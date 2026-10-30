import asyncio

import psycopg
from alembic import command

from passport.settings import libpq_url
from tests.conftest import alembic_config


def test_app_role_neither_owns_tables_nor_bypasses_rls(database_urls: dict[str, str]) -> None:
    with psycopg.connect(libpq_url(database_urls["app"])) as conn:
        bypass = conn.execute(
            "SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
        owned = conn.execute(
            "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' "
            "AND tableowner = current_user"
        ).fetchone()

    assert bypass == (False, False)
    assert owned == (0,)


def test_migrations_downgrade_to_base_and_upgrade_again(database_urls: dict[str, str]) -> None:
    # A separate database, so dropping and recreating types cannot invalidate type
    # caches held by connections other tests already opened.
    owner_url = database_urls["owner"].rsplit("/", 1)[0] + "/passport_test_roundtrip"
    admin = libpq_url(database_urls["owner"].rsplit("/", 1)[0] + "/postgres")
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute("DROP DATABASE IF EXISTS passport_test_roundtrip WITH (FORCE)")
        conn.execute("CREATE DATABASE passport_test_roundtrip")
    config = alembic_config(owner_url)
    try:
        command.upgrade(config, "heads")
        command.downgrade(config, "base")
        with psycopg.connect(libpq_url(owner_url)) as conn:
            leftover = conn.execute(
                "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' "
                "AND tablename <> 'alembic_version'"
            ).fetchone()
        command.upgrade(config, "heads")
    finally:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute("DROP DATABASE IF EXISTS passport_test_roundtrip WITH (FORCE)")

    assert leftover == (0,)


def test_task_enqueued_by_web_is_executed_by_worker(database_urls: dict[str, str]) -> None:
    from passport.jobs import app, noop

    async def run() -> list[str]:
        async with app.open_async():
            job_id = await noop.defer_async(marker="hello")
            await app.run_worker_async(wait=False, install_signal_handlers=False)
            jobs = await app.job_manager.list_jobs_async(id=job_id)
            return [job.status for job in jobs]

    assert asyncio.run(run()) == ["succeeded"]
