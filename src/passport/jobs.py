"""Background job queue (KTD11). Units register their tasks on ``app``."""

import procrastinate

from passport.settings import get_settings, libpq_url

app = procrastinate.App(
    connector=procrastinate.PsycopgConnector(conninfo=libpq_url(get_settings().database_url)),
    import_paths=["passport.jobs", "passport.agent.jobs"],
)


@app.task(name="passport.noop")
def noop(marker: str) -> str:
    """Smoke-test task proving web-to-worker delivery."""
    return marker
