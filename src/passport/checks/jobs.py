"""Scheduled and on-demand check jobs (R10, KTD5, KTD11).

``passport.jobs.app`` lists ``"passport.checks.jobs"`` in its ``import_paths`` so the
worker registers these tasks.

Weekly: a periodic task reads org ids through the scheduler's ``SECURITY DEFINER``
function (``all_org_ids``, the only cross-org path, KTD5), then per org, inside that
org's context, requests a run and defers one job for it, offset by an org-derived
stagger so connector rate limits are spread over a window.

On demand: ``passport.checks.runner.request_rerun`` (owner-only) creates or returns the
org's queued or running run; the caller commits and then calls ``enqueue_run`` only when
a run was created.
"""

import asyncio
import hashlib
import uuid
from datetime import timedelta
from typing import Any

import httpx

from passport.checks.runner import (
    DEFAULT_MAX_DURATION,
    SCHEDULED,
    Clock,
    ConnectorFactory,
    execute_run,
    fail_run,
    request_run,
)
from passport.connectors.base import Connector
from passport.connectors.models import Connection
from passport.connectors.setup import PlatformSettings, connector_for
from passport.connectors.vault import Vault, get_vault
from passport.db.base import utcnow
from passport.db.engine import get_sessionmaker
from passport.db.rls import set_org_context
from passport.jobs import app
from passport.tenancy.service import all_org_ids

# Mondays 03:17 UTC; each org's run then starts within the stagger window.
WEEKLY_CRON = "17 3 * * 1"
STAGGER_WINDOW = timedelta(hours=6)
HTTP_TIMEOUT_SECONDS = 30.0


def stagger_offset(org_id: uuid.UUID) -> timedelta:
    """A stable per-org delay within the stagger window."""
    digest = hashlib.sha256(org_id.bytes).digest()
    seconds = int.from_bytes(digest[:8], "big") % int(STAGGER_WINDOW.total_seconds())
    return timedelta(seconds=seconds)


def live_connector_factory(
    platform: PlatformSettings, vault: Vault, http: httpx.Client
) -> ConnectorFactory:
    def build(session: Any, connection: Connection) -> Connector:
        return connector_for(session, connection, platform=platform, vault=vault, http=http)

    return build


def run_checks_for_org(
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    connector_factory: ConnectorFactory | None = None,
    clock: Clock = utcnow,
) -> dict[str, Any]:
    """Execute (or resume) one run in its own session; an error marks the run failed."""
    sessions = get_sessionmaker()
    try:
        with sessions() as session:
            set_org_context(session, org_id)
            if connector_factory is not None:
                summary = execute_run(
                    session, org_id, run_id, connector_factory=connector_factory, clock=clock
                )
            else:
                with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS) as http:
                    factory = live_connector_factory(PlatformSettings(), get_vault(), http)
                    summary = execute_run(
                        session,
                        org_id,
                        run_id,
                        connector_factory=factory,
                        max_duration=DEFAULT_MAX_DURATION,
                        clock=clock,
                    )
    except Exception as exc:
        with sessions() as session:
            set_org_context(session, org_id)
            fail_run(session, org_id, run_id, f"{type(exc).__name__}: {exc}")
            session.commit()
        raise
    return {
        "run_id": str(summary.run_id),
        "status": summary.status.value,
        "coverage": summary.coverage.to_json(),
    }


@app.task(name="passport.checks.run_org_checks")
def run_org_checks(org_id: str, run_id: str) -> dict[str, Any]:
    """Run one org's checks with live connectors, then queue its weekly report (R11)."""
    from passport.reports.jobs import enqueue_report

    result = run_checks_for_org(uuid.UUID(org_id), uuid.UUID(run_id))
    enqueue_report(uuid.UUID(org_id), uuid.UUID(run_id))
    return result


def enqueue_run(org_id: uuid.UUID, run_id: uuid.UUID, *, delay: timedelta | None = None) -> int:
    """Defer the job for a run the caller has already committed."""
    seconds = int(delay.total_seconds()) if delay else 0
    return run_org_checks.configure(schedule_in={"seconds": seconds}).defer(
        org_id=str(org_id), run_id=str(run_id)
    )


def create_scheduled_runs(clock: Clock = utcnow) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """Request a scheduled run per org; returns ``(org_id, run_id)`` for runs created.

    An org whose run is already queued or running gets no second run.
    """
    sessions = get_sessionmaker()
    with sessions() as session:
        org_ids = all_org_ids(session)
    created: list[tuple[uuid.UUID, uuid.UUID]] = []
    for org_id in org_ids:
        with sessions() as session:
            set_org_context(session, org_id)
            run, new = request_run(session, org_id, trigger=SCHEDULED, clock=clock)
            session.commit()
            if new:
                created.append((org_id, run.id))
    return created


async def schedule_weekly_runs(clock: Clock = utcnow) -> int:
    """Create the week's runs and defer each org's job at its stagger offset."""
    created = await asyncio.to_thread(create_scheduled_runs, clock)
    for org_id, run_id in created:
        offset = int(stagger_offset(org_id).total_seconds())
        await run_org_checks.configure(schedule_in={"seconds": offset}).defer_async(
            org_id=str(org_id), run_id=str(run_id)
        )
    return len(created)


@app.periodic(cron=WEEKLY_CRON)
@app.task(name="passport.checks.schedule_weekly", queueing_lock="passport.checks.schedule_weekly")
async def schedule_weekly(timestamp: int) -> int:
    """The weekly trigger (R10): one staggered check job per org."""
    return await schedule_weekly_runs()
