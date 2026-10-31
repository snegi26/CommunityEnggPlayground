"""Build and send an org's weekly report after a check run (F2).

``passport.jobs.app`` must list ``"passport.reports.jobs"`` in its ``import_paths`` so
the worker registers this task. The task is deferred once a run has finished
(``enqueue_report``).

The report is committed before it is mailed, so a mail failure leaves a stored, unsent
report; the next report then diffs against the last report that was sent. A retried
job reuses the run's report and sends it only if it is still unsent.
"""

import uuid
from typing import Any

from passport.db.base import utcnow
from passport.db.engine import get_sessionmaker
from passport.db.rls import set_org_context
from passport.jobs import app
from passport.reports.builder import Clock, build_report
from passport.reports.email import EmailSettings, Mailer, SmtpMailer, send_report


def build_and_send_for_org(
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    mailer: Mailer | None = None,
    settings: EmailSettings | None = None,
    clock: Clock = utcnow,
) -> dict[str, Any]:
    settings = settings or EmailSettings()
    mailer = mailer or SmtpMailer(settings)
    sessions = get_sessionmaker()
    with sessions() as session:
        set_org_context(session, org_id)
        report = build_report(session, org_id, run_id, clock=clock)
        report_id = report.id
        session.commit()
        set_org_context(session, org_id)
        sent_to = send_report(session, report, mailer=mailer, settings=settings, clock=clock)
        session.commit()
    return {"report_id": str(report_id), "sent_to": len(sent_to)}


@app.task(name="passport.reports.build_and_send")
def build_and_send_weekly_report(org_id: str, run_id: str) -> dict[str, Any]:
    """Build the run's report and email it to the org's owners over SMTP."""
    return build_and_send_for_org(uuid.UUID(org_id), uuid.UUID(run_id))


def enqueue_report(org_id: uuid.UUID, run_id: uuid.UUID) -> int:
    """Defer the report job for a run the caller has already committed as finished."""
    return build_and_send_weekly_report.defer(org_id=str(org_id), run_id=str(run_id))
