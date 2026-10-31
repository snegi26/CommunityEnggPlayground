"""The weekly report's email summary (U13, KTD12).

Sent to the org's owners only. The body carries counts, item titles, and a link to the
in-product report, and nothing else: no causes, so no account names, offenders, account
ids, or raw observations reach an inbox. Connected systems are named by kind (AWS,
Google Workspace, GitHub), not by their display names, which are free text.

SMTP is configured per deployment through ``EmailSettings``; tests inject a fake
``Mailer``. A report is marked sent only after the mailer accepted every message.
"""

import smtplib
import ssl
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from email.message import EmailMessage
from typing import Any, Protocol

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.auth.models import User
from passport.db.base import utcnow
from passport.provenance.service import append_event
from passport.reports.builder import report_actor
from passport.reports.models import WeeklyReport
from passport.tenancy.models import Membership, Org, Role

KIND_LABELS: Mapping[str, str] = {
    "aws": "AWS",
    "google_workspace": "Google Workspace",
    "github": "GitHub",
}


class EmailSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "passport@localhost"
    # Public base URL of the web app, for links to the in-product report.
    passport_base_url: str = "http://localhost:8000"


class Mailer(Protocol):
    def send(self, message: EmailMessage) -> None: ...


class InsecureSmtpError(RuntimeError):
    """SMTP credentials would be sent over an unencrypted connection."""


class SmtpMailer:
    """Send through an SMTP server with stdlib ``smtplib``.

    Port 465 uses implicit TLS; otherwise STARTTLS is used when the server offers it.
    Credentials are never sent over a connection that is not encrypted.
    """

    def __init__(self, settings: EmailSettings, *, timeout: float = 30.0) -> None:
        self._settings = settings
        self._timeout = timeout

    def send(self, message: EmailMessage) -> None:
        s = self._settings
        context = ssl.create_default_context()
        smtp: smtplib.SMTP
        if s.smtp_port == 465:
            smtp = smtplib.SMTP_SSL(
                s.smtp_host, s.smtp_port, timeout=self._timeout, context=context
            )
            encrypted = True
        else:
            smtp = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=self._timeout)
            encrypted = False
        with smtp:
            if not encrypted:
                smtp.ehlo()
                if smtp.has_extn("starttls"):
                    smtp.starttls(context=context)
                    smtp.ehlo()
                    encrypted = True
            if s.smtp_username:
                if not encrypted:
                    raise InsecureSmtpError("the SMTP server offers no TLS; refusing to log in")
                smtp.login(s.smtp_username, s.smtp_password or "")
            smtp.send_message(message)


def report_link(settings: EmailSettings, report: WeeklyReport) -> str:
    base = settings.passport_base_url.rstrip("/")
    return f"{base}/orgs/{report.org_id}/reports/{report.id}"


def _titles(entries: Sequence[Mapping[str, Any]]) -> list[str]:
    return [f"  - {e['title']} ({e['framework']}): {e['status_label']}" for e in entries]


def email_subject(
    *, org_name: str, sections: Mapping[str, Any], coverage: Mapping[str, Any]
) -> str:
    if sections.get("baseline"):
        summary = "baseline report"
    elif sections.get("quiet_week"):
        summary = "nothing changed"
    else:
        summary = f"{len(sections['newly_bad'])} newly bad, {len(sections['resolved'])} resolved"
    if not coverage.get("all_reachable"):
        summary += ", not everything was checked"
    return f"Weekly freshness report for {org_name}: {summary}"


def email_body(
    *, org_name: str, sections: Mapping[str, Any], coverage: Mapping[str, Any], link: str
) -> str:
    """Counts, item titles, and the link; never causes or system observations (KTD12)."""
    lines = [f"Weekly freshness report for {org_name}", ""]
    if sections.get("baseline"):
        lines.append("This is the first report: a baseline of every item.")
    elif sections.get("quiet_week"):
        lines.append("Nothing changed since the last report, and every system was reachable.")
    elif sections.get("nothing_changed"):
        lines.append("No status changed since the last report, but not everything was checked.")
    lines += [
        "",
        f"Newly bad: {len(sections['newly_bad'])}",
        *_titles(sections["newly_bad"]),
        f"Resolved: {len(sections['resolved'])}",
        *_titles(sections["resolved"]),
        f"Still bad: {len(sections['still_bad'])}",
        *_titles(sections["still_bad"]),
        "",
        "Coverage",
        f"  Claims checked: {coverage['checked']} of {coverage['claims']}",
        f"  Contradicted: {coverage['contradicted']}",
        f"  Check failed: {coverage['check_failed']}",
        f"  Not checkable: {coverage['not_checkable']}",
    ]
    systems = list(coverage.get("systems", ()))
    down = [s for s in systems if not s["reachable"]]
    lines.append(f"  Connected systems reachable: {len(systems) - len(down)} of {len(systems)}")
    if down:
        kinds = sorted({KIND_LABELS.get(s["kind"], s["kind"]) for s in down})
        lines.append(f"  Unreachable this week: {len(down)} ({', '.join(kinds)})")
    if coverage.get("run_status") != "succeeded":
        lines.append(f"  The check run did not finish ({coverage.get('run_status')}).")
    lines += ["", f"Full report, with causes: {link}", ""]
    return "\n".join(lines)


def owner_recipients(session: Session, org_id: uuid.UUID) -> list[tuple[uuid.UUID, str]]:
    """``(user_id, email)`` of the org's owners, in a stable order."""
    rows = session.execute(
        select(User.id, User.email)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.org_id == org_id, Membership.role == Role.OWNER)
        .order_by(User.email)
    )
    return [(user_id, email) for user_id, email in rows]


def send_report(
    session: Session,
    report: WeeklyReport,
    *,
    mailer: Mailer,
    settings: EmailSettings,
    clock: Callable[[], datetime] = utcnow,
) -> list[str]:
    """Email the report's summary to each owner, then mark it sent; returns addresses.

    A report already sent is not sent again. If the mailer raises, the report stays
    unsent (and is not a diff baseline) and the error propagates.
    """
    if report.sent_at is not None:
        return []
    org = session.get(Org, report.org_id)
    org_name = org.name if org is not None else "your organization"
    recipients = owner_recipients(session, report.org_id)
    link = report_link(settings, report)
    subject = email_subject(org_name=org_name, sections=report.sections, coverage=report.coverage)
    body = email_body(
        org_name=org_name, sections=report.sections, coverage=report.coverage, link=link
    )
    for _, address in recipients:
        message = EmailMessage()
        message["From"] = settings.smtp_from
        message["To"] = address
        message["Subject"] = subject
        message.set_content(body)
        mailer.send(message)
    report.sent_at = clock()
    session.flush()
    append_event(
        session,
        org_id=report.org_id,
        actor=report_actor(report.check_run_id),
        event_type="weekly_report.sent",
        subject_kind="weekly_report",
        subject_id=report.id,
        payload={
            "recipients": [str(user_id) for user_id, _ in recipients],
            "sent_at": report.sent_at.isoformat(),
        },
    )
    return [address for _, address in recipients]
