"""Weekly report (U13): built from real runs, emailed to owners, diffed against the last sent."""

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.checks.runner import execute_run, request_run
from passport.connectors.base import Capability, Connector
from passport.connectors.fakes import FakeConnector, failure, users_mfa
from passport.connectors.models import ConnectionKind
from passport.connectors.observation import FailureKind
from passport.connectors.registry import create_connection
from passport.controls.models import ScopeKind
from passport.controls.settings import add_scope_entry, ensure_defaults
from passport.db.engine import get_sessionmaker
from passport.db.models import Claim, ClaimState, Document, DocumentVersion, Event
from passport.db.rls import set_org_context
from passport.provenance.actor import Human
from passport.provenance.service import verify_chain
from passport.reports.builder import render_report_html
from passport.reports.email import EmailSettings
from passport.reports.jobs import build_and_send_for_org
from passport.reports.models import WeeklyReport
from tests.helpers import SignedInUser, create_org, invite_and_join, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")

PROD = "111111111111"
DOMAIN = "example.com"
OFFENDER = "bob.offender"
WEEK1 = datetime(2026, 10, 5, 3, tzinfo=UTC)
SETTINGS = EmailSettings(
    smtp_from="passport@example.com", passport_base_url="https://passport.example"
)


class FakeMailer:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.sent: list[EmailMessage] = []

    def send(self, message: EmailMessage) -> None:
        if self.fail:
            raise ConnectionRefusedError("smtp down")
        self.sent.append(message)


def _session(org_id: uuid.UUID) -> Session:
    db = get_sessionmaker()()
    set_org_context(db, org_id)
    return db


def _setup(owner: SignedInUser, *, workspace: bool = False) -> uuid.UUID:
    """An org with AWS (and optionally Workspace), an MFA policy, and an empty policy."""
    org_id = create_org(owner)
    actor = Human(owner.user_id)
    with _session(org_id) as db:
        ensure_defaults(db, org_id, actor)
        add_scope_entry(db, org_id, actor, ScopeKind.AWS_ACCOUNT, PROD, production=True)
        create_connection(
            db, org_id=org_id, actor=actor, kind=ConnectionKind.AWS, display_name="AWS prod"
        )
        if workspace:
            add_scope_entry(db, org_id, actor, ScopeKind.WORKSPACE_DOMAIN, DOMAIN, production=True)
            create_connection(
                db,
                org_id=org_id,
                actor=actor,
                kind=ConnectionKind.GOOGLE_WORKSPACE,
                display_name="Workspace",
            )
        for title, with_claim in [("Access policy", True), ("Backup policy", False)]:
            document = Document(org_id=org_id, title=title)
            db.add(document)
            db.flush()
            version = DocumentVersion(
                org_id=org_id,
                document_id=document.id,
                version_number=1,
                filename="p.md",
                content_hash="0" * 64,
                storage_key="k",
            )
            db.add(version)
            db.flush()
            if with_claim:
                db.add(
                    Claim(
                        org_id=org_id,
                        document_version_id=version.id,
                        span_id="s1",
                        quote="MFA is required on all production accounts.",
                        predicate_id="mfa_enforced",
                        predicate_version=1,
                        parameters={"scope": "all_production_accounts"},
                        state=ClaimState.CONFIRMED,
                    )
                )
        db.commit()
    return org_id


def aws(mfa: Mapping[str, bool]) -> FakeConnector:
    return FakeConnector(
        ConnectionKind.AWS, scope=(PROD,), responses={Capability.LIST_USERS_MFA: users_mfa(mfa)}
    )


def workspace(ok: bool) -> FakeConnector:
    response = users_mfa({"carol": True}) if ok else failure(FailureKind.UNAUTHORIZED, "revoked")
    return FakeConnector(
        ConnectionKind.GOOGLE_WORKSPACE,
        scope=(DOMAIN,),
        responses={Capability.LIST_USERS_MFA: response},
    )


def week(
    org_id: uuid.UUID,
    n: int,
    fakes: Mapping[str, Connector],
    mailer: FakeMailer,
) -> WeeklyReport:
    """Run week ``n``'s checks, then build and send its report; returns the report."""
    at = WEEK1 + timedelta(days=7 * n)
    with _session(org_id) as db:
        run, _ = request_run(db, org_id, trigger="scheduled", clock=lambda: at)
        db.commit()
        set_org_context(db, org_id)
        execute_run(
            db,
            org_id,
            run.id,
            connector_factory=lambda _s, c: fakes[c.display_name],
            clock=lambda: at,
            today=at.date(),
        )
        run_id = run.id
    try:
        build_and_send_for_org(org_id, run_id, mailer=mailer, settings=SETTINGS, clock=lambda: at)
    except ConnectionRefusedError:
        assert mailer.fail
    with _session(org_id) as db:
        report = db.scalars(select(WeeklyReport).where(WeeklyReport.check_run_id == run_id)).one()
        db.expunge(report)
        return report


def body(message: EmailMessage) -> str:
    content = message.get_content()
    assert isinstance(content, str)
    return content


def titles(report: WeeklyReport, section: str) -> list[str]:
    return [e["title"] for e in report.sections[section]]


def test_the_first_report_is_a_baseline_emailed_to_owners_without_account_names() -> None:
    owner = sign_up()
    approver = sign_up()
    org_id = _setup(owner)
    invite_and_join(owner, org_id, approver, "approver")
    mailer = FakeMailer()

    report = week(org_id, 0, {"AWS prod": aws({"alice": True, OFFENDER: False})}, mailer)

    assert report.sections["baseline"] is True
    assert sorted(titles(report, "all_items")) == ["Access policy", "Backup policy"]
    assert report.sent_at is not None
    # Owners only.
    assert [m["To"] for m in mailer.sent] == [owner.email]
    text = body(mailer.sent[0])
    assert "Access policy" in text and "Backup policy" in text
    assert f"https://passport.example/orgs/{org_id}/reports/{report.id}" in text
    # The contradiction names the account in product, never in the email (KTD12).
    assert OFFENDER not in text and PROD not in text
    assert OFFENDER in " ".join(c for e in report.sections["newly_bad"] for c in e["causes"])
    html = render_report_html(
        org_name="Acme",
        sections=report.sections,
        coverage=report.coverage,
        generated_at=report.created_at,
    )
    assert OFFENDER in html

    with _session(org_id) as db:
        events = [
            e.event_type
            for e in db.scalars(
                select(Event).where(Event.subject_kind == "weekly_report").order_by(Event.seq)
            )
        ]
        assert events == ["weekly_report.built", "weekly_report.sent"]
        assert verify_chain(db, org_id).ok

    # A retried job for the same run neither rebuilds nor mails again.
    build_and_send_for_org(org_id, report.check_run_id, mailer=mailer, settings=SETTINGS)
    assert len(mailer.sent) == 1
    with _session(org_id) as db:
        assert len(list(db.scalars(select(WeeklyReport)))) == 1


def test_ae8_a_fixed_contradiction_is_resolved_then_ae4_a_quiet_week_says_nothing_changed() -> None:
    owner = sign_up()
    org_id = _setup(owner)
    mailer = FakeMailer()
    week(org_id, 0, {"AWS prod": aws({"alice": True, OFFENDER: False})}, mailer)

    fixed = week(org_id, 1, {"AWS prod": aws({"alice": True, OFFENDER: True})}, mailer)

    assert [(e["title"], e["before"], e["status"]) for e in fixed.sections["resolved"]] == [
        ("Access policy", "contradicted", "current")
    ]
    assert titles(fixed, "still_bad") == ["Backup policy"]
    assert fixed.sections["newly_bad"] == []

    quiet = week(org_id, 2, {"AWS prod": aws({"alice": True, OFFENDER: True})}, mailer)

    assert quiet.sections["nothing_changed"] is True and quiet.sections["quiet_week"] is True
    coverage = quiet.coverage
    assert (coverage["claims"], coverage["checked"], coverage["check_failed"]) == (1, 1, 0)
    assert coverage["not_checkable"] == 0 and coverage["all_reachable"] is True
    text = body(mailer.sent[-1])
    assert "Nothing changed since the last report" in text
    assert "Claims checked: 1 of 1" in text
    assert "Connected systems reachable: 1 of 1" in text


def test_after_a_missed_week_the_diff_compares_against_the_last_sent_report() -> None:
    owner = sign_up()
    org_id = _setup(owner)
    week(org_id, 0, {"AWS prod": aws({"alice": True, OFFENDER: False})}, FakeMailer())

    # Week 1 fixed the account, but its email failed: the report is stored, not sent.
    missed = week(
        org_id, 1, {"AWS prod": aws({"alice": True, OFFENDER: True})}, FakeMailer(fail=True)
    )
    assert missed.sent_at is None
    assert titles(missed, "resolved") == ["Access policy"]

    # Week 2 has the same state as week 1, but week 1 was never sent: still resolved.
    mailer = FakeMailer()
    report = week(org_id, 2, {"AWS prod": aws({"alice": True, OFFENDER: True})}, mailer)

    assert titles(report, "resolved") == ["Access policy"]
    assert report.sections["nothing_changed"] is False
    assert report.sent_at is not None
    assert "Resolved: 1" in body(mailer.sent[0])
    with _session(org_id) as db:
        sent = db.scalars(select(Event).where(Event.event_type == "weekly_report.sent"))
        assert {e.subject_id for e in sent} == {
            str(r.id) for r in db.scalars(select(WeeklyReport)) if r.sent_at is not None
        }
        assert (
            len(list(db.scalars(select(WeeklyReport).where(WeeklyReport.sent_at.is_(None))))) == 1
        )


def test_ae6_an_unreachable_identity_provider_shows_in_coverage_and_the_email() -> None:
    owner = sign_up()
    org_id = _setup(owner, workspace=True)
    mailer = FakeMailer()
    week(org_id, 0, {"AWS prod": aws({"alice": True}), "Workspace": workspace(True)}, mailer)

    report = week(
        org_id, 1, {"AWS prod": aws({"alice": True}), "Workspace": workspace(False)}, mailer
    )

    coverage = report.coverage
    assert coverage["unreachable"] == ["Workspace"] and coverage["all_reachable"] is False
    assert {s["name"]: s["reachable"] for s in coverage["systems"]} == {
        "AWS prod": True,
        "Workspace": False,
    }
    assert [(e["title"], e["status"]) for e in report.sections["newly_bad"]] == [
        ("Access policy", "check_failed")
    ]
    assert report.sections["quiet_week"] is False
    html = render_report_html(
        org_name="Acme",
        sections=report.sections,
        coverage=coverage,
        generated_at=report.created_at,
    )
    assert "Workspace: unreachable" in html and "Not everything was checked" in html
    text = body(mailer.sent[-1])
    assert "Connected systems reachable: 1 of 2" in text
    assert "Unreachable this week: 1 (Google Workspace)" in text
    assert "not everything was checked" in mailer.sent[-1]["Subject"]
