"""Passport, claim review, re-run, and report pages (U14) through the real HTTP app."""

import re
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from procrastinate.testing import InMemoryConnector
from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.checks.jobs import run_checks_for_org
from passport.checks.runner import ConnectorFactory, fail_run, request_run
from passport.connectors.base import Capability, Connector
from passport.connectors.fakes import FakeConnector, Rows, users_mfa
from passport.connectors.models import Connection, ConnectionKind
from passport.connectors.registry import create_connection
from passport.controls.models import Framework, ItemKind, ScopeKind
from passport.controls.service import map_item
from passport.controls.settings import add_scope_entry
from passport.db.engine import get_sessionmaker
from passport.db.models import Claim, ClaimState, Document, DocumentVersion, EvidenceItem
from passport.db.rls import set_org_context
from passport.jobs import app as jobs_app
from passport.provenance.actor import Human
from passport.reports.builder import build_report
from passport.status.service import recompute_statuses
from tests.helpers import SignedInUser, create_org, invite_and_join, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")

AWS_PROD = "111111111111"
MFA_QUOTE = "MFA is required on all production accounts."
ROOT_QUOTE = "The root user of every AWS account has MFA."
CSRF = re.compile(r'name="csrf_token" value="([0-9a-f]{64})"')


# --- helpers (also used by test_web_setup) --------------------------------------------


def db_for(org_id: uuid.UUID) -> Session:
    db = get_sessionmaker()()
    set_org_context(db, org_id)
    return db


def csrf(client: TestClient, path: str = "/") -> str:
    page = client.get(path)
    match = CSRF.search(page.text)
    assert match, page.text[:500]
    return match.group(1)


def row_html(page: str, kind: str, item_id: uuid.UUID) -> str:
    match = re.search(rf'<tr class="item" data-item="{kind}:{item_id}">(.*?)</tr>', page, re.S)
    assert match, f"no row for {kind}:{item_id}"
    return match.group(1)


def connect_aws(org_id: uuid.UUID, owner: SignedInUser, name: str = "AWS prod") -> None:
    actor = Human(owner.user_id)
    with db_for(org_id) as db:
        create_connection(
            db, org_id=org_id, actor=actor, kind=ConnectionKind.AWS, display_name=name
        )
        add_scope_entry(db, org_id, actor, ScopeKind.AWS_ACCOUNT, AWS_PROD, production=True)
        db.commit()


def seed_policy(
    org_id: uuid.UUID,
    owner: SignedInUser,
    title: str,
    claims: list[tuple[str, str | None, dict[str, Any], ClaimState]],
    frameworks: tuple[Framework, ...] = (Framework.SOC2,),
    needs_review_reason: str | None = None,
) -> tuple[uuid.UUID, uuid.UUID, list[uuid.UUID]]:
    """A one-version policy with claims, mapped to a control per framework."""
    actor = Human(owner.user_id)
    with db_for(org_id) as db:
        document = Document(org_id=org_id, title=title)
        db.add(document)
        db.flush()
        version = DocumentVersion(
            org_id=org_id,
            document_id=document.id,
            version_number=1,
            filename=f"{title}.md",
            content_hash="0" * 64,
            storage_key="k",
        )
        db.add(version)
        db.flush()
        ids = []
        for i, (quote, predicate, params, state) in enumerate(claims):
            claim = Claim(
                org_id=org_id,
                document_version_id=version.id,
                span_id=f"s{i}",
                quote=quote,
                predicate_id=predicate,
                predicate_version=1 if predicate else None,
                parameters=params,
                check_description=f"Check: {quote}" if predicate else None,
                state=state,
                needs_review_reason=needs_review_reason
                if state is ClaimState.NEEDS_REVIEW
                else None,
                created_at=datetime(2026, 10, 1, tzinfo=UTC) + timedelta(seconds=i),
            )
            db.add(claim)
            db.flush()
            ids.append(claim.id)
        for framework in frameworks:
            control = "CC6.1" if framework is Framework.SOC2 else "5.15"
            map_item(db, org_id, actor, ItemKind.DOCUMENT, document.id, framework, control)
        recompute_statuses(db, org_id)
        db.commit()
        return document.id, version.id, ids


def seed_evidence(
    org_id: uuid.UUID, owner: SignedInUser, title: str, framework: Framework
) -> uuid.UUID:
    actor = Human(owner.user_id)
    with db_for(org_id) as db:
        item = EvidenceItem(
            org_id=org_id,
            title=title,
            filename="e.pdf",
            content_hash="1" * 64,
            storage_key="k",
            source="export",
            collected_at=datetime.now(UTC) - timedelta(days=3),
        )
        db.add(item)
        db.flush()
        control = "CC6.1" if framework is Framework.SOC2 else "5.15"
        map_item(db, org_id, actor, ItemKind.EVIDENCE, item.id, framework, control)
        recompute_statuses(db, org_id)
        db.commit()
        return item.id


def mfa_claim(
    state: ClaimState = ClaimState.CONFIRMED,
) -> tuple[str, str, dict[str, Any], ClaimState]:
    return (MFA_QUOTE, "mfa_enforced", {"scope": "all_production_accounts"}, state)


def root_claim(
    state: ClaimState = ClaimState.CONFIRMED,
) -> tuple[str, str, dict[str, Any], ClaimState]:
    return (ROOT_QUOTE, "root_mfa_enabled", {"scope": "all_accounts"}, state)


def aws_fake() -> FakeConnector:
    return FakeConnector(
        ConnectionKind.AWS,
        scope=(AWS_PROD,),
        responses={
            Capability.LIST_USERS_MFA: users_mfa({"alice": True, "bob": False}),
            Capability.GET_ROOT_MFA: Rows([{"account": AWS_PROD, "root_mfa": True}]),
        },
    )


def factory(fakes: Mapping[str, Connector]) -> ConnectorFactory:
    def build(session: Session, connection: Connection) -> Connector:
        return fakes[connection.display_name]

    return build


def run_checks(org_id: uuid.UUID, fakes: Mapping[str, Connector]) -> uuid.UUID:
    with db_for(org_id) as db:
        run, _ = request_run(db, org_id, trigger="scheduled")
        run_id = run.id
        db.commit()
    run_checks_for_org(org_id, run_id, connector_factory=factory(fakes))
    return run_id


@pytest.fixture
def owner() -> SignedInUser:
    return sign_up()


@pytest.fixture
def org_id(owner: SignedInUser) -> uuid.UUID:
    return create_org(owner)


# --- passport --------------------------------------------------------------------------


def test_the_passport_shows_status_last_checked_and_approver_or_unapproved(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    connect_aws(org_id, owner)
    access, _, _ = seed_policy(org_id, owner, "Access policy", [mfa_claim()])
    cloud, _, _ = seed_policy(org_id, owner, "Cloud policy", [root_claim()])
    run_checks(org_id, {"AWS prod": aws_fake()})
    client = owner.client
    token = csrf(client, f"/orgs/{org_id}/passport")

    approved = client.post(
        f"/orgs/{org_id}/items/document/{cloud}/approve",
        data={"csrf_token": token, "framework": "soc2"},
        follow_redirects=False,
    )
    assert approved.status_code == 303

    page = client.get(f"/orgs/{org_id}/passport?framework=soc2").text
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    access_row = row_html(page, "document", access)
    assert "Contradicted" in access_row and "Trusted" in access_row
    assert "bob" in access_row  # the cause names the offender (R3)
    assert today in re.search(r'class="last-checked">(.*?)</td>', access_row, re.S).group(1)  # type: ignore[union-attr]
    assert re.search(r'class="approver">\s*unapproved', access_row)
    cloud_row = row_html(page, "document", cloud)
    assert "Current" in cloud_row
    approver = re.search(r'class="approver">(.*?)</td>', cloud_row, re.S).group(1)  # type: ignore[union-attr]
    assert owner.email in approver and today in approver
    # The badge carries its status as text, not colour alone.
    assert '<span class="badge status-contradicted">Contradicted</span>' in access_row


def test_switching_frameworks_shows_only_items_mapped_to_that_framework(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    soc2_doc, _, _ = seed_policy(org_id, owner, "SOC only policy", [mfa_claim()])
    iso_ev = seed_evidence(org_id, owner, "ISO access review export", Framework.ISO27001)

    soc2 = owner.client.get(f"/orgs/{org_id}/passport?framework=soc2").text
    iso = owner.client.get(f"/orgs/{org_id}/passport?framework=iso27001").text

    assert f"document:{soc2_doc}" in soc2 and f"evidence:{iso_ev}" not in soc2
    assert f"evidence:{iso_ev}" in iso and f"document:{soc2_doc}" not in iso
    assert "Never" in row_html(iso, "evidence", iso_ev)


# --- claim review ----------------------------------------------------------------------


def test_a_viewer_sees_no_confirm_buttons_and_a_forged_confirm_is_rejected(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    _, version, [claim] = seed_policy(
        org_id, owner, "Access policy", [mfa_claim(ClaimState.UNCONFIRMED)]
    )
    viewer = sign_up(mfa=False)
    invite_and_join(owner, org_id, viewer, "viewer")
    page = viewer.client.get(f"/orgs/{org_id}/versions/{version}/claims")
    assert page.status_code == 200 and MFA_QUOTE in page.text
    assert "/confirm" not in page.text and "Reject" not in page.text

    forged = viewer.client.post(
        f"/orgs/{org_id}/claims/{claim}/confirm",
        data={"csrf_token": csrf(viewer.client, f"/orgs/{org_id}/passport")},
    )
    assert forged.status_code == 403
    assert "viewer may not approve" in forged.text
    with db_for(org_id) as db:
        assert db.get(Claim, claim).state is ClaimState.UNCONFIRMED  # type: ignore[union-attr]

    # The owner, by contrast, sees and uses the action.
    owner_page = owner.client.get(f"/orgs/{org_id}/versions/{version}/claims").text
    assert f"/claims/{claim}/confirm" in owner_page
    done = owner.client.post(
        f"/orgs/{org_id}/claims/{claim}/confirm",
        data={"csrf_token": csrf(owner.client, f"/orgs/{org_id}/passport")},
        follow_redirects=False,
    )
    assert done.status_code == 303
    with db_for(org_id) as db:
        stored = db.get(Claim, claim)
        assert stored is not None and stored.state is ClaimState.CONFIRMED
        assert stored.confirmed_by == owner.user_id


def test_a_form_post_without_a_csrf_token_is_rejected(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    _, _, [claim] = seed_policy(org_id, owner, "Access policy", [mfa_claim(ClaimState.UNCONFIRMED)])
    url = f"/orgs/{org_id}/claims/{claim}/confirm"
    assert owner.client.post(url).status_code == 403
    assert owner.client.post(url, data={"csrf_token": "0" * 64}).status_code == 403
    # Another session's token does not work either: tokens are bound to the session.
    other = sign_up()
    assert owner.client.post(url, data={"csrf_token": csrf(other.client)}).status_code == 403
    with db_for(org_id) as db:
        assert db.get(Claim, claim).state is ClaimState.UNCONFIRMED  # type: ignore[union-attr]


def test_a_needs_review_claim_needs_acknowledgement_and_the_refusal_is_a_409(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    _, version, [claim] = seed_policy(
        org_id,
        owner,
        "Access policy",
        [mfa_claim(ClaimState.NEEDS_REVIEW)],
        needs_review_reason="The quote covers production only.",
    )
    page = owner.client.get(f"/orgs/{org_id}/versions/{version}/claims").text
    assert "The quote covers production only." in page and 'name="acknowledge"' in page
    token = csrf(owner.client, f"/orgs/{org_id}/passport")

    refused = owner.client.post(
        f"/orgs/{org_id}/claims/{claim}/confirm", data={"csrf_token": token}
    )
    assert refused.status_code == 409
    assert "needs acknowledgement" in refused.text

    ok = owner.client.post(
        f"/orgs/{org_id}/claims/{claim}/confirm",
        data={"csrf_token": token, "acknowledge": "true"},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    again = owner.client.post(f"/orgs/{org_id}/claims/{claim}/confirm", data={"csrf_token": token})
    assert again.status_code == 409 and "already confirmed" in again.text


def test_edit_previews_the_check_then_saves_an_unconfirmed_revision(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    _, version, [claim] = seed_policy(org_id, owner, "Password policy", [mfa_claim()])
    token = csrf(owner.client, f"/orgs/{org_id}/passport")
    form = {
        "csrf_token": token,
        "predicate_id": "password_min_length",
        "param_scope": "all_accounts",
        "param_min_length": "14",
    }
    preview = owner.client.post(f"/orgs/{org_id}/claims/{claim}/preview", data=form)
    assert preview.status_code == 200
    assert "Preview:" in preview.text and "14" in preview.text
    bad = owner.client.post(
        f"/orgs/{org_id}/claims/{claim}/preview", data={**form, "param_min_length": "0"}
    )
    assert bad.status_code == 422

    saved = owner.client.post(
        f"/orgs/{org_id}/claims/{claim}/edit", data=form, follow_redirects=False
    )
    assert saved.status_code == 303
    with db_for(org_id) as db:
        revision = db.scalars(select(Claim).where(Claim.revision_of == claim)).one()
        assert revision.predicate_id == "password_min_length"
        assert revision.parameters["min_length"] == 14
        assert revision.state is ClaimState.UNCONFIRMED
    page = owner.client.get(f"/orgs/{org_id}/versions/{version}/claims").text
    assert "Unconfirmed" in page and "Confirmed</span>" not in page


# --- re-run ----------------------------------------------------------------------------


def test_rerun_shows_queued_then_running_and_the_passport_reflects_the_results(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    connect_aws(org_id, owner)
    access, _, _ = seed_policy(org_id, owner, "Access policy", [mfa_claim()])
    client = owner.client
    before = client.get(f"/orgs/{org_id}/passport").text
    assert "Idle" in before and "No run has completed yet." in before
    assert "Re-run checks now" in before

    jobs = InMemoryConnector()
    with jobs_app.replace_connector(jobs):
        pressed = client.post(
            f"/orgs/{org_id}/checks/rerun",
            data={"csrf_token": csrf(client, f"/orgs/{org_id}/passport"), "framework": "soc2"},
        )
    assert pressed.status_code == 200
    assert "Queued" in pressed.text and "Re-run checks now" not in pressed.text
    [job] = list(jobs.jobs.values())
    assert job["task_name"] == "passport.checks.run_org_checks"
    run_id = uuid.UUID(job["args"]["run_id"])

    seen_during_run: list[str] = []

    def observing(session: Session, connection: Connection) -> Connector:
        seen_during_run.append(client.get(f"/orgs/{org_id}/checks/status").text)
        return aws_fake()

    run_checks_for_org(org_id, run_id, connector_factory=observing)

    assert seen_during_run and "Running" in seen_during_run[0]
    after = client.get(f"/orgs/{org_id}/passport").text
    assert "Idle" in after and "Last completed run:" in after
    assert "Contradicted" in row_html(after, "document", access)


def test_only_owners_may_rerun_and_a_failed_run_shows_its_reason(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    approver = sign_up()
    invite_and_join(owner, org_id, approver, "approver")
    page = approver.client.get(f"/orgs/{org_id}/passport").text
    assert "Re-run checks now" not in page
    refused = approver.client.post(
        f"/orgs/{org_id}/checks/rerun", data={"csrf_token": csrf(approver.client)}
    )
    assert refused.status_code == 403

    connect_aws(org_id, owner)
    seed_policy(org_id, owner, "Access policy", [mfa_claim()])

    with db_for(org_id) as db:
        run, _ = request_run(db, org_id, trigger="on_demand")
        fail_run(db, org_id, run.id, "RuntimeError: connector exploded")
        db.commit()
    status = owner.client.get(f"/orgs/{org_id}/checks/status").text
    assert "Failed" in status and "connector exploded" in status


# --- reports ---------------------------------------------------------------------------


def test_the_report_page_renders_the_stored_weekly_report(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    connect_aws(org_id, owner)
    seed_policy(org_id, owner, "Access policy", [mfa_claim()])
    run_id = run_checks(org_id, {"AWS prod": aws_fake()})
    with db_for(org_id) as db:
        report_id = build_report(db, org_id, run_id).id
        db.commit()

    page = owner.client.get(f"/orgs/{org_id}/reports/{report_id}")
    assert page.status_code == 200
    assert "Weekly report: Acme" in page.text and "Access policy" in page.text
    assert (
        f"/orgs/{org_id}/reports/{report_id}" in owner.client.get(f"/orgs/{org_id}/passport").text
    )

    stranger = sign_up()
    other_org = create_org(stranger, "Other")
    assert stranger.client.get(f"/orgs/{org_id}/reports/{report_id}").status_code == 404
    assert stranger.client.get(f"/orgs/{other_org}/reports/{report_id}").status_code == 404
