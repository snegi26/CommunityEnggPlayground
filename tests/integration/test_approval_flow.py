"""Approval workflow and version matching (U10): confirm, edit, reject, carry over, approve."""

import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

import passport.predicates.definitions  # noqa: F401  (registers v1 predicates)
from passport.agent.drafting import draft_claims_for_version, start_run
from passport.claims.approval import approve_item
from passport.claims.matching import carry_over_confirmations
from passport.claims.service import (
    ActingMember,
    ClaimActionError,
    ForbiddenError,
    NeedsAcknowledgementError,
    checkable_claims,
    confirm_claim,
    dismiss_claim,
    edit_claim,
    reject_claim,
)
from passport.controls.models import Framework
from passport.controls.settings import ensure_defaults, get_framework_settings
from passport.db.engine import get_sessionmaker
from passport.db.models import Claim, ClaimState, DocumentVersion, Event, EvidenceItem
from passport.db.rls import set_org_context, set_user_context
from passport.documents.service import PolicyUpload, spans_to_draft, upload_evidence, upload_policy
from passport.documents.storage import LocalDirectoryStorage
from passport.predicates.registry import registry
from passport.provenance.actor import Agent, AgentNotPermittedError, Human
from passport.tenancy.models import Role
from passport.tenancy.service import require_membership
from tests.helpers import SignedInUser, create_org, invite_and_join, sign_up
from tests.unit.test_drafting_verification import StubClient, claim, end_turn, propose_turn

pytestmark = pytest.mark.usefixtures("database_urls")

Attempt = Callable[[Session, ActingMember], object]

MFA = "MFA is required for all users of production accounts."
ROOT = "The root user of every AWS account has MFA enabled."
PASSWORD = "Passwords must be at least 12 characters long."
TRAIL = "CloudTrail logging is enabled in every region for all accounts."
S3 = "S3 buckets encrypt data at rest by default."
REVIEW = "This policy is reviewed annually."
POLICY = f"""# Access

{MFA}

{ROOT}

# Passwords

{PASSWORD}

# Logging

{TRAIL}

{S3}

# Review

{REVIEW}
""".encode()

# Predicate and parameters each claimed sentence binds to, as drafting would.
BINDINGS: dict[str, tuple[str, dict[str, Any]]] = {
    MFA: ("mfa_enforced", {"scope": "all_production_accounts"}),
    ROOT: ("root_mfa_enabled", {"scope": "all_accounts"}),
    PASSWORD: ("password_min_length", {"scope": "all_accounts", "min_length": 12}),
    TRAIL: ("cloudtrail_enabled", {"scope": "all_accounts", "multi_region": True}),
    S3: ("s3_encryption_enabled", {"scope": "all_accounts"}),
}


@dataclass
class Team:
    org_id: uuid.UUID
    owner: SignedInUser
    approver: SignedInUser
    viewer: SignedInUser
    consultant: SignedInUser


@pytest.fixture
def storage(tmp_path: Path) -> LocalDirectoryStorage:
    return LocalDirectoryStorage(tmp_path / "storage")


@pytest.fixture
def team() -> Team:
    owner = sign_up()
    org_id = create_org(owner)
    approver, viewer, consultant = sign_up(), sign_up(mfa=False), sign_up()
    invite_and_join(owner, org_id, approver, "approver")
    invite_and_join(owner, org_id, viewer, "viewer")
    invite_and_join(owner, org_id, consultant, "approver", external=True)
    return Team(org_id, owner, approver, viewer, consultant)


def _session(org_id: uuid.UUID) -> Session:
    db = get_sessionmaker()()
    set_org_context(db, org_id)
    return db


def _commit(db: Session) -> None:
    """Commit and keep the session in its org: the RLS setting is transaction-local."""
    org_id = db.scalar(text("SELECT current_setting('app.org_id', true)"))
    db.commit()
    set_org_context(db, uuid.UUID(org_id))


def _member(db: Session, user: SignedInUser, org_id: uuid.UUID) -> ActingMember:
    set_user_context(db, user.user_id)
    return ActingMember.for_membership(require_membership(db, user_id=user.user_id, org_id=org_id))


def _upload(
    team: Team,
    storage: LocalDirectoryStorage,
    data: bytes = POLICY,
    document_id: uuid.UUID | None = None,
) -> PolicyUpload:
    """Upload a version and, as the upload flow must, carry confirmations over."""
    actor = Human(team.owner.user_id)
    with _session(team.org_id) as db:
        upload = upload_policy(
            db,
            org_id=team.org_id,
            actor=actor,
            filename="policy.md",
            data=data,
            document_id=document_id,
            storage=storage,
        )
        carry_over_confirmations(db, version=upload.version, actor=actor)
        _commit(db)
        return upload


def _drafted(
    db: Session,
    upload: PolicyUpload,
    sentence: str,
    *,
    state: ClaimState = ClaimState.UNCONFIRMED,
    reason: str | None = None,
) -> Claim:
    """Store a claim exactly as drafting would (no model needed here)."""
    span = next(s for s in upload.spans if s.text == sentence)
    predicate_id, params = BINDINGS[sentence]
    description = registry.describe(predicate_id, 1, params)
    row = Claim(
        org_id=upload.version.org_id,
        document_version_id=upload.version.id,
        span_id=span.span_id,
        quote=sentence,
        predicate_id=predicate_id,
        predicate_version=1,
        parameters=params,
        check_description=description,
        state=state,
        needs_review_reason=reason,
    )
    db.add(row)
    db.flush()
    return row


def _events(org_id: uuid.UUID, event_type: str) -> list[Event]:
    with _session(org_id) as db:
        return list(
            db.scalars(select(Event).where(Event.event_type == event_type).order_by(Event.seq))
        )


def _claim(org_id: uuid.UUID, claim_id: uuid.UUID) -> Claim:
    with _session(org_id) as db:
        found = db.get(Claim, claim_id)
        assert found is not None
        return found


@pytest.fixture
def confirmed_policy(team: Team, storage: LocalDirectoryStorage) -> Iterator[PolicyUpload]:
    """Version 1 with five claims, all confirmed by the client's approver."""
    first = _upload(team, storage)
    with _session(team.org_id) as db:
        ids = [_drafted(db, first, sentence).id for sentence in BINDINGS]
        acting = _member(db, team.approver, team.org_id)
        for claim_id in ids:
            confirm_claim(db, acting, claim_id)
        _commit(db)
    yield first


# --- Covers AE9 and R20 ----------------------------------------------------------


def test_new_version_keeps_four_confirmations_and_drafts_only_the_changed_span(
    team: Team, storage: LocalDirectoryStorage, confirmed_policy: PolicyUpload
) -> None:
    edited = POLICY.replace(b"at least 12 characters", b"at least 14 characters")
    second = _upload(team, storage, edited, confirmed_policy.document.id)

    # Carry-over ran at upload, before and without any model call.
    with _session(team.org_id) as db:
        carried = list(
            db.scalars(select(Claim).where(Claim.document_version_id == second.version.id))
        )
        to_draft = spans_to_draft(db, second.version.id)
    assert sorted(c.quote for c in carried) == sorted([MFA, ROOT, TRAIL, S3])
    assert all(c.state is ClaimState.CONFIRMED for c in carried)
    assert all(c.confirmed_by == team.approver.user_id for c in carried)
    assert all(c.confirmed_at is not None for c in carried)
    assert [s.text for s in to_draft] == [PASSWORD.replace("12", "14")]

    links = _events(team.org_id, "claim.carried_over")
    assert len(links) == 4
    for event in links:
        new_claim = _claim(team.org_id, uuid.UUID(event.payload["to_claim_id"]))
        assert new_claim.revision_of == uuid.UUID(event.payload["from_claim_id"])
        assert event.payload["to_document_version_id"] == str(second.version.id)
        assert event.payload["state"] == "confirmed"

    # Drafting then sees only the changed span; its claim (12 -> 14) arrives unconfirmed.
    changed = to_draft[0]
    client = StubClient(
        [
            propose_turn(
                claim(
                    changed.span_id,
                    changed.text,
                    "password_min_length",
                    {"scope": "all_accounts", "min_length": 14},
                )
            ),
            end_turn(),
        ]
    )
    with _session(team.org_id) as db:
        run = start_run(db, org_id=team.org_id, version_id=second.version.id, model_id="m")
        result = draft_claims_for_version(db, run=run, client=client)
        _commit(db)
    sent = str(client.draft_requests[0].messages[0]["content"])
    assert changed.span_id in sent
    assert all(c.span_id not in sent for c in carried)
    [drafted] = result.claims
    assert drafted.state is ClaimState.UNCONFIRMED
    assert drafted.parameters["min_length"] == 14
    assert drafted.confirmed_by is None

    with _session(team.org_id) as db:
        checks = checkable_claims(db, team.org_id)
    assert {c.id for c in checks} == {c.id for c in carried} | {drafted.id}
    states = sorted(c.state.value for c in checks)
    assert states == ["confirmed"] * 4 + ["unconfirmed"]


def test_reworded_sentence_binding_the_same_predicate_arrives_unconfirmed(
    team: Team, storage: LocalDirectoryStorage, confirmed_policy: PolicyUpload
) -> None:
    reworded = MFA.replace("for all users of", "for every user of")
    second = _upload(
        team, storage, POLICY.replace(MFA.encode(), reworded.encode()), confirmed_policy.document.id
    )
    with _session(team.org_id) as db:
        [changed] = spans_to_draft(db, second.version.id)
    assert changed.text == reworded

    client = StubClient([propose_turn(claim(changed.span_id, reworded)), end_turn()])
    with _session(team.org_id) as db:
        run = start_run(db, org_id=team.org_id, version_id=second.version.id, model_id="m")
        [drafted] = draft_claims_for_version(db, run=run, client=client).claims
        _commit(db)
        old_mfa = db.scalars(
            select(Claim).where(
                Claim.document_version_id == confirmed_policy.version.id, Claim.quote == MFA
            )
        ).one()
        checks = {c.id: c for c in checkable_claims(db, team.org_id)}

    # Same predicate and parameters as the confirmed claim, but it came from a changed span.
    assert (drafted.predicate_id, drafted.parameters) == (old_mfa.predicate_id, old_mfa.parameters)
    assert old_mfa.state is ClaimState.CONFIRMED
    assert drafted.state is ClaimState.UNCONFIRMED
    assert drafted.id in checks and old_mfa.id not in checks


def test_carry_over_is_idempotent(
    team: Team, storage: LocalDirectoryStorage, confirmed_policy: PolicyUpload
) -> None:
    second = _upload(team, storage, POLICY, confirmed_policy.document.id)
    with _session(team.org_id) as db:
        version = db.get(DocumentVersion, second.version.id)
        assert version is not None
        again = carry_over_confirmations(db, version=version, actor=Human(team.owner.user_id))
        _commit(db)
        count = db.scalar(
            select(func.count())
            .select_from(Claim)
            .where(Claim.document_version_id == second.version.id)
        )
    assert again == []
    assert count == 5


# --- Confirm, edit, reject, dismiss (R7, R21, KTD5, KTD10) -----------------------


def test_consultant_confirmation_is_recorded_on_behalf_of_the_org(
    team: Team, storage: LocalDirectoryStorage
) -> None:
    first = _upload(team, storage)
    with _session(team.org_id) as db:
        ours, theirs = _drafted(db, first, MFA), _drafted(db, first, ROOT)
        confirm_claim(db, _member(db, team.consultant, team.org_id), ours.id)
        confirm_claim(db, _member(db, team.approver, team.org_id), theirs.id)
        _commit(db)
        ours_id, theirs_id = ours.id, theirs.id

    by_consultant, by_client = _claim(team.org_id, ours_id), _claim(team.org_id, theirs_id)
    assert by_consultant.confirmed_by == team.consultant.user_id
    assert by_consultant.confirmed_on_behalf is True
    assert by_client.confirmed_by == team.approver.user_id
    assert by_client.confirmed_on_behalf is False

    events = {e.subject_id: e for e in _events(team.org_id, "claim.confirmed")}
    consultant_event, client_event = events[str(ours_id)], events[str(theirs_id)]
    assert consultant_event.actor_user_id == team.consultant.user_id
    assert consultant_event.on_behalf_of_org is True
    assert consultant_event.payload["role"] == "approver"
    assert consultant_event.payload["on_behalf_of_org"] is True
    assert consultant_event.payload["predicate_version"] == 1
    assert consultant_event.payload["check_description"] == by_consultant.check_description
    assert client_event.on_behalf_of_org is False


def test_owner_may_confirm_and_the_event_names_the_role(
    team: Team, storage: LocalDirectoryStorage
) -> None:
    first = _upload(team, storage)
    with _session(team.org_id) as db:
        row = _drafted(db, first, S3)
        confirm_claim(db, _member(db, team.owner, team.org_id), row.id)
        _commit(db)
    [event] = _events(team.org_id, "claim.confirmed")
    assert event.actor_user_id == team.owner.user_id
    assert event.payload["role"] == "owner"
    assert event.payload["check_description"] == registry.describe(
        "s3_encryption_enabled", 1, BINDINGS[S3][1]
    )


def test_editing_parameters_creates_a_new_unconfirmed_revision(
    team: Team, storage: LocalDirectoryStorage, confirmed_policy: PolicyUpload
) -> None:
    with _session(team.org_id) as db:
        old = db.scalars(select(Claim).where(Claim.quote == PASSWORD)).one()
        acting = _member(db, team.approver, team.org_id)
        new = edit_claim(
            db,
            acting,
            old.id,
            predicate_id="password_min_length",
            parameters={"scope": "all_production_accounts", "min_length": 16},
        )
        _commit(db)
        old_id, new_id = old.id, new.id
        checks = {c.id for c in checkable_claims(db, team.org_id)}

    old_row, new_row = _claim(team.org_id, old_id), _claim(team.org_id, new_id)
    assert new_row.revision_of == old_id
    assert new_row.state is ClaimState.UNCONFIRMED
    assert new_row.confirmed_by is None and new_row.confirmed_at is None
    assert new_row.parameters == {"scope": "all_production_accounts", "min_length": 16}
    assert new_row.check_description is not None
    assert "at least 16 characters" in new_row.check_description
    assert (new_row.span_id, new_row.quote) == (old_row.span_id, old_row.quote)
    # The old revision keeps its own history but no longer counts.
    assert old_row.state is ClaimState.CONFIRMED
    assert new_id in checks and old_id not in checks

    [event] = _events(team.org_id, "claim.edited")
    assert event.subject_id == str(new_id)
    assert event.payload["revision_of"] == str(old_id)
    assert event.payload["role"] == "approver"
    assert event.payload["check_description"] == new_row.check_description
    assert event.payload["before"]["parameters"]["min_length"] == 12

    # A superseded revision cannot be acted on again.
    with _session(team.org_id) as db, pytest.raises(ClaimActionError):
        confirm_claim(db, _member(db, team.approver, team.org_id), old_id)

    # Confirming the new revision is a fresh, separate confirmation.
    with _session(team.org_id) as db:
        confirm_claim(db, _member(db, team.consultant, team.org_id), new_id)
        _commit(db)
    assert _claim(team.org_id, new_id).confirmed_by == team.consultant.user_id


def test_viewer_cannot_confirm_edit_reject_or_approve_and_nothing_is_written(
    team: Team, storage: LocalDirectoryStorage
) -> None:
    first = _upload(team, storage)
    with _session(team.org_id) as db:
        row = _drafted(db, first, MFA)
        _commit(db)
        row_id = row.id
        before = db.scalar(select(func.count()).select_from(Event))

    attempts: list[Attempt] = [
        lambda db, m: confirm_claim(db, m, row_id),
        lambda db, m: reject_claim(db, m, row_id),
        lambda db, m: dismiss_claim(db, m, row_id),
        lambda db, m: edit_claim(
            db, m, row_id, predicate_id="mfa_enforced", parameters={"scope": "all_users"}
        ),
        lambda db, m: approve_item(db, m, item_kind="document_version", item_id=first.version.id),
    ]
    for attempt in attempts:
        with _session(team.org_id) as db:
            viewer = _member(db, team.viewer, team.org_id)
            assert viewer.role is Role.VIEWER
            with pytest.raises(ForbiddenError):
                attempt(db, viewer)
            _commit(db)

    with _session(team.org_id) as db:
        assert db.scalar(select(func.count()).select_from(Event)) == before
        assert db.scalar(select(func.count()).select_from(Claim)) == 1
    assert _claim(team.org_id, row_id).state is ClaimState.UNCONFIRMED


def test_the_agent_cannot_confirm_even_with_an_approving_role(
    team: Team, storage: LocalDirectoryStorage
) -> None:
    first = _upload(team, storage)
    agent = Agent(run_id=uuid.uuid4(), model_id="m", prompt_version="p")
    with _session(team.org_id) as db:
        row = _drafted(db, first, MFA)
        with pytest.raises(AgentNotPermittedError):
            confirm_claim(db, ActingMember(team.org_id, agent, Role.OWNER), row.id)


def test_needs_review_claim_requires_acknowledging_the_reason(
    team: Team, storage: LocalDirectoryStorage
) -> None:
    first = _upload(team, storage)
    reason = "The quote names production accounts only, not every user."
    with _session(team.org_id) as db:
        row = _drafted(db, first, MFA, state=ClaimState.NEEDS_REVIEW, reason=reason)
        _commit(db)
        row_id = row.id

    with _session(team.org_id) as db:
        with pytest.raises(NeedsAcknowledgementError) as refused:
            confirm_claim(db, _member(db, team.approver, team.org_id), row_id)
        assert reason in str(refused.value)
    assert _claim(team.org_id, row_id).state is ClaimState.NEEDS_REVIEW
    assert _events(team.org_id, "claim.confirmed") == []

    with _session(team.org_id) as db:
        confirm_claim(db, _member(db, team.approver, team.org_id), row_id, acknowledge_reason=True)
        _commit(db)
    assert _claim(team.org_id, row_id).state is ClaimState.CONFIRMED
    [event] = _events(team.org_id, "claim.confirmed")
    assert event.payload["acknowledged_reason"] == reason


def test_rejecting_removes_the_claim_from_checks_but_keeps_it_in_the_log(
    team: Team, storage: LocalDirectoryStorage
) -> None:
    first = _upload(team, storage)
    with _session(team.org_id) as db:
        kept, rejected = _drafted(db, first, MFA), _drafted(db, first, ROOT)
        _commit(db)
        assert {c.id for c in checkable_claims(db, team.org_id)} == {kept.id, rejected.id}
        reject_claim(
            db, _member(db, team.approver, team.org_id), rejected.id, reason="Not our policy"
        )
        _commit(db)
        checks = {c.id for c in checkable_claims(db, team.org_id)}
        kept_id, rejected_id = kept.id, rejected.id

    assert checks == {kept_id}
    assert _claim(team.org_id, rejected_id).state is ClaimState.REJECTED
    [event] = _events(team.org_id, "claim.rejected")
    assert event.subject_id == str(rejected_id)
    assert event.actor_user_id == team.approver.user_id
    assert event.payload["reason"] == "Not our policy"
    assert event.payload["previous_state"] == "unconfirmed"
    assert event.payload["role"] == "approver"
    assert event.payload["check_description"] is not None


def test_not_checkable_claims_can_only_be_dismissed(
    team: Team, storage: LocalDirectoryStorage
) -> None:
    first = _upload(team, storage)
    with _session(team.org_id) as db:
        span = next(s for s in first.spans if s.text == REVIEW)
        row = Claim(
            org_id=team.org_id,
            document_version_id=first.version.id,
            span_id=span.span_id,
            quote=REVIEW,
            predicate_id=None,
            state=ClaimState.UNCONFIRMED,
        )
        db.add(row)
        _commit(db)
        row_id = row.id
        assert checkable_claims(db, team.org_id) == []

    refused: tuple[Attempt, ...] = (
        lambda db, m: confirm_claim(db, m, row_id),
        lambda db, m: reject_claim(db, m, row_id),
        lambda db, m: edit_claim(
            db, m, row_id, predicate_id="mfa_enforced", parameters={"scope": "all_users"}
        ),
    )
    for attempt in refused:
        with _session(team.org_id) as db, pytest.raises(ClaimActionError):
            attempt(db, _member(db, team.approver, team.org_id))

    with _session(team.org_id) as db:
        dismiss_claim(db, _member(db, team.consultant, team.org_id), row_id)
        _commit(db)
    assert _claim(team.org_id, row_id).state is ClaimState.DISMISSED
    [event] = _events(team.org_id, "claim.dismissed")
    assert event.actor_user_id == team.consultant.user_id
    assert event.on_behalf_of_org is True


# --- Document approval (R1, R9, R19, R21) ----------------------------------------


def test_approving_an_expired_policy_sets_approver_and_next_review_one_cadence_ahead(
    team: Team, storage: LocalDirectoryStorage
) -> None:
    actor = Human(team.owner.user_id)
    with _session(team.org_id) as db:
        upload = upload_policy(
            db,
            org_id=team.org_id,
            actor=actor,
            filename="policy.md",
            data=POLICY,
            review_due_on=date(2025, 1, 1),
            storage=storage,
        )
        ensure_defaults(db, team.org_id, actor)
        cadence = get_framework_settings(db, Framework.SOC2).policy_review_days
        _commit(db)
        version_id = upload.version.id

    today = date(2026, 10, 30)
    with _session(team.org_id) as db:
        approval = approve_item(
            db,
            _member(db, team.consultant, team.org_id),
            item_kind="document_version",
            item_id=version_id,
            today=today,
        )
        _commit(db)

    assert approval.review_due_on == today + timedelta(days=cadence) == date(2027, 10, 30)
    with _session(team.org_id) as db:
        version = db.get(DocumentVersion, version_id)
        assert version is not None
        assert version.last_approved_by == team.consultant.user_id
        assert version.approved_on_behalf is True
        assert version.approved_at is not None
        assert version.review_due_on == date(2027, 10, 30) and version.review_due_on > today
    [event] = _events(team.org_id, "document_version.approved")
    assert event.actor_user_id == team.consultant.user_id
    assert event.on_behalf_of_org is True
    assert event.payload["role"] == "approver"
    assert event.payload["framework"] == "soc2"
    assert event.payload["cadence_days"] == 365
    assert event.payload["previous_review_due_on"] == "2025-01-01"
    assert event.payload["review_due_on"] == "2027-10-30"


def test_approving_evidence_uses_the_access_review_cadence(
    team: Team, storage: LocalDirectoryStorage
) -> None:
    actor = Human(team.owner.user_id)
    with _session(team.org_id) as db:
        item = upload_evidence(
            db,
            org_id=team.org_id,
            actor=actor,
            title="Q3 access review",
            filename="review.csv",
            data=b"user,decision\n",
            source="Google Workspace export",
            collected_at=datetime(2026, 9, 30, tzinfo=UTC),
            storage=storage,
        )
        _commit(db)
        item_id = item.id

    today = date(2026, 10, 30)
    with _session(team.org_id) as db:
        approval = approve_item(
            db,
            _member(db, team.approver, team.org_id),
            item_kind="evidence",
            item_id=item_id,
            framework=Framework.ISO27001,
            today=today,
        )
        _commit(db)
        stored = db.get(EvidenceItem, item_id)
        assert stored is not None
        assert stored.last_approved_by == team.approver.user_id
        assert stored.approved_on_behalf is False
    # No settings stored yet: R19's default quarterly access review applies.
    assert approval.cadence_days == 90
    assert approval.review_due_on == today + timedelta(days=90)
    [event] = _events(team.org_id, "evidence_item.approved")
    assert event.payload["framework"] == "iso27001"
