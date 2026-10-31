"""Status service (U12): persisted statuses, change-only events, and AE8 resolution."""

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.checks.runner import execute_run, request_run
from passport.connectors.base import Capability
from passport.connectors.fakes import FakeConnector, users_mfa
from passport.connectors.models import ConnectionKind
from passport.connectors.registry import create_connection, disconnect_connection
from passport.controls.models import Framework, ScopeKind
from passport.controls.service import map_item, unmap_item
from passport.controls.settings import add_scope_entry, ensure_defaults
from passport.db.engine import get_sessionmaker
from passport.db.models import (
    Claim,
    ClaimState,
    Document,
    DocumentVersion,
    Event,
    EvidenceItem,
    ItemStatus,
)
from passport.db.rls import set_org_context
from passport.provenance.actor import Human
from passport.provenance.service import verify_chain
from passport.status.service import recompute_statuses
from tests.helpers import create_org, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")

PROD = "111111111111"
TODAY = date(2026, 10, 30)


def _session(org_id: uuid.UUID) -> Session:
    db = get_sessionmaker()()
    set_org_context(db, org_id)
    return db


def _commit(db: Session, org_id: uuid.UUID) -> None:
    db.commit()
    set_org_context(db, org_id)


def _seed(db: Session, org_id: uuid.UUID, owner: uuid.UUID) -> tuple[Document, DocumentVersion]:
    actor = Human(owner)
    ensure_defaults(db, org_id, actor)
    add_scope_entry(db, org_id, actor, ScopeKind.AWS_ACCOUNT, PROD, production=True)
    document = Document(org_id=org_id, title="Access policy")
    db.add(document)
    db.flush()
    version = DocumentVersion(
        org_id=org_id,
        document_id=document.id,
        version_number=1,
        filename="p.md",
        content_hash="0" * 64,
        storage_key="k",
        review_due_on=TODAY + timedelta(days=200),
    )
    db.add(version)
    db.flush()
    return document, version


def _claim(
    db: Session,
    org_id: uuid.UUID,
    version: DocumentVersion,
    *,
    predicate: str | None = "mfa_enforced",
    state: ClaimState = ClaimState.CONFIRMED,
    quote: str = "MFA is required on all production accounts.",
) -> Claim:
    claim = Claim(
        org_id=org_id,
        document_version_id=version.id,
        span_id=uuid.uuid4().hex,
        quote=quote,
        predicate_id=predicate,
        predicate_version=1 if predicate else None,
        parameters={"scope": "all_production_accounts"} if predicate else {},
        state=state,
    )
    db.add(claim)
    db.flush()
    return claim


def _status_events(db: Session) -> list[Event]:
    return list(
        db.scalars(select(Event).where(Event.event_type.like("item_status.%")).order_by(Event.seq))
    )


def _run(db: Session, org_id: uuid.UUID, fake: FakeConnector, at: datetime) -> None:
    run, _ = request_run(db, org_id, trigger="scheduled")
    _commit(db, org_id)
    execute_run(
        db,
        org_id,
        run.id,
        connector_factory=lambda _s, _c: fake,
        clock=lambda: at,
        today=at.date(),
    )


def test_ae8_a_contradicted_policy_returns_to_current_and_unchanged_reruns_write_nothing() -> None:
    owner = sign_up()
    org_id = create_org(owner)
    with _session(org_id) as db:
        document, version = _seed(db, org_id, owner.user_id)
        create_connection(
            db,
            org_id=org_id,
            actor=Human(owner.user_id),
            kind=ConnectionKind.AWS,
            display_name="AWS prod",
        )
        _claim(db, org_id, version)
        _commit(db, org_id)
        fake = FakeConnector(ConnectionKind.AWS, scope=(PROD,))
        fake.script(
            Capability.LIST_USERS_MFA,
            users_mfa({"alice": True, "bob": False}),
            users_mfa({"alice": True, "bob": True}),
        )
        week1 = datetime(2026, 10, 19, 3, tzinfo=UTC)
        _run(db, org_id, fake, week1)
        row = db.scalars(select(ItemStatus)).one()
        assert (row.item_kind, row.item_id, row.framework) == ("document", document.id, "soc2")
        assert (row.status, row.trusted) == ("contradicted", True)

        _run(db, org_id, fake, week1 + timedelta(days=7))
        db.refresh(row)
        assert (row.status, row.trusted) == ("current", True)
        events = _status_events(db)
        assert [e.payload["after"]["status"] for e in events] == ["contradicted", "current"]
        assert events[-1].payload["before"]["status"] == "contradicted"
        assert {(e.actor_kind, e.model_id) for e in events} == {("agent", "none")}

        # A third run with the same system state and a recompute both change nothing.
        _run(db, org_id, fake, week1 + timedelta(days=14))
        recompute_statuses(db, org_id, today=TODAY)
        _commit(db, org_id)
        assert len(_status_events(db)) == 2
        assert verify_chain(db, org_id).ok


def test_statuses_follow_mappings_disconnections_and_open_claims_only() -> None:
    owner = sign_up()
    org_id = create_org(owner)
    actor = Human(owner.user_id)
    with _session(org_id) as db:
        document, version = _seed(db, org_id, owner.user_id)
        conn = create_connection(
            db, org_id=org_id, actor=actor, kind=ConnectionKind.AWS, display_name="AWS prod"
        )
        _claim(db, org_id, version)
        _claim(db, org_id, version, state=ClaimState.REJECTED, quote="Rejected claim.")
        _claim(db, org_id, version, predicate=None, state=ClaimState.DISMISSED, quote="Gone.")
        evidence = EvidenceItem(
            org_id=org_id,
            title="Access review",
            filename="r.csv",
            content_hash="1" * 64,
            storage_key="e",
            source="upload",
            collected_at=datetime(2026, 3, 1, tzinfo=UTC),
        )
        db.add(evidence)
        _commit(db, org_id)
        _run(
            db,
            org_id,
            FakeConnector(
                ConnectionKind.AWS,
                scope=(PROD,),
                responses={Capability.LIST_USERS_MFA: users_mfa({"alice": True})},
            ),
            datetime(2026, 10, 26, 3, tzinfo=UTC),
        )
        rows = {(r.item_kind, r.framework): r for r in db.scalars(select(ItemStatus))}
        # Unmapped items use the first configured framework (SOC 2) and are labelled.
        assert set(rows) == {("document", "soc2"), ("evidence", "soc2")}
        assert rows[("document", "soc2")].status == "current"
        assert rows[("document", "soc2")].causes[-1]["kind"] == "unmapped"
        assert all("Rejected" not in c["text"] for c in rows[("document", "soc2")].causes)

        # Mapping to ISO only replaces the SOC 2 row with an ISO one.
        map_item(db, org_id, actor, "document", document.id, Framework.ISO27001, "5.15")
        recompute_statuses(db, org_id, today=TODAY)
        _commit(db, org_id)
        docs = {
            r.framework
            for r in db.scalars(select(ItemStatus).where(ItemStatus.item_kind == "document"))
        }
        assert docs == {"iso27001"}
        assert any(e.event_type == "item_status.removed" for e in _status_events(db))

        # Disconnecting the only system that serves the claim makes it not checkable.
        disconnect_connection(db, actor=actor, connection=conn)
        recompute_statuses(db, org_id, today=TODAY)
        _commit(db, org_id)
        doc = db.scalars(select(ItemStatus).where(ItemStatus.item_kind == "document")).one()
        assert doc.status == "not_checkable"
        assert "No connected system" in doc.causes[0]["text"]

        unmap_item(db, org_id, actor, "document", document.id, Framework.ISO27001, "5.15")
        recompute_statuses(db, org_id, today=TODAY)
        _commit(db, org_id)
        doc = db.scalars(select(ItemStatus).where(ItemStatus.item_kind == "document")).one()
        assert doc.framework == "soc2"


def test_an_unchecked_claim_with_an_unbound_sentence_is_unconfirmed_then_trusted_on_confirm() -> (
    None
):
    owner = sign_up()
    org_id = create_org(owner)
    with _session(org_id) as db:
        _, version = _seed(db, org_id, owner.user_id)
        claim = _claim(db, org_id, version, state=ClaimState.UNCONFIRMED)
        _claim(
            db,
            org_id,
            version,
            predicate=None,
            state=ClaimState.UNCONFIRMED,
            quote="Laptops are encrypted.",
        )
        recompute_statuses(db, org_id, today=TODAY)
        row = db.scalars(select(ItemStatus)).one()
        assert (row.status, row.trusted) == ("unconfirmed", False)
        kinds = [c["kind"] for c in row.causes]
        assert kinds.count("unconfirmed") == 1 and "not_checkable" in kinds

        claim.state = ClaimState.CONFIRMED
        recompute_statuses(db, org_id, today=TODAY)
        db.refresh(row)
        # No run yet: the confirmed claim is not checked, never vacuously current.
        assert row.status == "not_checkable"
        assert row.trusted is False
