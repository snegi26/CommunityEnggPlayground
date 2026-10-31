"""Auditor export (U15): a ZIP of snapshot, CSV summaries, and the audit-window event log."""

import csv
import io
import json
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

import passport.predicates.definitions  # noqa: F401  (registers v1 predicates)
from passport.app import create_app
from passport.checks.runner import execute_run, request_run
from passport.claims.approval import approve_item
from passport.claims.service import ActingMember, confirm_claim, preview_check
from passport.connectors.base import Capability
from passport.connectors.fakes import FakeConnector, users_mfa
from passport.connectors.models import ConnectionKind
from passport.connectors.registry import create_connection
from passport.controls.models import AuditType, Framework, ScopeKind
from passport.controls.service import map_item
from passport.controls.settings import add_scope_entry, ensure_defaults, update_framework_settings
from passport.db.engine import get_sessionmaker
from passport.db.models import Claim, ClaimState, Event, ItemStatus, Observation
from passport.db.rls import set_org_context, set_user_context
from passport.documents.service import upload_evidence, upload_policy
from passport.documents.storage import LocalDirectoryStorage
from passport.export.builder import generate_export
from passport.export.routes import router as export_router
from passport.provenance.actor import Agent, Human
from passport.provenance.service import GENESIS_HASH, append_event
from passport.settings import libpq_url
from passport.tenancy.service import require_membership
from tests.helpers import SignedInUser, create_org, invite_and_join, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")

PROD = "111111111111"
RUN_AT = datetime(2026, 10, 26, 3, tzinfo=UTC)
DRAFTER = "claude-test-model"
DRAFT_PROMPT = "draft_claims_v1"


@dataclass
class Seeded:
    org_id: uuid.UUID
    name: str
    owner: SignedInUser
    document_id: uuid.UUID
    evidence_id: uuid.UUID
    confirmed_claim: uuid.UUID
    unconfirmed_claim: uuid.UUID
    unbound_claim: uuid.UUID
    secrets: set[str] = field(default_factory=set)


@pytest.fixture
def storage(tmp_path: Path) -> LocalDirectoryStorage:
    return LocalDirectoryStorage(tmp_path / "storage")


def _session(org_id: uuid.UUID) -> Session:
    db = get_sessionmaker()()
    set_org_context(db, org_id)
    return db


def _commit(db: Session, org_id: uuid.UUID) -> None:
    db.commit()
    set_org_context(db, org_id)


def _draft(
    db: Session,
    org_id: uuid.UUID,
    version_id: uuid.UUID,
    quote: str,
    predicate: str | None,
    params: dict[str, Any],
) -> Claim:
    """Store a claim as the drafting agent does: unconfirmed, with a ``claim.drafted`` event."""
    preview = preview_check(predicate, params) if predicate else None
    claim = Claim(
        org_id=org_id,
        document_version_id=version_id,
        span_id=uuid.uuid4().hex,
        quote=quote,
        predicate_id=predicate,
        predicate_version=preview.predicate_version if preview else None,
        parameters=preview.parameters if preview else {},
        check_description=preview.check_description if preview else None,
        state=ClaimState.UNCONFIRMED,
    )
    db.add(claim)
    db.flush()
    append_event(
        db,
        org_id=org_id,
        actor=Agent(run_id=uuid.uuid4(), model_id=DRAFTER, prompt_version=DRAFT_PROMPT),
        event_type="claim.drafted",
        subject_kind="claim",
        subject_id=claim.id,
        payload={"quote": quote, "predicate_id": predicate},
    )
    return claim


def _seed(
    storage: LocalDirectoryStorage,
    owner: SignedInUser,
    consultant: SignedInUser,
    name: str,
    mfa_users: dict[str, bool],
    *,
    window: tuple[date, date] | None = None,
) -> Seeded:
    org_id = create_org(owner, name)
    invite_and_join(owner, org_id, consultant, "approver", external=True)
    actor = Human(owner.user_id)
    with _session(org_id) as db:
        ensure_defaults(db, org_id, actor)
        if window:
            update_framework_settings(
                db,
                org_id,
                actor,
                Framework.SOC2,
                audit_type=AuditType.SOC2_TYPE2,
                window_start=window[0],
                window_end=window[1],
            )
        add_scope_entry(db, org_id, actor, ScopeKind.AWS_ACCOUNT, PROD, production=True)
        policy = (
            f"# {name} access policy\n\n"
            "MFA is required on all production accounts.\n\n"
            "Root accounts use hardware keys.\n\n"
            "Laptops are encrypted.\n"
        ).encode()
        upload = upload_policy(
            db,
            org_id=org_id,
            actor=actor,
            filename="access.md",
            data=policy,
            title=f"{name} Access policy",
            storage=storage,
        )
        document_id, version_id = upload.document.id, upload.version.id
        map_item(db, org_id, actor, "document", document_id, Framework.SOC2, "CC6.1")
        confirmed = _draft(
            db,
            org_id,
            version_id,
            f"{name}: MFA is required on all production accounts.",
            "mfa_enforced",
            {"scope": "all_production_accounts"},
        )
        unconfirmed = _draft(
            db,
            org_id,
            version_id,
            f"{name}: Root accounts use hardware keys.",
            "root_mfa_enabled",
            {"scope": "all_accounts"},
        )
        unbound = _draft(db, org_id, version_id, f"{name}: Laptops are encrypted.", None, {})
        evidence = upload_evidence(
            db,
            org_id=org_id,
            actor=actor,
            title=f"{name} access review",
            filename="review.csv",
            data=f"{name},reviewed\n".encode(),
            source="upload",
            collected_at=datetime(2026, 9, 1, tzinfo=UTC),
            storage=storage,
        )
        create_connection(
            db, org_id=org_id, actor=actor, kind=ConnectionKind.AWS, display_name=f"{name} AWS"
        )
        _commit(db, org_id)

        set_user_context(db, consultant.user_id)
        acting = ActingMember.for_membership(
            require_membership(db, user_id=consultant.user_id, org_id=org_id)
        )
        confirm_claim(db, acting, confirmed.id)
        approve_item(db, acting, item_kind="document_version", item_id=version_id)
        approve_item(db, acting, item_kind="evidence", item_id=evidence.id)
        _commit(db, org_id)

        fake = FakeConnector(ConnectionKind.AWS, scope=(PROD,), clock=lambda: RUN_AT)
        fake.script(Capability.LIST_USERS_MFA, users_mfa(mfa_users))
        # The org name makes each org's response, and so its hash, unique to that org.
        fake.script(Capability.GET_ROOT_MFA, [{"account": PROD, "root_mfa": True, "org": name}])
        run, _ = request_run(db, org_id, trigger="scheduled")
        _commit(db, org_id)
        execute_run(
            db,
            org_id,
            run.id,
            connector_factory=lambda _s, _c: fake,
            clock=lambda: RUN_AT,
            today=RUN_AT.date(),
        )
        _commit(db, org_id)

        secrets = {str(org_id), name, owner.email, str(owner.user_id)}
        for e in db.scalars(select(Event).where(Event.org_id == org_id)):
            # Payload hashes are omitted: identical payloads (e.g. {"trigger": "scheduled"})
            # hash alike in every org, so they identify content, not the org.
            secrets |= {e.hash, e.subject_id}
        for o in db.scalars(select(Observation).where(Observation.org_id == org_id)):
            secrets |= {str(o.id), o.response_sha256}
        for c in db.scalars(select(Claim).where(Claim.org_id == org_id)):
            secrets |= {str(c.id), c.quote}
        secrets |= {
            upload.version.content_hash,
            evidence.content_hash,
            str(version_id),
            str(evidence.id),
            upload.document.title,
            evidence.title,
        }
        secrets.discard(GENESIS_HASH)
    return Seeded(
        org_id=org_id,
        name=name,
        owner=owner,
        document_id=document_id,
        evidence_id=evidence.id,
        confirmed_claim=confirmed.id,
        unconfirmed_claim=unconfirmed.id,
        unbound_claim=unbound.id,
        secrets=secrets,
    )


def _export_bytes(org: Seeded, framework: Framework = Framework.SOC2) -> bytes:
    with _session(org.org_id) as db:
        result = generate_export(db, org.org_id, Human(org.owner.user_id), framework)
        _commit(db, org.org_id)
    return result.data


def _open(data: bytes) -> tuple[dict[str, Any], list[dict[str, str]], list[dict[str, str]], Any]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert sorted(archive.namelist()) == [
            "claims.csv",
            "events.json",
            "items.csv",
            "snapshot.json",
        ]
        snapshot = json.loads(archive.read("snapshot.json"))
        items = list(csv.DictReader(io.StringIO(archive.read("items.csv").decode())))
        claims = list(csv.DictReader(io.StringIO(archive.read("claims.csv").decode())))
        events = json.loads(archive.read("events.json"))
    return snapshot, items, claims, events


def _export(org: Seeded) -> tuple[dict[str, Any], list[dict[str, str]], list[dict[str, str]], Any]:
    return _open(_export_bytes(org))


def _two_orgs(storage: LocalDirectoryStorage) -> tuple[Seeded, Seeded, SignedInUser]:
    consultant = sign_up()
    x = _seed(storage, sign_up(), consultant, "Xylo Corp", {"alice": True, "bob": True})
    y = _seed(storage, sign_up(), consultant, "Yarrow Ltd", {"carol": True, "dave": False})
    return x, y, consultant


def test_ae5_export_of_org_x_contains_nothing_from_org_y(
    storage: LocalDirectoryStorage,
) -> None:
    x, y, _ = _two_orgs(storage)
    data = _export_bytes(x)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        contents = b"".join(archive.read(n) for n in archive.namelist())
    assert y.secrets, "Y must have seeded identifiers"
    leaked = sorted(s for s in y.secrets if s.encode() in contents)
    assert leaked == []
    # The scan is meaningful: X's own identifiers are present.
    assert str(x.org_id).encode() in contents and x.name.encode() in contents
    assert str(x.confirmed_claim).encode() in contents


def test_snapshot_matches_passport_statuses_and_files_parse(
    storage: LocalDirectoryStorage,
) -> None:
    x, _, consultant = _two_orgs(storage)
    snapshot, items, claims, events = _export(x)
    assert snapshot["org"]["name"] == "Xylo Corp"
    assert snapshot["framework"] == "soc2"
    assert snapshot["generated_at"]
    assert snapshot["audit"]["audit_type"] == "soc2_type2"
    assert snapshot["audit"]["events_scope"] == "all"
    assert snapshot["chain_verification"]["ok"] is True
    assert snapshot["summary"]["chain_verified"] is True

    with _session(x.org_id) as db:
        stored = {
            (r.item_kind, str(r.item_id)): r
            for r in db.scalars(select(ItemStatus).where(ItemStatus.framework == "soc2"))
        }
    by_key = {(i["item_kind"], i["item_id"]): i for i in snapshot["items"]}
    assert set(by_key) == set(stored)
    for key, row in stored.items():
        assert by_key[key]["status"] == row.status
        assert by_key[key]["trusted"] == row.trusted
        assert by_key[key]["causes"] == row.causes
    assert {(i["item_kind"], i["item_id"], i["status"]) for i in items} == {
        (k[0], k[1], r.status) for k, r in stored.items()
    }

    document = by_key[("document", str(x.document_id))]
    assert document["unmapped"] is False and document["controls"] == ["CC6.1"]
    assert document["last_approved_by"]["user_id"] == str(consultant.user_id)
    assert document["last_approved_by"]["name"] == consultant.email
    assert document["last_approved_by"]["on_behalf_of_org"] is True
    assert document["approved_at"] and document["review_due_on"]
    # The evidence item is unmapped; the status engine assigns it to SOC 2 and labels it.
    evidence = by_key[("evidence", str(x.evidence_id))]
    assert evidence["unmapped"] is True
    assert next(i for i in items if i["item_kind"] == "evidence")["unmapped"] == "true"

    claim_ids = {c["claim_id"] for c in document["claims"]}
    assert claim_ids == {str(x.confirmed_claim), str(x.unconfirmed_claim), str(x.unbound_claim)}
    assert {c["claim_id"] for c in claims} == claim_ids
    confirmed = next(c for c in document["claims"] if c["claim_id"] == str(x.confirmed_claim))
    assert confirmed["state"] == "confirmed" and confirmed["label"] == "confirmed"
    assert confirmed["confirmed_by"] == {
        "user_id": str(consultant.user_id),
        "name": consultant.email,
        "on_behalf_of_org": True,
    }
    assert confirmed["predicate_id"] == "mfa_enforced"
    assert "MFA" in confirmed["check_description"]
    assert confirmed["latest_check"]["outcome"] == "current"

    assert isinstance(events, list) and events
    assert [e["seq"] for e in events] == sorted(e["seq"] for e in events)


def test_unconfirmed_claims_are_present_and_labelled(storage: LocalDirectoryStorage) -> None:
    x, _, _ = _two_orgs(storage)
    snapshot, _, claims, _ = _export(x)
    document = next(i for i in snapshot["items"] if i["item_kind"] == "document")
    labels = {c["claim_id"]: (c["state"], c["label"]) for c in document["claims"]}
    assert labels[str(x.unconfirmed_claim)] == ("unconfirmed", "unconfirmed")
    assert labels[str(x.unbound_claim)] == ("unconfirmed", "unconfirmed")
    row = next(c for c in claims if c["claim_id"] == str(x.unconfirmed_claim))
    assert (row["state"], row["label"], row["confirmed_by_id"]) == (
        "unconfirmed",
        "unconfirmed",
        "",
    )
    assert snapshot["summary"]["unconfirmed_claims"] == 2
    # One unconfirmed claim keeps the whole item untrusted.
    assert document["trusted"] is False


def test_every_status_change_names_a_person_or_the_agent_with_model_and_prompt(
    storage: LocalDirectoryStorage,
) -> None:
    x, _, consultant = _two_orgs(storage)
    _, _, _, events = _export(x)
    changes = [e for e in events if e["event_type"].startswith("item_status.")]
    confirmations = [e for e in events if e["event_type"] == "claim.confirmed"]
    drafted = [e for e in events if e["event_type"] == "claim.drafted"]
    assert changes and confirmations and drafted
    for event in events:
        assert event["actor_kind"] in ("human", "agent")
        if event["actor_kind"] == "agent":
            assert event["model_id"] and event["prompt_version"] and event["agent_run_id"]
            assert event["actor_user_id"] is None
        else:
            assert event["actor_user_id"] and event["actor_name"]
            assert event["model_id"] is None
        for key in ("hash", "prev_hash", "payload", "subject_kind", "subject_id"):
            assert key in event
    assert {(e["model_id"], e["prompt_version"]) for e in drafted} == {(DRAFTER, DRAFT_PROMPT)}
    assert all(e["actor_kind"] == "agent" for e in changes)
    assert all(
        e["actor_user_id"] == str(consultant.user_id) and e["on_behalf_of_org"] is True
        for e in confirmations
    )


def test_observations_carry_ipe_fields(storage: LocalDirectoryStorage) -> None:
    x, _, _ = _two_orgs(storage)
    snapshot, _, claims, _ = _export(x)
    document = next(i for i in snapshot["items"] if i["item_kind"] == "document")
    confirmed = next(c for c in document["claims"] if c["claim_id"] == str(x.confirmed_claim))
    (observation,) = confirmed["latest_check"]["observations"]
    assert observation["endpoint"] == "fake://aws/list_users_mfa"
    assert observation["row_count"] == 2
    assert observation["complete"] is True
    assert len(observation["response_sha256"]) == 64
    assert observation["collector_version"] == "fake-1"
    assert observation["scope"] == [PROD]
    assert observation["collected_at"].startswith("2026-10-26")
    for key in ("parameters", "total_count", "observation_id"):
        assert key in observation
    row = next(c for c in claims if c["claim_id"] == str(x.confirmed_claim))
    assert row["observation_endpoints"] == "fake://aws/list_users_mfa"
    assert row["observation_row_counts"] == "2"
    assert row["observation_complete"] == "true"
    assert row["observation_sha256s"] == observation["response_sha256"]
    # The unbound claim has never been checked.
    unbound = next(c for c in document["claims"] if c["claim_id"] == str(x.unbound_claim))
    assert unbound["latest_check"] is None


def test_tampered_chain_reports_verification_failure_in_summary(
    storage: LocalDirectoryStorage, database_urls: dict[str, str]
) -> None:
    x, _, _ = _two_orgs(storage)
    with psycopg.connect(libpq_url(database_urls["owner"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", (str(x.org_id),))
        conn.execute(
            "UPDATE events SET payload = '{\"tampered\": true}' WHERE org_id = %s AND seq = 3",
            (x.org_id,),
        )
    snapshot, _, _, _ = _export(x)
    assert snapshot["chain_verification"] == {
        "ok": False,
        "events_checked": 3,
        "first_bad_seq": 3,
    }
    assert snapshot["summary"]["chain_verified"] is False


def test_events_are_limited_to_the_audit_window(storage: LocalDirectoryStorage) -> None:
    consultant = sign_up()
    today = datetime.now(UTC).date()
    # A window that ended before anything was seeded excludes every event.
    x = _seed(
        storage,
        sign_up(),
        consultant,
        "Window Co",
        {"alice": True},
        window=(date(2025, 1, 1), date(2025, 12, 31)),
    )
    snapshot, _, _, events = _export(x)
    assert snapshot["audit"]["events_scope"] == "window"
    assert snapshot["audit"]["window_start"] == "2025-01-01"
    assert events == []
    with _session(x.org_id) as db:
        update_framework_settings(
            db,
            x.org_id,
            Human(x.owner.user_id),
            Framework.SOC2,
            audit_type=AuditType.SOC2_TYPE2,
            window_start=date(2025, 1, 1),
            window_end=today,
        )
        _commit(db, x.org_id)
    _, _, _, events = _export(x)
    assert events and all(e["created_at"][:10] <= today.isoformat() for e in events)
    # The first export's own event is inside the new window.
    assert any(e["event_type"] == "export.generated" for e in events)


def _route_client(user: SignedInUser) -> TestClient:
    app = create_app()
    app.include_router(export_router)
    client = TestClient(app, base_url="https://testserver")
    client.cookies.update(user.client.cookies)
    return client


def test_route_is_owner_only_returns_a_zip_and_writes_an_event(
    storage: LocalDirectoryStorage,
) -> None:
    x, _, consultant = _two_orgs(storage)
    owner = _route_client(x.owner)
    response = owner.get(f"/orgs/{x.org_id}/export", params={"framework": "soc2"})
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/zip"
    assert "attachment" in response.headers["content-disposition"]
    snapshot, _, _, _ = _open(response.content)
    assert snapshot["framework"] == "soc2"

    with _session(x.org_id) as db:
        (event,) = db.scalars(select(Event).where(Event.event_type == "export.generated")).all()
        assert (event.actor_kind, event.actor_user_id) == ("human", x.owner.user_id)
        assert event.payload["framework"] == "soc2"
        assert event.payload["export_id"] == snapshot["export_id"]
        assert len(event.payload["zip_sha256"]) == 64

    iso = owner.get(f"/orgs/{x.org_id}/export", params={"framework": "iso27001"})
    assert iso.status_code == 200
    iso_snapshot, _, _, _ = _open(iso.content)
    # Nothing in this org maps to ISO 27001, and unmapped items go to SOC 2.
    assert iso_snapshot["items"] == []

    assert owner.get(f"/orgs/{x.org_id}/export", params={"framework": "pci"}).status_code == 422
    approver = _route_client(consultant)
    denied = approver.get(f"/orgs/{x.org_id}/export", params={"framework": "soc2"})
    assert denied.status_code == 403
    outsider = _route_client(sign_up())
    assert outsider.get(f"/orgs/{x.org_id}/export", params={"framework": "soc2"}).status_code == 404
