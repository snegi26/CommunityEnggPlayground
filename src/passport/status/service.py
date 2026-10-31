"""Recompute and persist an org's item statuses (KTD8, KTD9).

Loads every document (its latest version) and evidence item with the inputs the pure
engine needs: the claims on the latest version, each claim's latest check facts and
last successful verification, whether a connected system serves it now, review and
collection dates, control mappings, and per-framework settings. The engine's results
are written to ``item_statuses``, one row per item and framework.

An event is written only when an item's status, trust, or causes change (or its row
appears or disappears), so a recompute over unchanged inputs writes nothing. Events name
the freshness agent as an ``Agent`` with ``model_id`` ``"none"``: the engine is
deterministic code and no model runs (KTD2, KTD9).

Which claims belong to an item: the claims a check covers (``checkable_claims``) plus,
from the same latest versions, the claims that bind no predicate and are still open
(they make an item not checkable rather than silently current). Rejected and dismissed
claims are history only.
"""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from passport.checks.models import CheckOutcome
from passport.claims.service import CHECKED_STATES, checkable_claims, current_claims_for_versions
from passport.connectors.models import Connection, ConnectionKind, ConnectionStatus
from passport.connectors.registry import kinds_serving
from passport.controls.models import ControlMapping, Framework, ItemKind, OrgFrameworkSettings
from passport.db.base import utcnow
from passport.db.models import Claim, Document, DocumentVersion, EvidenceItem, ItemStatus
from passport.predicates.registry import PredicateError, PredicateRegistry
from passport.predicates.registry import registry as default_registry
from passport.provenance.actor import Agent
from passport.provenance.service import append_event
from passport.status.engine import (
    ENGINE_VERSION,
    ClaimCheck,
    ClaimInput,
    FrameworkSettings,
    ItemInput,
    ItemResult,
    Status,
    evaluate_item,
)

VERIFIED = (Status.CURRENT.value, Status.CONTRADICTED.value)


def status_actor(run_id: uuid.UUID | None = None) -> Agent:
    """The freshness agent recomputing statuses; no model runs."""
    return Agent(run_id=run_id or uuid.uuid4(), model_id="none", prompt_version=ENGINE_VERSION)


@dataclass(frozen=True)
class StatusChange:
    item_kind: str
    item_id: uuid.UUID
    framework: str
    before: str | None
    after: str | None


def _served_kinds(session: Session, org_id: uuid.UUID) -> set[ConnectionKind]:
    return {
        ConnectionKind(kind)
        for kind in session.scalars(
            select(Connection.kind).where(
                Connection.org_id == org_id,
                Connection.status == ConnectionStatus.ACTIVE.value,
            )
        )
    }


def _latest_checks(
    session: Session, org_id: uuid.UUID, claim_ids: Iterable[uuid.UUID]
) -> tuple[dict[uuid.UUID, ClaimCheck], dict[uuid.UUID, CheckOutcome]]:
    """Each claim's latest outcome, and its latest outcome that verified (pass or fail)."""
    ids = list(claim_ids)
    latest: dict[uuid.UUID, ClaimCheck] = {}
    verified: dict[uuid.UUID, CheckOutcome] = {}
    if not ids:
        return latest, verified
    rows = session.scalars(
        select(CheckOutcome)
        .where(CheckOutcome.org_id == org_id, CheckOutcome.claim_id.in_(ids))
        .order_by(CheckOutcome.checked_at.desc(), CheckOutcome.created_at.desc())
    )
    for row in rows:
        if row.claim_id not in latest:
            latest[row.claim_id] = ClaimCheck.from_json(row.detail, row.checked_at)
        if row.outcome in VERIFIED and row.claim_id not in verified:
            verified[row.claim_id] = row
    return latest, verified


def _document_inputs(
    session: Session, org_id: uuid.UUID, registry: PredicateRegistry
) -> list[ItemInput]:
    latest_number = (
        select(
            DocumentVersion.document_id,
            func.max(DocumentVersion.version_number).label("number"),
        )
        .where(DocumentVersion.org_id == org_id)
        .group_by(DocumentVersion.document_id)
        .subquery()
    )
    versions = session.execute(
        select(Document, DocumentVersion)
        .join(DocumentVersion, DocumentVersion.document_id == Document.id)
        .join(
            latest_number,
            (latest_number.c.document_id == DocumentVersion.document_id)
            & (latest_number.c.number == DocumentVersion.version_number),
        )
        .where(Document.org_id == org_id)
        .order_by(Document.created_at, Document.id)
    ).all()

    checked = checkable_claims(session, org_id)
    checked_by_version: dict[uuid.UUID, list[Claim]] = {}
    for claim in checked:
        checked_by_version.setdefault(claim.document_version_id, []).append(claim)
    current = current_claims_for_versions(session, org_id, (v.id for _, v in versions))
    claims_by_version: dict[uuid.UUID, list[Claim]] = {}
    for _, version in versions:
        unbound = [
            c for c in current[version.id] if c.predicate_id is None and c.state in CHECKED_STATES
        ]
        ordered = sorted(
            [*checked_by_version.get(version.id, []), *unbound],
            key=lambda c: (c.created_at, c.id),
        )
        claims_by_version[version.id] = ordered

    all_claims = [c for claims in claims_by_version.values() for c in claims]
    latest, verified = _latest_checks(session, org_id, (c.id for c in all_claims))
    kinds = _served_kinds(session, org_id)

    def served(claim: Claim) -> bool:
        if claim.predicate_id is None or claim.predicate_version is None:
            return False
        try:
            capability = registry.get(claim.predicate_id, claim.predicate_version).capability
        except PredicateError:
            return False
        return any(kind in kinds for kind in kinds_serving(capability))

    mappings = _mappings(session, org_id, ItemKind.DOCUMENT)
    items: list[ItemInput] = []
    for document, version in versions:
        claim_inputs = tuple(
            ClaimInput(
                claim_id=c.id,
                quote=c.quote,
                predicate_id=c.predicate_id,
                state=c.state,
                served=served(c),
                latest=latest.get(c.id),
                last_verified_at=verified[c.id].checked_at if c.id in verified else None,
                check_description=c.check_description,
            )
            for c in claims_by_version[version.id]
        )
        frameworks = mappings.get(document.id, set()) | mappings.get(version.id, set())
        items.append(
            ItemInput(
                kind=ItemKind.DOCUMENT,
                item_id=document.id,
                title=document.title,
                claims=claim_inputs,
                review_due_on=version.review_due_on,
                frameworks=tuple(f for f in Framework if f in frameworks),
            )
        )
    return items


def _evidence_inputs(session: Session, org_id: uuid.UUID) -> list[ItemInput]:
    mappings = _mappings(session, org_id, ItemKind.EVIDENCE)
    return [
        ItemInput(
            kind=ItemKind.EVIDENCE,
            item_id=evidence.id,
            title=evidence.title,
            review_due_on=evidence.review_due_on,
            collected_at=evidence.collected_at,
            frameworks=tuple(f for f in Framework if f in mappings.get(evidence.id, set())),
        )
        for evidence in session.scalars(
            select(EvidenceItem)
            .where(EvidenceItem.org_id == org_id)
            .order_by(EvidenceItem.created_at, EvidenceItem.id)
        )
    ]


def _mappings(
    session: Session, org_id: uuid.UUID, kind: ItemKind
) -> dict[uuid.UUID, set[Framework]]:
    found: dict[uuid.UUID, set[Framework]] = {}
    for item_id, framework in session.execute(
        select(ControlMapping.item_id, ControlMapping.framework).where(
            ControlMapping.org_id == org_id, ControlMapping.item_kind == kind.value
        )
    ):
        found.setdefault(item_id, set()).add(Framework(framework))
    return found


def _settings(session: Session, org_id: uuid.UUID) -> dict[Framework, FrameworkSettings]:
    return {
        Framework(row.framework): FrameworkSettings.from_row(row)
        for row in session.scalars(
            select(OrgFrameworkSettings).where(OrgFrameworkSettings.org_id == org_id)
        )
    }


def compute_statuses(
    session: Session,
    org_id: uuid.UUID,
    *,
    today: date,
    registry: PredicateRegistry = default_registry,
) -> list[ItemResult]:
    """Every item's results for the org, without writing anything."""
    settings = _settings(session, org_id)
    items = [*_document_inputs(session, org_id, registry), *_evidence_inputs(session, org_id)]
    return [result for item in items for result in evaluate_item(item, settings, today)]


def _snapshot(row: ItemStatus) -> dict[str, object]:
    return {"status": row.status, "trusted": row.trusted, "causes": row.causes}


def recompute_statuses(
    session: Session,
    org_id: uuid.UUID,
    *,
    actor: Agent | None = None,
    today: date | None = None,
    registry: PredicateRegistry = default_registry,
) -> list[StatusChange]:
    """Recompute and persist every item status for the org; returns what changed."""
    actor = actor or status_actor()
    now = utcnow()
    results = compute_statuses(session, org_id, today=today or now.date(), registry=registry)
    existing = {
        (row.item_kind, row.item_id, row.framework): row
        for row in session.scalars(select(ItemStatus).where(ItemStatus.org_id == org_id))
    }
    changes: list[StatusChange] = []
    for result in results:
        key = (result.item_kind.value, result.item_id, result.framework.value)
        after = {
            "status": result.status.value,
            "trusted": result.trusted,
            "causes": result.causes_json(),
        }
        row = existing.pop(key, None)
        before = _snapshot(row) if row is not None else None
        if row is None:
            row = ItemStatus(
                org_id=org_id,
                item_kind=key[0],
                item_id=result.item_id,
                framework=key[2],
            )
            session.add(row)
        row.status = result.status.value
        row.trusted = result.trusted
        row.causes = result.causes_json()
        row.computed_at = now
        if before == after:
            continue
        append_event(
            session,
            org_id=org_id,
            actor=actor,
            event_type="item_status.changed",
            subject_kind=key[0],
            subject_id=result.item_id,
            payload={"framework": key[2], "before": before, "after": after},
        )
        changes.append(
            StatusChange(
                key[0],
                result.item_id,
                key[2],
                str(before["status"]) if before else None,
                result.status.value,
            )
        )
    for (kind, item_id, framework), row in existing.items():
        before = _snapshot(row)
        session.delete(row)
        append_event(
            session,
            org_id=org_id,
            actor=actor,
            event_type="item_status.removed",
            subject_kind=kind,
            subject_id=item_id,
            payload={"framework": framework, "before": before, "after": None},
        )
        changes.append(StatusChange(kind, item_id, framework, row.status, None))
    session.flush()
    return changes
