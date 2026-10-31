"""Document approval: a person marks a policy version or evidence item reviewed.

Human-only and limited to owners and approvers (KTD5, KTD10). It records the approver,
whether they acted on behalf of the org (R21), when, and the next review date: today plus
the framework's cadence (R19). That supplies R1's "last approved by" and moves an expired
review date (R9) forward.

Cadence: policy versions use the framework's policy-review cadence. Evidence uses the
access-review cadence, the only recurring evidence review R19 defines; an evidence item's
age against the audit window is the status engine's separate check.

Framework: the caller may name one. Otherwise the frameworks the item is mapped to are
used and, when there are several, the shortest cadence wins so no framework's review lapses
before the stored date. An unmapped item uses the org's first configured framework (the
rule the status engine applies to unmapped items); with no settings stored yet, R19's
defaults apply.
"""

import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.claims.service import ActingMember, acting_fields, authorize
from passport.controls.models import ControlMapping, Framework, ItemKind, OrgFrameworkSettings
from passport.controls.settings import DEFAULT_ACCESS_REVIEW_DAYS, DEFAULT_POLICY_REVIEW_DAYS
from passport.db.base import utcnow
from passport.db.models import DocumentVersion, EvidenceItem
from passport.provenance.service import append_event

ApprovableKind = Literal["document_version", "evidence"]


class ApprovalItemNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class Approval:
    item_kind: ApprovableKind
    item_id: uuid.UUID
    framework: Framework
    cadence_days: int
    approved_at: datetime
    review_due_on: date


def _cadence(settings: OrgFrameworkSettings | None, item_kind: ApprovableKind) -> int:
    if item_kind == "document_version":
        return settings.policy_review_days if settings else DEFAULT_POLICY_REVIEW_DAYS
    return settings.access_review_days if settings else DEFAULT_ACCESS_REVIEW_DAYS


def _mapped_frameworks(
    session: Session, org_id: uuid.UUID, kind: ItemKind, ids: list[uuid.UUID]
) -> set[Framework]:
    rows = session.scalars(
        select(ControlMapping.framework).where(
            ControlMapping.org_id == org_id,
            ControlMapping.item_kind == kind.value,
            ControlMapping.item_id.in_(ids),
        )
    )
    return {Framework(f) for f in rows}


def _choose_cadence(
    session: Session,
    org_id: uuid.UUID,
    item_kind: ApprovableKind,
    candidates: set[Framework],
) -> tuple[Framework, int]:
    stored = {
        Framework(s.framework): s
        for s in session.scalars(
            select(OrgFrameworkSettings).where(OrgFrameworkSettings.org_id == org_id)
        )
    }
    if not candidates:
        configured = [f for f in Framework if f in stored]
        candidates = {configured[0] if configured else next(iter(Framework))}
    ordered = [f for f in Framework if f in candidates]
    return min(((f, _cadence(stored.get(f), item_kind)) for f in ordered), key=lambda pair: pair[1])


def approve_item(
    session: Session,
    acting: ActingMember,
    *,
    item_kind: ApprovableKind,
    item_id: uuid.UUID,
    framework: Framework | None = None,
    today: date | None = None,
) -> Approval:
    """Mark the item reviewed by the acting person and set its next review date."""
    human = authorize(acting)
    item: DocumentVersion | EvidenceItem | None
    if item_kind == "document_version":
        item = session.scalars(
            select(DocumentVersion)
            .where(DocumentVersion.id == item_id, DocumentVersion.org_id == acting.org_id)
            .with_for_update()
        ).one_or_none()
        mapped_kind, mapped_ids = ItemKind.DOCUMENT, [item_id]
        if item is not None:
            mapped_ids.append(item.document_id)
        subject_kind = "document_version"
    elif item_kind == "evidence":
        item = session.scalars(
            select(EvidenceItem)
            .where(EvidenceItem.id == item_id, EvidenceItem.org_id == acting.org_id)
            .with_for_update()
        ).one_or_none()
        mapped_kind, mapped_ids = ItemKind.EVIDENCE, [item_id]
        subject_kind = "evidence_item"
    else:
        raise ValueError(f"cannot approve a {item_kind!r}")
    if item is None:
        raise ApprovalItemNotFoundError(f"{item_kind} {item_id} not found")

    candidates = (
        {framework}
        if framework is not None
        else _mapped_frameworks(session, acting.org_id, mapped_kind, mapped_ids)
    )
    chosen, cadence = _choose_cadence(session, acting.org_id, item_kind, candidates)
    approved_at = utcnow()
    review_due_on = (today or approved_at.date()) + timedelta(days=cadence)
    previous_due, previous_approver = item.review_due_on, item.last_approved_by

    item.last_approved_by = human.user_id
    item.approved_on_behalf = human.on_behalf_of_org
    item.approved_at = approved_at
    item.review_due_on = review_due_on
    session.flush()
    append_event(
        session,
        org_id=acting.org_id,
        actor=human,
        event_type=f"{subject_kind}.approved",
        subject_kind=subject_kind,
        subject_id=item_id,
        payload={
            **acting_fields(acting, human),
            "framework": chosen.value,
            "cadence_days": cadence,
            "approved_at": approved_at.isoformat(),
            "review_due_on": review_due_on.isoformat(),
            "previous_review_due_on": previous_due.isoformat() if previous_due else None,
            "previous_approved_by": str(previous_approver) if previous_approver else None,
        },
    )
    return Approval(item_kind, item_id, chosen, cadence, approved_at, review_due_on)
