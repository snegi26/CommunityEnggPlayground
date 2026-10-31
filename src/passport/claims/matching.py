"""F3 version matching: carry claims of unchanged spans to a new policy version (R20, KTD14).

Matching is deterministic and runs at upload, before drafting: the upload's span diff has already
marked each new span unchanged, changed, or new against the previous version. Every
current claim of a span marked unchanged is copied to the new version with its state and
confirmation intact (``revision_of`` links the copy to its source) and a
``claim.carried_over`` event names both claim ids. Claims of changed or new spans are not
copied: drafting sees only those spans, and what it drafts is always unconfirmed, even if
the predicate and parameters match an earlier confirmed claim. Claims of removed spans
stay on the old version only.

Rejected and dismissed claims carry over too, so a person's decision on an unchanged
sentence is not lost (drafting never sees that sentence again).
"""

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.db.models import Claim, DocumentVersion
from passport.documents.service import get_version, spans_for_version
from passport.provenance.actor import Actor, require_human
from passport.provenance.service import append_event


class ClaimRef(Protocol):
    @property
    def id(self) -> uuid.UUID: ...

    @property
    def span_id(self) -> str: ...

    @property
    def revision_of(self) -> uuid.UUID | None: ...


@dataclass(frozen=True)
class SpanLink:
    """A new-version span: its id, its diff mark, and the previous span it pairs with."""

    span_id: str
    change_kind: str
    previous_span_id: str | None


@dataclass(frozen=True)
class CarryOver[C: ClaimRef]:
    claim: C
    to_span_id: str


def current_revisions[C: ClaimRef](claims: Sequence[C]) -> list[C]:
    """Claims no other claim in ``claims`` revises, in their given order."""
    revised = {c.revision_of for c in claims if c.revision_of is not None}
    return [c for c in claims if c.id not in revised]


def plan_carry_over[C: ClaimRef](
    spans: Sequence[SpanLink], previous_claims: Sequence[C]
) -> list[CarryOver[C]]:
    """Which previous-version claims carry to which new span: unchanged spans only."""
    by_span: dict[str, list[C]] = {}
    for claim in current_revisions(previous_claims):
        by_span.setdefault(claim.span_id, []).append(claim)
    plan: list[CarryOver[C]] = []
    for span in spans:
        if span.change_kind != "unchanged" or span.previous_span_id is None:
            continue
        plan.extend(CarryOver(c, span.span_id) for c in by_span.get(span.previous_span_id, []))
    return plan


def carry_over_confirmations(
    session: Session, *, version: DocumentVersion, actor: Actor
) -> list[Claim]:
    """Copy the previous version's claims on unchanged spans to ``version``.

    Call it in the upload transaction right after ``upload_policy`` stores the spans, and
    before drafting is enqueued, with the uploader as ``actor``: carry-over is a
    deterministic consequence of that person's upload, never an agent or model action
    (KTD10), and no one confirms anything here. Calling it again is a no-op.
    """
    human = require_human(actor)
    if version.version_number == 1:
        return []
    previous = get_version(session, version.document_id, version.version_number - 1)
    previous_span_ids = {s.id: s.span_id for s in spans_for_version(session, previous.id)}
    links = [
        SpanLink(
            s.span_id,
            s.change_kind,
            previous_span_ids.get(s.previous_id) if s.previous_id else None,
        )
        for s in spans_for_version(session, version.id)
    ]
    previous_claims = list(
        session.scalars(
            select(Claim)
            .where(Claim.org_id == version.org_id, Claim.document_version_id == previous.id)
            .order_by(Claim.created_at, Claim.id)
        )
    )
    already = set(
        session.scalars(
            select(Claim.revision_of).where(
                Claim.document_version_id == version.id, Claim.revision_of.is_not(None)
            )
        )
    )

    carried: list[Claim] = []
    for item in plan_carry_over(links, previous_claims):
        source = item.claim
        if source.id in already:
            continue
        copy = Claim(
            org_id=version.org_id,
            document_version_id=version.id,
            span_id=item.to_span_id,
            quote=source.quote,
            predicate_id=source.predicate_id,
            predicate_version=source.predicate_version,
            parameters=source.parameters,
            check_description=source.check_description,
            state=source.state,
            needs_review_reason=source.needs_review_reason,
            revision_of=source.id,
            confirmed_by=source.confirmed_by,
            confirmed_on_behalf=source.confirmed_on_behalf,
            confirmed_at=source.confirmed_at,
        )
        session.add(copy)
        session.flush()
        append_event(
            session,
            org_id=version.org_id,
            actor=human,
            event_type="claim.carried_over",
            subject_kind="claim",
            subject_id=copy.id,
            payload={
                "from_claim_id": str(source.id),
                "to_claim_id": str(copy.id),
                "from_document_version_id": str(previous.id),
                "to_document_version_id": str(version.id),
                "from_span_id": source.span_id,
                "to_span_id": copy.span_id,
                "state": copy.state.value,
                "predicate_id": copy.predicate_id,
                "predicate_version": copy.predicate_version,
                "check_description": copy.check_description,
                "confirmed_by": str(copy.confirmed_by) if copy.confirmed_by else None,
                "confirmed_on_behalf": copy.confirmed_on_behalf,
                "confirmed_at": copy.confirmed_at.isoformat() if copy.confirmed_at else None,
            },
        )
        carried.append(copy)
    return carried
