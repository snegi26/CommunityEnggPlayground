"""Confirm, edit, reject, and dismiss drafted claims (U10, R7, R21, KTD5, KTD10).

Every operation here is human-only and allowed to owners and approvers; a viewer gets
``ForbiddenError`` and the agent gets ``AgentNotPermittedError``, both before anything is
read or written. Each change appends one event naming the person, their role, whether they
acted on behalf of the org (an external membership, R21), and the predicate version and
check description they saw.

Revisions: editing never changes a claim in place. It stores a new claim with
``revision_of`` pointing at the old one, unconfirmed. The old row keeps its own state and
history; a claim with a successor is *superseded*, which is derived from ``revision_of``
rather than stored as a state, so the claim-state enum (and the history it records) keeps
meaning only what a person decided. Superseded claims cannot be acted on and never count
in ``checkable_claims``.

Callers set the org context (``set_org_context``) on the session first; queries also
filter by org explicitly (KTD5).
"""

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy import exists, func, select
from sqlalchemy.orm import Session, aliased

from passport.db.base import utcnow
from passport.db.models import Claim, ClaimState, DocumentVersion
from passport.predicates.registry import PredicateRegistry
from passport.predicates.registry import registry as default_registry
from passport.provenance.actor import Actor, Human, require_human
from passport.provenance.service import append_event
from passport.tenancy.models import APPROVING_ROLES, Membership, Role

# States a check runs for; rejected and dismissed claims are kept only as history.
CHECKED_STATES = (ClaimState.UNCONFIRMED, ClaimState.NEEDS_REVIEW, ClaimState.CONFIRMED)


class ForbiddenError(PermissionError):
    """The member's role may not approve (viewers are read-only, KTD5). Maps to HTTP 403."""


class ClaimNotFoundError(LookupError):
    pass


class ClaimActionError(ValueError):
    """The claim's state does not allow this action."""


class NeedsAcknowledgementError(ClaimActionError):
    """A needs-review claim is confirmed only after its failed-support reason is acknowledged."""


# --- Who is acting ---------------------------------------------------------------


class MemberContext(Protocol):
    """What a request's org context provides; ``passport.auth.deps.OrgContext`` fits."""

    @property
    def org_id(self) -> uuid.UUID: ...

    @property
    def actor(self) -> Human: ...

    @property
    def membership(self) -> Membership: ...


@dataclass(frozen=True)
class ActingMember:
    """A principal acting in one org with a membership role."""

    org_id: uuid.UUID
    actor: Actor
    role: Role

    @classmethod
    def for_membership(cls, membership: Membership) -> "ActingMember":
        actor = Human(user_id=membership.user_id, on_behalf_of_org=membership.external)
        return cls(membership.org_id, actor, Role(membership.role))

    @classmethod
    def from_context(cls, ctx: MemberContext) -> "ActingMember":
        return cls(ctx.org_id, ctx.actor, Role(ctx.membership.role))


def authorize(acting: ActingMember) -> Human:
    """A person with an approving role (KTD5, KTD10); raises before anything is written."""
    human = require_human(acting.actor)
    if acting.role not in APPROVING_ROLES:
        raise ForbiddenError(f"a {acting.role.value} may not approve or change claims")
    return human


def acting_fields(acting: ActingMember, human: Human) -> dict[str, Any]:
    """Who acted, recorded in every approval event's payload."""
    return {
        "user_id": str(human.user_id),
        "role": acting.role.value,
        "on_behalf_of_org": human.on_behalf_of_org,
    }


# --- Check preview (pure) --------------------------------------------------------


@dataclass(frozen=True)
class CheckPreview:
    """What an approver sees before saving an edit: the check in plain language (R7)."""

    predicate_id: str
    predicate_version: int
    parameters: dict[str, Any]
    check_description: str


def preview_check(
    predicate_id: str,
    parameters: Mapping[str, Any],
    registry: PredicateRegistry = default_registry,
) -> CheckPreview:
    """Validate parameters against the predicate's latest version and describe the check.

    Raises ``UnknownPredicateError`` or ``InvalidParametersError`` for bad input.
    """
    predicate = registry.latest(predicate_id)
    params = predicate.parse_params(parameters)
    return CheckPreview(
        predicate_id=predicate.id,
        predicate_version=predicate.version,
        parameters=params.model_dump(mode="json"),
        check_description=predicate.describe(params),
    )


# --- Queries ---------------------------------------------------------------------


def _not_superseded() -> Any:
    successor = aliased(Claim)
    return ~exists().where(successor.revision_of == Claim.id)


def is_superseded(session: Session, claim_id: uuid.UUID) -> bool:
    return bool(session.scalar(select(exists().where(Claim.revision_of == claim_id))))


def current_claims(session: Session, org_id: uuid.UUID, version_id: uuid.UUID) -> list[Claim]:
    """A version's claims in every state, latest revisions only (for review pages)."""
    successor = aliased(Claim)
    in_version = exists().where(
        successor.revision_of == Claim.id,
        successor.document_version_id == version_id,
    )
    return list(
        session.scalars(
            select(Claim)
            .where(Claim.org_id == org_id, Claim.document_version_id == version_id, ~in_version)
            .order_by(Claim.created_at, Claim.id)
        )
    )


def checkable_claims(session: Session, org_id: uuid.UUID) -> list[Claim]:
    """Claims a check run evaluates (U11, U12).

    Only claims on each document's latest version, latest revisions only, with a
    predicate, and not rejected or dismissed. Confirmed, unconfirmed, and needs-review
    claims are all checked; trust (R8) comes from the state, not from this filter.
    """
    latest = (
        select(
            DocumentVersion.document_id,
            func.max(DocumentVersion.version_number).label("number"),
        )
        .where(DocumentVersion.org_id == org_id)
        .group_by(DocumentVersion.document_id)
        .subquery()
    )
    return list(
        session.scalars(
            select(Claim)
            .join(DocumentVersion, DocumentVersion.id == Claim.document_version_id)
            .join(
                latest,
                (latest.c.document_id == DocumentVersion.document_id)
                & (latest.c.number == DocumentVersion.version_number),
            )
            .where(
                Claim.org_id == org_id,
                Claim.predicate_id.is_not(None),
                Claim.state.in_(CHECKED_STATES),
                _not_superseded(),
            )
            .order_by(Claim.created_at, Claim.id)
        )
    )


# --- Mutations -------------------------------------------------------------------


def _load_for_update(session: Session, org_id: uuid.UUID, claim_id: uuid.UUID) -> Claim:
    claim = session.scalars(
        select(Claim).where(Claim.id == claim_id, Claim.org_id == org_id).with_for_update()
    ).one_or_none()
    if claim is None:
        raise ClaimNotFoundError(f"claim {claim_id} not found")
    if is_superseded(session, claim.id):
        raise ClaimActionError("this claim has a newer revision; act on that one instead")
    return claim


def _check_fields(claim: Claim) -> dict[str, Any]:
    return {
        "document_version_id": str(claim.document_version_id),
        "span_id": claim.span_id,
        "quote": claim.quote,
        "predicate_id": claim.predicate_id,
        "predicate_version": claim.predicate_version,
        "parameters": claim.parameters,
        "check_description": claim.check_description,
    }


def _record(
    session: Session,
    acting: ActingMember,
    human: Human,
    claim: Claim,
    event_type: str,
    extra: dict[str, Any],
) -> None:
    append_event(
        session,
        org_id=acting.org_id,
        actor=human,
        event_type=event_type,
        subject_kind="claim",
        subject_id=claim.id,
        payload={**acting_fields(acting, human), **_check_fields(claim), **extra},
    )


def _require_checkable(claim: Claim, action: str) -> None:
    if claim.predicate_id is None:
        raise ClaimActionError(f"a not-checkable claim cannot be {action}; dismiss it instead")


def _require_open(claim: Claim, action: str) -> None:
    if claim.state in (ClaimState.REJECTED, ClaimState.DISMISSED):
        raise ClaimActionError(f"a {claim.state.value} claim cannot be {action}")


def confirm_claim(
    session: Session,
    acting: ActingMember,
    claim_id: uuid.UUID,
    *,
    acknowledge_reason: bool = False,
) -> Claim:
    """Confirm a checkable claim, recording who confirmed it and the check they saw."""
    human = authorize(acting)
    claim = _load_for_update(session, acting.org_id, claim_id)
    _require_checkable(claim, "confirmed")
    _require_open(claim, "confirmed")
    if claim.state is ClaimState.CONFIRMED:
        raise ClaimActionError("this claim is already confirmed")
    acknowledged = None
    if claim.state is ClaimState.NEEDS_REVIEW:
        if not acknowledge_reason:
            raise NeedsAcknowledgementError(
                "confirming needs acknowledgement of why the quote may not support this check: "
                f"{claim.needs_review_reason}"
            )
        acknowledged = claim.needs_review_reason
    previous = claim.state
    claim.state = ClaimState.CONFIRMED
    claim.confirmed_by = human.user_id
    claim.confirmed_on_behalf = human.on_behalf_of_org
    claim.confirmed_at = utcnow()
    session.flush()
    _record(
        session,
        acting,
        human,
        claim,
        "claim.confirmed",
        {
            "previous_state": previous.value,
            "acknowledged_reason": acknowledged,
            "confirmed_at": claim.confirmed_at.isoformat(),
        },
    )
    return claim


def edit_claim(
    session: Session,
    acting: ActingMember,
    claim_id: uuid.UUID,
    *,
    predicate_id: str,
    parameters: Mapping[str, Any],
    registry: PredicateRegistry = default_registry,
) -> Claim:
    """Store a new unconfirmed revision binding the chosen predicate and parameters.

    The old revision's confirmation never applies to the new one (R20); the new
    revision must be confirmed again.
    """
    human = authorize(acting)
    claim = _load_for_update(session, acting.org_id, claim_id)
    _require_checkable(claim, "edited")
    _require_open(claim, "edited")
    preview = preview_check(predicate_id, parameters, registry)
    revision = Claim(
        org_id=claim.org_id,
        document_version_id=claim.document_version_id,
        span_id=claim.span_id,
        quote=claim.quote,
        predicate_id=preview.predicate_id,
        predicate_version=preview.predicate_version,
        parameters=preview.parameters,
        check_description=preview.check_description,
        state=ClaimState.UNCONFIRMED,
        needs_review_reason=None,
        revision_of=claim.id,
    )
    session.add(revision)
    session.flush()
    _record(
        session,
        acting,
        human,
        revision,
        "claim.edited",
        {
            "revision_of": str(claim.id),
            "state": revision.state.value,
            "before": {**_check_fields(claim), "state": claim.state.value},
        },
    )
    return revision


def _close(
    session: Session,
    acting: ActingMember,
    claim_id: uuid.UUID,
    target: ClaimState,
    reason: str | None,
) -> Claim:
    human = authorize(acting)
    claim = _load_for_update(session, acting.org_id, claim_id)
    action = target.value
    if target is ClaimState.REJECTED:
        _require_checkable(claim, action)
    elif claim.predicate_id is not None:
        raise ClaimActionError("only a not-checkable claim is dismissed; reject this one instead")
    _require_open(claim, action)
    previous = claim.state
    claim.state = target
    session.flush()
    _record(
        session,
        acting,
        human,
        claim,
        f"claim.{action}",
        {"previous_state": previous.value, "reason": reason},
    )
    return claim


def reject_claim(
    session: Session, acting: ActingMember, claim_id: uuid.UUID, *, reason: str | None = None
) -> Claim:
    """Reject a checkable claim: it stays in history and is no longer checked."""
    return _close(session, acting, claim_id, ClaimState.REJECTED, reason)


def dismiss_claim(
    session: Session, acting: ActingMember, claim_id: uuid.UUID, *, reason: str | None = None
) -> Claim:
    """Dismiss a not-checkable claim (the only action it allows)."""
    return _close(session, acting, claim_id, ClaimState.DISMISSED, reason)
