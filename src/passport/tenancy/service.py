"""Orgs, memberships, and invitations (KTD5)."""

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from passport.auth.models import User
from passport.auth.service import hash_token, new_token
from passport.db.base import utcnow
from passport.db.rls import set_invite_context, set_org_context
from passport.tenancy.models import Invitation, Membership, Org, Role

INVITATION_TTL = timedelta(days=7)


class NotFoundError(Exception):
    """The resource does not exist or is not visible to the caller (never says which)."""


class InvitationError(Exception):
    """Invitation token invalid, expired, or already used."""


def create_org(session: Session, *, name: str, owner: User) -> Org:
    org = Org(id=uuid.uuid4(), name=name)
    set_org_context(session, org.id)
    session.add(org)
    session.flush()
    session.add(Membership(org_id=org.id, user_id=owner.id, role=Role.OWNER))
    session.flush()
    return org


def require_membership(session: Session, *, user_id: uuid.UUID, org_id: uuid.UUID) -> Membership:
    """Return the caller's membership and bind the transaction to that org."""
    membership = session.scalar(
        select(Membership).where(Membership.user_id == user_id, Membership.org_id == org_id)
    )
    if membership is None:
        raise NotFoundError
    set_org_context(session, org_id)
    return membership


@dataclass(frozen=True)
class OrgChoice:
    org_id: uuid.UUID
    name: str
    role: Role


def orgs_for_user(session: Session, *, user_id: uuid.UUID) -> list[OrgChoice]:
    """The org switcher: one user's memberships, via the user-keyed policy only."""
    rows = session.execute(
        select(Org.id, Org.name, Membership.role)
        .join(Membership, Membership.org_id == Org.id)
        .where(Membership.user_id == user_id)
        .order_by(Org.name)
    ).all()
    return [OrgChoice(org_id=r.id, name=r.name, role=r.role) for r in rows]


def create_invitation(
    session: Session,
    *,
    org_id: uuid.UUID,
    invited_by: User,
    email: str,
    role: Role,
    external: bool = False,
) -> str:
    """Create a single-use invitation bound to one org, role, and external flag."""
    token = new_token()
    session.add(
        Invitation(
            org_id=org_id,
            email=email.strip().lower(),
            role=role,
            external=external,
            token_hash=hash_token(token),
            expires_at=utcnow() + INVITATION_TTL,
            invited_by=invited_by.id,
        )
    )
    session.flush()
    return token


def accept_invitation(session: Session, *, token: str, user: User) -> Membership:
    token_hash = hash_token(token)
    set_invite_context(session, token_hash)
    invitation = session.scalar(select(Invitation).where(Invitation.token_hash == token_hash))
    if (
        invitation is None
        or invitation.accepted_at is not None
        or invitation.expires_at <= utcnow()
    ):
        raise InvitationError
    set_org_context(session, invitation.org_id)
    existing = session.scalar(
        select(Membership).where(
            Membership.org_id == invitation.org_id, Membership.user_id == user.id
        )
    )
    if existing is not None:
        raise InvitationError
    membership = Membership(
        org_id=invitation.org_id,
        user_id=user.id,
        role=invitation.role,
        external=invitation.external,
    )
    session.add(membership)
    invitation.accepted_at = utcnow()
    session.flush()
    return membership


def all_org_ids(session: Session) -> list[uuid.UUID]:
    """Scheduler path: org ids only, through the owner-defined function."""
    return list(session.scalars(text("SELECT passport_all_org_ids()")))


def membership_of(session: Session, *, user_id: uuid.UUID, org_id: uuid.UUID) -> Membership | None:
    return session.scalar(
        select(Membership).where(Membership.user_id == user_id, Membership.org_id == org_id)
    )
