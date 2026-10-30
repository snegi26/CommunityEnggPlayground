"""Request dependencies: the signed-in user and the active org (KTD5, KTD15)."""

import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session

from passport.auth.models import User
from passport.auth.service import CurrentSession, resolve_session
from passport.db.engine import get_session
from passport.provenance.actor import Human
from passport.tenancy.models import APPROVING_ROLES, Membership
from passport.tenancy.service import NotFoundError, require_membership

SESSION_COOKIE = "passport_session"

DbSession = Annotated[Session, Depends(get_session)]


def current_session(
    db: DbSession, passport_session: Annotated[str | None, Cookie()] = None
) -> CurrentSession:
    resolved = resolve_session(db, passport_session) if passport_session else None
    if resolved is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "login_required")
    return resolved


SignedIn = Annotated[CurrentSession, Depends(current_session)]


@dataclass(frozen=True)
class OrgContext:
    user: User
    membership: Membership

    @property
    def org_id(self) -> uuid.UUID:
        return self.membership.org_id

    @property
    def actor(self) -> Human:
        return Human(user_id=self.user.id, on_behalf_of_org=self.membership.external)


def org_context(org_id: uuid.UUID, db: DbSession, signed_in: SignedIn) -> OrgContext:
    """Verify membership, bind the transaction to the org, and enforce MFA for approvers."""
    try:
        membership = require_membership(db, user_id=signed_in.user.id, org_id=org_id)
    except NotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found") from None
    if membership.role in APPROVING_ROLES:
        if not signed_in.user.totp_enabled:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "mfa_enrollment_required")
        if not signed_in.mfa_verified:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "mfa_verification_required")
    return OrgContext(user=signed_in.user, membership=membership)


InOrg = Annotated[OrgContext, Depends(org_context)]


def require_roles(ctx: OrgContext, *roles: str) -> None:
    if ctx.membership.role not in roles:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
