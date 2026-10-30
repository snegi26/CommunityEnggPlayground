"""Organizations (tenants), memberships, and invitations (KTD5)."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from passport.db.base import Base, CreatedAtMixin, IdMixin


class Role(enum.StrEnum):
    OWNER = "owner"
    APPROVER = "approver"
    VIEWER = "viewer"


# Roles that hold approval authority must use MFA (KTD15) and may confirm claims (KTD5).
APPROVING_ROLES = frozenset({Role.OWNER, Role.APPROVER})

role_enum = Enum(Role, name="membership_role", values_callable=lambda e: [m.value for m in e])


class Org(IdMixin, CreatedAtMixin, Base):
    __tablename__ = "orgs"

    name: Mapped[str] = mapped_column(String(200))


class Membership(IdMixin, CreatedAtMixin, Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("org_id", "user_id"),)

    org_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("orgs.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"))
    role: Mapped[Role] = mapped_column(role_enum)
    # Consultant memberships are external; approvals they make are recorded as on
    # behalf of the org (R21).
    external: Mapped[bool] = mapped_column(Boolean, default=False)


class Invitation(IdMixin, CreatedAtMixin, Base):
    __tablename__ = "invitations"

    org_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("orgs.id", ondelete="CASCADE"))
    email: Mapped[str] = mapped_column(String(320))
    role: Mapped[Role] = mapped_column(role_enum)
    external: Mapped[bool] = mapped_column(Boolean, default=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    invited_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
