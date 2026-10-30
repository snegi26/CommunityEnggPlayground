"""Control catalog reference rows and org-scoped mappings, settings, and scope (U4).

``controls`` is global reference data loaded by migration and read-only to the app
role. Every other table here carries ``org_id`` and is RLS-isolated (KTD5).
"""

import enum
import uuid
from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from passport.db.base import Base, CreatedAtMixin, IdMixin, utcnow
from passport.db.models import OrgScoped


class Framework(enum.StrEnum):
    SOC2 = "soc2"
    ISO27001 = "iso27001"


class AuditType(enum.StrEnum):
    SOC2_TYPE1 = "soc2_type1"  # point in time: a single as-of date
    SOC2_TYPE2 = "soc2_type2"  # observation period: window start and end
    ISO27001_CERTIFICATION = "iso27001_certification"  # certification cycle window


AUDIT_TYPES: dict[Framework, frozenset[AuditType]] = {
    Framework.SOC2: frozenset({AuditType.SOC2_TYPE1, AuditType.SOC2_TYPE2}),
    Framework.ISO27001: frozenset({AuditType.ISO27001_CERTIFICATION}),
}


class ItemKind(enum.StrEnum):
    DOCUMENT = "document"
    EVIDENCE = "evidence"


class ScopeKind(enum.StrEnum):
    AWS_ACCOUNT = "aws_account"
    GITHUB_ORG = "github_org"
    WORKSPACE_DOMAIN = "workspace_domain"


class Control(Base):
    """One catalog control: identifier and short title only (no copyrighted text)."""

    __tablename__ = "controls"

    framework: Mapped[str] = mapped_column(String(30), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    position: Mapped[int] = mapped_column(Integer)


class ControlMapping(IdMixin, CreatedAtMixin, OrgScoped, Base):
    """A document or evidence item mapped to one control; items map to many (R4)."""

    __tablename__ = "control_mappings"
    __table_args__ = (
        UniqueConstraint("org_id", "item_kind", "item_id", "framework", "control_id"),
        ForeignKeyConstraint(
            ["framework", "control_id"], ["controls.framework", "controls.control_id"]
        ),
    )

    item_kind: Mapped[str] = mapped_column(String(20))
    item_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    framework: Mapped[str] = mapped_column(String(30))
    control_id: Mapped[str] = mapped_column(String(20))


class OrgFrameworkSettings(IdMixin, OrgScoped, Base):
    """Audit window and review cadences for one org and framework (R19)."""

    __tablename__ = "org_framework_settings"
    __table_args__ = (
        UniqueConstraint("org_id", "framework"),
        CheckConstraint(
            "window_start IS NULL OR window_end IS NULL OR window_end > window_start",
            name="window_order",
        ),
        CheckConstraint(
            "audit_type <> 'soc2_type1' OR (window_start IS NULL AND window_end IS NULL)",
            name="type1_single_date",
        ),
        CheckConstraint(
            "policy_review_days > 0 AND access_review_days > 0 AND expiring_soon_days >= 0",
            name="positive_cadences",
        ),
    )

    framework: Mapped[str] = mapped_column(String(30))
    audit_type: Mapped[str] = mapped_column(String(30))
    as_of_date: Mapped[date | None] = mapped_column(Date)
    window_start: Mapped[date | None] = mapped_column(Date)
    window_end: Mapped[date | None] = mapped_column(Date)
    policy_review_days: Mapped[int] = mapped_column(Integer)
    access_review_days: Mapped[int] = mapped_column(Integer)
    expiring_soon_days: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScopeEntry(IdMixin, CreatedAtMixin, OrgScoped, Base):
    """An in-scope system a claim's scope can refer to; R18 compares against these."""

    __tablename__ = "scope_entries"
    __table_args__ = (UniqueConstraint("org_id", "kind", "identifier"),)

    kind: Mapped[str] = mapped_column(String(30))
    identifier: Mapped[str] = mapped_column(String(200))
    label: Mapped[str] = mapped_column(String(200), default="")
    production: Mapped[bool] = mapped_column(Boolean, default=False)
