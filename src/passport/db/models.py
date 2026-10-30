"""Core domain tables (U3). Every row carries ``org_id`` and is RLS-isolated (KTD5)."""

import enum
import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from passport.db.base import Base, CreatedAtMixin, IdMixin


def _enum(cls: type[enum.Enum], name: str) -> Enum:
    return Enum(cls, name=name, values_callable=lambda e: [m.value for m in e])


class OrgScoped:
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("orgs.id", ondelete="CASCADE"), index=True
    )


class ApprovalFields:
    """Document approval (U10): who last marked the item reviewed, and when it is next due."""

    last_approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_on_behalf: Mapped[bool] = mapped_column(Boolean, default=False)
    review_due_on: Mapped[date | None] = mapped_column(Date)


class Document(IdMixin, CreatedAtMixin, OrgScoped, Base):
    __tablename__ = "documents"

    title: Mapped[str] = mapped_column(String(300))


class DocumentVersion(IdMixin, CreatedAtMixin, OrgScoped, ApprovalFields, Base):
    __tablename__ = "document_versions"
    __table_args__ = (UniqueConstraint("document_id", "version_number"),)

    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("documents.id", ondelete="CASCADE")
    )
    version_number: Mapped[int] = mapped_column(Integer)
    filename: Mapped[str] = mapped_column(String(300))
    content_hash: Mapped[str] = mapped_column(String(64))
    storage_key: Mapped[str] = mapped_column(String(500))


class EvidenceItem(IdMixin, CreatedAtMixin, OrgScoped, ApprovalFields, Base):
    __tablename__ = "evidence_items"

    title: Mapped[str] = mapped_column(String(300))
    filename: Mapped[str] = mapped_column(String(300))
    content_hash: Mapped[str] = mapped_column(String(64))
    storage_key: Mapped[str] = mapped_column(String(500))
    source: Mapped[str] = mapped_column(String(300))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Uploaded by a person: collection metadata is asserted, not observed (R13).
    user_asserted: Mapped[bool] = mapped_column(Boolean, default=True)


class ClaimState(enum.StrEnum):
    UNCONFIRMED = "unconfirmed"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    DISMISSED = "dismissed"


class Claim(IdMixin, CreatedAtMixin, OrgScoped, Base):
    __tablename__ = "claims"

    document_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("document_versions.id", ondelete="CASCADE")
    )
    span_id: Mapped[str] = mapped_column(String(200))
    quote: Mapped[str] = mapped_column(Text)
    # None means no predicate fits: the claim is not checkable (KTD3).
    predicate_id: Mapped[str | None] = mapped_column(String(100))
    predicate_version: Mapped[int | None] = mapped_column(Integer)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    check_description: Mapped[str | None] = mapped_column(Text)
    state: Mapped[ClaimState] = mapped_column(_enum(ClaimState, "claim_state"))
    needs_review_reason: Mapped[str | None] = mapped_column(Text)
    revision_of: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("claims.id"))
    confirmed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    confirmed_on_behalf: Mapped[bool] = mapped_column(Boolean, default=False)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CheckBinding(IdMixin, CreatedAtMixin, OrgScoped, Base):
    """Which connection serves a claim's predicate capability."""

    __tablename__ = "check_bindings"

    claim_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("claims.id", ondelete="CASCADE"))
    connection_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    capability: Mapped[str] = mapped_column(String(100))


class RunStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class CheckRun(IdMixin, CreatedAtMixin, OrgScoped, Base):
    __tablename__ = "check_runs"

    trigger: Mapped[str] = mapped_column(String(20))
    status: Mapped[RunStatus] = mapped_column(_enum(RunStatus, "run_status"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(Text)


class Observation(IdMixin, CreatedAtMixin, OrgScoped, Base):
    """One connector read, shaped as information produced by the entity (KTD7)."""

    __tablename__ = "observations"

    check_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("check_runs.id", ondelete="SET NULL")
    )
    connection_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    capability: Mapped[str] = mapped_column(String(100))
    outcome: Mapped[str] = mapped_column(String(30))
    endpoint: Mapped[str] = mapped_column(String(500))
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    total_count: Mapped[int | None] = mapped_column(Integer)
    complete: Mapped[bool] = mapped_column(Boolean, default=False)
    response_sha256: Mapped[str] = mapped_column(String(64))
    raw_response: Mapped[Any] = mapped_column(JSONB)
    scope: Mapped[list[str]] = mapped_column(JSONB, default=list)
    collector_version: Mapped[str] = mapped_column(String(50))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ItemStatus(IdMixin, OrgScoped, Base):
    """Computed freshness status, keyed by item and framework (KTD9)."""

    __tablename__ = "item_statuses"
    __table_args__ = (UniqueConstraint("item_kind", "item_id", "framework"),)

    item_kind: Mapped[str] = mapped_column(String(20))
    item_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    framework: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30))
    trusted: Mapped[bool] = mapped_column(Boolean, default=False)
    causes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Event(OrgScoped, Base):
    """Append-only, per-org hash-chained provenance record (KTD8)."""

    __tablename__ = "events"
    __table_args__ = (UniqueConstraint("org_id", "seq"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    seq: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(100))
    subject_kind: Mapped[str] = mapped_column(String(50))
    subject_id: Mapped[str] = mapped_column(String(100))
    actor_kind: Mapped[str] = mapped_column(String(10))
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    on_behalf_of_org: Mapped[bool] = mapped_column(Boolean, default=False)
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    model_id: Mapped[str | None] = mapped_column(String(100))
    prompt_version: Mapped[str | None] = mapped_column(String(100))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    payload_hash: Mapped[str] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ChainHead(Base):
    __tablename__ = "event_chain_heads"

    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("orgs.id", ondelete="CASCADE"), primary_key=True
    )
    seq: Mapped[int] = mapped_column(Integer, default=0)
    hash: Mapped[str] = mapped_column(String(64))
