"""Per-claim outcomes of a check run (U11, KTD11).

One row per claim per run. A retried run skips claims that already have a row, so
re-running a half-finished run never reads or records their observations twice.
``detail`` holds the facts the status engine (U12) renders from: each connected
system's result, the predicate evaluation over the checkable observations, and any
reason the claim could not be checked. Rows from observations are not kept here, so
the evaluation is made once, at check time, and stored.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from passport.db.base import Base, CreatedAtMixin, IdMixin
from passport.db.models import OrgScoped


class CheckOutcome(IdMixin, CreatedAtMixin, OrgScoped, Base):
    __tablename__ = "check_outcomes"
    __table_args__ = (UniqueConstraint("check_run_id", "claim_id"),)

    check_run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("check_runs.id", ondelete="CASCADE"), index=True
    )
    claim_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("claims.id", ondelete="CASCADE"), index=True
    )
    # The claim result at check time: current, contradicted, check_failed, not_checkable.
    outcome: Mapped[str] = mapped_column(String(30))
    # Observation rows this outcome was computed from, one per connected system read.
    observation_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
