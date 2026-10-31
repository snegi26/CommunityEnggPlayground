"""Weekly reports (U13). One per check run; the last sent one is the next diff baseline."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from passport.db.base import Base, CreatedAtMixin, IdMixin
from passport.db.models import OrgScoped


class WeeklyReport(IdMixin, CreatedAtMixin, OrgScoped, Base):
    __tablename__ = "weekly_reports"

    # Unique: a retried job reuses the run's report instead of building and mailing twice.
    check_run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("check_runs.id", ondelete="CASCADE"), unique=True
    )
    # Set only after the mailer accepted every message; unsent reports are never a baseline.
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Item statuses at build time, keyed "kind:item_id:framework": the next diff baseline.
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    sections: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    coverage: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
