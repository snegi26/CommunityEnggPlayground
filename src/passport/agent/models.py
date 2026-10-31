"""Agent run records. One row per drafting run over a document version."""

import enum
import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import Date, DateTime, ForeignKey, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from passport.db.base import Base, CreatedAtMixin, IdMixin
from passport.db.models import OrgScoped


class AgentRunStatus(enum.StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class AgentRun(IdMixin, CreatedAtMixin, OrgScoped, Base):
    """A drafting run: which model and prompt ran on which version, and what came of it.

    ``id`` is the ``run_id`` of the run's ``Agent`` actor, so every event the run writes
    links back here. ``counts`` holds proposed, accepted and discarded totals per reason.
    ``suggested_review_on`` is a suggestion read from the policy text; it never replaces
    a review date an owner set on the version.
    """

    __tablename__ = "agent_runs"

    document_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("document_versions.id", ondelete="CASCADE"), index=True
    )
    model_id: Mapped[str] = mapped_column(String(100))
    prompt_version: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default=AgentRunStatus.RUNNING.value)
    counts: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    suggested_review_on: Mapped[date | None] = mapped_column(Date)
    suggested_review_source: Mapped[str | None] = mapped_column(Text)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
