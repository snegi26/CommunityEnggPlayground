"""Parsed policy spans per document version, with their diff against the prior version."""

import uuid
from typing import Literal

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from passport.db.base import Base, CreatedAtMixin, IdMixin
from passport.db.models import OrgScoped

SpanChangeKind = Literal["unchanged", "changed", "new"]


class DocumentSpan(IdMixin, CreatedAtMixin, OrgScoped, Base):
    """One body paragraph of a document version (KTD14).

    ``span_id`` is what claims cite; ``text_key`` is the version-independent key the F3 diff
    compares. ``change_kind`` is relative to the previous version (all ``new`` for v1), and
    ``previous_id`` is the previous version's span this one corresponds to.
    """

    __tablename__ = "document_spans"
    __table_args__ = (UniqueConstraint("document_version_id", "span_id"),)

    document_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("document_versions.id", ondelete="CASCADE"), index=True
    )
    span_id: Mapped[str] = mapped_column(String(200))
    section_path: Mapped[list[str]] = mapped_column(JSONB, default=list)
    paragraph_index: Mapped[int] = mapped_column(Integer)
    char_start: Mapped[int] = mapped_column(Integer)
    char_end: Mapped[int] = mapped_column(Integer)
    text: Mapped[str] = mapped_column(Text)
    text_key: Mapped[str] = mapped_column(String(64))
    change_kind: Mapped[str] = mapped_column(String(10))
    previous_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("document_spans.id", ondelete="SET NULL")
    )
