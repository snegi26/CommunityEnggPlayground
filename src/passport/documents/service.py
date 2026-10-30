"""Upload policies and evidence, keep document versions, and store parsed spans (U5).

Callers set the org context (``set_org_context``) on the session first; row-level security
then confines every read and write here to that org. All uploads are human-only and append
an event naming the person (KTD8, R13).
"""

import uuid
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import PurePath

from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.db.models import Document, DocumentVersion, EvidenceItem
from passport.documents.models import DocumentSpan
from passport.documents.parsing import (
    DocumentRejectedError,
    SpanDiff,
    SpanMark,
    content_hash,
    diff_spans,
    parse_document,
)
from passport.documents.storage import ObjectStorage, get_storage
from passport.provenance.actor import Actor, require_human
from passport.provenance.service import append_event
from passport.settings import get_settings


@dataclass(frozen=True)
class PolicyUpload:
    document: Document
    version: DocumentVersion
    spans: list[DocumentSpan]
    diff: SpanDiff
    # "No text found" notice when the file yielded no spans (for example a scanned PDF).
    notice: str | None


def _check_size(data: bytes) -> None:
    cap = get_settings().max_upload_bytes
    if len(data) > cap:
        raise DocumentRejectedError(
            f"File is larger than the {cap // (1024 * 1024)} MB upload limit ({len(data)} bytes)."
        )


def upload_policy(
    session: Session,
    *,
    org_id: uuid.UUID,
    actor: Actor,
    filename: str,
    data: bytes,
    title: str | None = None,
    document_id: uuid.UUID | None = None,
    review_due_on: date | None = None,
    storage: ObjectStorage | None = None,
) -> PolicyUpload:
    """Store a policy file as version 1 of a new document, or the next version of one.

    The new version's spans are diffed against the previous version's and each span is
    stored with its mark (unchanged, changed, new). Raises ``DocumentRejectedError`` for an
    unsupported type or an oversized file, before anything is written.
    """
    require_human(actor)
    _check_size(data)
    parsed = parse_document(filename, data)

    if document_id is None:
        document = Document(org_id=org_id, title=title or PurePath(filename).stem)
        session.add(document)
        session.flush()
        append_event(
            session,
            org_id=org_id,
            actor=actor,
            event_type="document.created",
            subject_kind="document",
            subject_id=document.id,
            payload={"title": document.title},
        )
        previous: DocumentVersion | None = None
    else:
        # Lock the document so concurrent uploads number their versions in turn.
        found = session.scalars(
            select(Document).where(Document.id == document_id).with_for_update()
        ).one_or_none()
        if found is None:
            raise LookupError(f"document {document_id} not found")
        document = found
        previous = session.scalars(
            select(DocumentVersion)
            .where(DocumentVersion.document_id == document.id)
            .order_by(DocumentVersion.version_number.desc())
            .limit(1)
        ).one_or_none()

    key = (storage or get_storage()).put(org_id, data)
    version = DocumentVersion(
        org_id=org_id,
        document_id=document.id,
        version_number=(previous.version_number + 1) if previous else 1,
        filename=filename,
        content_hash=parsed.content_hash,
        storage_key=key,
        review_due_on=review_due_on,
    )
    session.add(version)
    session.flush()

    previous_spans = spans_for_version(session, previous.id) if previous else []
    if previous is None:
        diff = SpanDiff(
            marks=tuple(SpanMark(s.span_id, "new", None) for s in parsed.spans), removed=()
        )
    else:
        diff = diff_spans(previous_spans, parsed.spans)
    previous_rows = {s.span_id: s.id for s in previous_spans}
    rows = []
    for span, mark in zip(parsed.spans, diff.marks, strict=True):
        rows.append(
            DocumentSpan(
                org_id=org_id,
                document_version_id=version.id,
                span_id=span.span_id,
                section_path=list(span.section_path),
                paragraph_index=span.paragraph_index,
                char_start=span.char_start,
                char_end=span.char_end,
                text=span.text,
                text_key=span.text_key,
                change_kind=mark.kind,
                previous_id=previous_rows[mark.previous_span_id] if mark.previous_span_id else None,
            )
        )
    session.add_all(rows)
    session.flush()

    kinds = [m.kind for m in diff.marks]
    append_event(
        session,
        org_id=org_id,
        actor=actor,
        event_type="document.version_uploaded",
        subject_kind="document_version",
        subject_id=version.id,
        payload={
            "document_id": str(document.id),
            "version_number": version.version_number,
            "filename": filename,
            "content_hash": version.content_hash,
            "review_due_on": review_due_on.isoformat() if review_due_on else None,
            "spans": len(rows),
            "unchanged": kinds.count("unchanged"),
            "changed": kinds.count("changed"),
            "new": kinds.count("new"),
            "removed": len(diff.removed),
            "no_text_found": parsed.notice is not None,
        },
    )
    return PolicyUpload(document, version, rows, diff, parsed.notice)


def list_versions(session: Session, document_id: uuid.UUID) -> list[DocumentVersion]:
    return list(
        session.scalars(
            select(DocumentVersion)
            .where(DocumentVersion.document_id == document_id)
            .order_by(DocumentVersion.version_number)
        )
    )


def get_version(session: Session, document_id: uuid.UUID, version_number: int) -> DocumentVersion:
    return session.scalars(
        select(DocumentVersion).where(
            DocumentVersion.document_id == document_id,
            DocumentVersion.version_number == version_number,
        )
    ).one()


def read_version_bytes(version: DocumentVersion, storage: ObjectStorage | None = None) -> bytes:
    return (storage or get_storage()).get(version.storage_key)


def spans_for_version(session: Session, version_id: uuid.UUID) -> list[DocumentSpan]:
    return list(
        session.scalars(
            select(DocumentSpan)
            .where(DocumentSpan.document_version_id == version_id)
            .order_by(DocumentSpan.paragraph_index)
        )
    )


def spans_to_draft(session: Session, version_id: uuid.UUID) -> list[DocumentSpan]:
    """Spans that are new or changed in this version: the only ones drafting sees (KTD14)."""
    return [s for s in spans_for_version(session, version_id) if s.change_kind != "unchanged"]


def removed_spans(session: Session, version_id: uuid.UUID) -> list[DocumentSpan]:
    """Previous-version spans with no counterpart in this version."""
    version = session.get(DocumentVersion, version_id)
    if version is None or version.version_number == 1:
        return []
    previous = get_version(session, version.document_id, version.version_number - 1)
    carried = {s.previous_id for s in spans_for_version(session, version_id)}
    return [s for s in spans_for_version(session, previous.id) if s.id not in carried]


def upload_evidence(
    session: Session,
    *,
    org_id: uuid.UUID,
    actor: Actor,
    title: str,
    filename: str,
    data: bytes,
    source: str,
    collected_at: datetime,
    storage: ObjectStorage | None = None,
) -> EvidenceItem:
    """Store an evidence file with its collection metadata, asserted by the uploader (R13)."""
    require_human(actor)
    _check_size(data)
    key = (storage or get_storage()).put(org_id, data)
    item = EvidenceItem(
        org_id=org_id,
        title=title,
        filename=filename,
        content_hash=content_hash(data),
        storage_key=key,
        source=source,
        collected_at=collected_at,
        user_asserted=True,
    )
    session.add(item)
    session.flush()
    append_event(
        session,
        org_id=org_id,
        actor=actor,
        event_type="evidence.uploaded",
        subject_kind="evidence_item",
        subject_id=item.id,
        payload={
            "title": title,
            "filename": filename,
            "content_hash": item.content_hash,
            "source": source,
            "collected_at": collected_at.isoformat(),
            "user_asserted": True,
        },
    )
    return item
