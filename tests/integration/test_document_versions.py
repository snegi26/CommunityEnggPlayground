import uuid
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from passport.db.engine import get_sessionmaker
from passport.db.models import Document, DocumentVersion, Event, EvidenceItem
from passport.db.rls import set_org_context
from passport.documents.models import DocumentSpan
from passport.documents.parsing import NO_TEXT_NOTICE, DocumentRejectedError
from passport.documents.service import (
    get_version,
    list_versions,
    read_version_bytes,
    removed_spans,
    spans_for_version,
    spans_to_draft,
    upload_evidence,
    upload_policy,
)
from passport.documents.storage import LocalDirectoryStorage
from passport.provenance.actor import Agent, AgentNotPermittedError, Human
from passport.settings import get_settings
from tests.helpers import create_org, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")

FIXTURES = Path(__file__).parents[1] / "fixtures" / "policies"
POLICY_MD = (FIXTURES / "access_control.md").read_bytes()


@pytest.fixture
def storage(tmp_path: Path) -> LocalDirectoryStorage:
    return LocalDirectoryStorage(tmp_path / "storage")


@pytest.fixture
def org() -> tuple[uuid.UUID, Human]:
    owner = sign_up()
    return create_org(owner), Human(owner.user_id)


def _session(org_id: uuid.UUID) -> Session:
    db = get_sessionmaker()()
    set_org_context(db, org_id)
    return db


def test_second_version_keeps_first_retrievable_and_links_both_to_one_document(
    org: tuple[uuid.UUID, Human], storage: LocalDirectoryStorage
) -> None:
    org_id, actor = org
    edited = POLICY_MD.replace(b"every quarter", b"every six months")
    with _session(org_id) as db:
        first = upload_policy(
            db,
            org_id=org_id,
            actor=actor,
            filename="access_control.md",
            data=POLICY_MD,
            title="Access Control Policy",
            review_due_on=date(2027, 10, 30),
            storage=storage,
        )
        second = upload_policy(
            db,
            org_id=org_id,
            actor=actor,
            filename="access_control_v2.md",
            data=edited,
            document_id=first.document.id,
            storage=storage,
        )
        db.commit()

    with _session(org_id) as db:
        assert db.scalar(select(func.count()).select_from(Document)) == 1
        versions = list_versions(db, first.document.id)
        assert [v.version_number for v in versions] == [1, 2]
        v1 = get_version(db, first.document.id, 1)
        assert v1.content_hash == first.version.content_hash
        assert v1.review_due_on == date(2027, 10, 30)
        assert read_version_bytes(v1, storage) == POLICY_MD
        assert read_version_bytes(versions[1], storage) == edited
        assert len(spans_for_version(db, v1.id)) == 6
        events = db.scalars(select(Event).order_by(Event.seq)).all()
    assert [e.event_type for e in events] == [
        "document.created",
        "document.version_uploaded",
        "document.version_uploaded",
    ]
    assert all(e.actor_kind == "human" and e.actor_user_id == actor.user_id for e in events)
    assert second.version.version_number == 2


def test_new_version_stores_span_marks_for_drafting_and_carry_forward(
    org: tuple[uuid.UUID, Human], storage: LocalDirectoryStorage
) -> None:
    org_id, actor = org
    # One paragraph edited; another differs only in whitespace.
    edited = POLICY_MD.replace(b"every quarter", b"every six months").replace(
        b"It applies to all", b"It  applies\nto all"
    )
    with _session(org_id) as db:
        first = upload_policy(
            db, org_id=org_id, actor=actor, filename="p.md", data=POLICY_MD, storage=storage
        )
        second = upload_policy(
            db,
            org_id=org_id,
            actor=actor,
            filename="p.md",
            data=edited,
            document_id=first.document.id,
            storage=storage,
        )
        db.commit()

    with _session(org_id) as db:
        assert {s.change_kind for s in spans_for_version(db, first.version.id)} == {"new"}
        spans = spans_for_version(db, second.version.id)
        kinds = [s.change_kind for s in spans]
        assert kinds.count("changed") == 1 and kinds.count("unchanged") == 5
        to_draft = spans_to_draft(db, second.version.id)
        assert [s.text for s in to_draft] == [
            "Access to production systems is reviewed every six months by the system owner."
        ]
        old_by_id = {s.id: s for s in spans_for_version(db, first.version.id)}
        for span in spans:
            assert span.previous_id is not None
            previous = old_by_id[span.previous_id]
            assert previous.document_version_id == first.version.id
            if span.change_kind == "unchanged":
                assert previous.text_key == span.text_key
        assert removed_spans(db, second.version.id) == []
    assert second.diff.removed == ()


def test_unsupported_file_type_is_rejected_and_nothing_is_stored(
    org: tuple[uuid.UUID, Human], storage: LocalDirectoryStorage
) -> None:
    org_id, actor = org
    with _session(org_id) as db:
        with pytest.raises(DocumentRejectedError, match=r"\.xlsx.*\.docx.*\.pdf"):
            upload_policy(
                db,
                org_id=org_id,
                actor=actor,
                filename="controls.xlsx",
                data=b"PK\x03\x04",
                storage=storage,
            )
        assert db.scalar(select(func.count()).select_from(DocumentVersion)) == 0
    assert not storage.root.exists()


def test_files_over_the_size_cap_are_rejected(
    org: tuple[uuid.UUID, Human], storage: LocalDirectoryStorage
) -> None:
    org_id, actor = org
    too_big = b"x" * (get_settings().max_upload_bytes + 1)
    with _session(org_id) as db:
        with pytest.raises(DocumentRejectedError, match="larger than"):
            upload_policy(
                db, org_id=org_id, actor=actor, filename="big.md", data=too_big, storage=storage
            )
        with pytest.raises(DocumentRejectedError, match="larger than"):
            upload_evidence(
                db,
                org_id=org_id,
                actor=actor,
                title="Export",
                filename="big.csv",
                data=too_big,
                source="Okta admin console",
                collected_at=datetime.now(UTC),
                storage=storage,
            )


def test_evidence_upload_records_collection_metadata_as_user_asserted(
    org: tuple[uuid.UUID, Human], storage: LocalDirectoryStorage
) -> None:
    org_id, actor = org
    collected = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)
    with _session(org_id) as db:
        item = upload_evidence(
            db,
            org_id=org_id,
            actor=actor,
            title="Q3 access review sign-off",
            filename="review.pdf",
            data=b"%PDF-1.4 evidence",
            source="Okta admin console export",
            collected_at=collected,
            storage=storage,
        )
        db.commit()

    with _session(org_id) as db:
        stored = db.get(EvidenceItem, item.id)
        assert stored is not None
        assert (stored.user_asserted, stored.source, stored.collected_at) == (
            True,
            "Okta admin console export",
            collected,
        )
        assert storage.get(stored.storage_key) == b"%PDF-1.4 evidence"
        event = db.scalars(select(Event)).one()
    assert (event.event_type, event.actor_kind, event.actor_user_id) == (
        "evidence.uploaded",
        "human",
        actor.user_id,
    )
    assert event.payload["user_asserted"] is True
    assert event.payload["collected_at"] == collected.isoformat()


def test_scanned_pdf_upload_keeps_the_version_with_no_spans_and_a_notice(
    org: tuple[uuid.UUID, Human], storage: LocalDirectoryStorage
) -> None:
    org_id, actor = org
    with _session(org_id) as db:
        result = upload_policy(
            db,
            org_id=org_id,
            actor=actor,
            filename="scan.pdf",
            data=(FIXTURES / "scanned.pdf").read_bytes(),
            storage=storage,
        )
        db.commit()
        assert result.notice == NO_TEXT_NOTICE
        assert result.spans == []
        assert spans_for_version(db, result.version.id) == []


def test_agent_cannot_upload_and_spans_are_isolated_per_org(
    org: tuple[uuid.UUID, Human], storage: LocalDirectoryStorage
) -> None:
    org_id, actor = org
    agent = Agent(run_id=uuid.uuid4(), model_id="m", prompt_version="p")
    with _session(org_id) as db:
        with pytest.raises(AgentNotPermittedError):
            upload_policy(
                db, org_id=org_id, actor=agent, filename="p.md", data=POLICY_MD, storage=storage
            )
        upload_policy(
            db, org_id=org_id, actor=actor, filename="p.md", data=POLICY_MD, storage=storage
        )
        db.commit()

    other_org = create_org(sign_up(), name="Other")
    with _session(other_org) as db:
        assert db.scalar(select(func.count()).select_from(DocumentSpan)) == 0
