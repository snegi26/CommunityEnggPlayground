from pathlib import Path

import pytest

from passport.documents.parsing import (
    NO_TEXT_NOTICE,
    DocumentRejectedError,
    diff_spans,
    normalize_whitespace,
    parse_document,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "policies"


def test_docx_with_three_headings_yields_spans_with_ids_stable_across_parses() -> None:
    data = (FIXTURES / "access_control.docx").read_bytes()

    first = parse_document("access_control.docx", data)
    second = parse_document("access_control.docx", data)

    assert len(first.spans) == 6
    assert {s.section_path for s in first.spans} == {
        ("Purpose",),
        ("Multi-factor Authentication",),
        ("Access Reviews",),
    }
    assert [s.span_id for s in first.spans] == [s.span_id for s in second.spans]
    assert len({s.span_id for s in first.spans}) == 6
    assert first.notice is None


def test_span_ids_depend_on_the_version_content_but_text_keys_do_not() -> None:
    data = (FIXTURES / "access_control.md").read_bytes()

    original = parse_document("a.md", data)
    resaved = parse_document("a.md", data + b"\n\n")

    assert [s.span_id for s in original.spans] != [s.span_id for s in resaved.spans]
    assert [s.text_key for s in original.spans] == [s.text_key for s in resaved.spans]


def test_spans_record_offsets_into_the_extracted_text() -> None:
    result = parse_document("p.md", b"# Scope\n\nFirst   paragraph\nwraps.\n\nSecond one.\n")

    first, second = result.spans
    assert (first.text, first.section_path, first.paragraph_index) == (
        "First paragraph wraps.",
        ("Scope",),
        0,
    )
    assert result.text[first.char_start : first.char_end] == first.text
    assert result.text[second.char_start : second.char_end] == "Second one."
    assert second.paragraph_index == 1


def test_pdf_and_markdown_of_the_same_policy_yield_the_same_span_texts() -> None:
    pdf = parse_document("access_control.pdf", (FIXTURES / "access_control.pdf").read_bytes())
    md = parse_document("access_control.md", (FIXTURES / "access_control.md").read_bytes())

    assert len(md.spans) == 6
    assert [normalize_whitespace(s.text) for s in pdf.spans] == [
        normalize_whitespace(s.text) for s in md.spans
    ]
    assert [s.section_path for s in pdf.spans] == [s.section_path for s in md.spans]


def test_scanned_pdf_yields_no_spans_and_a_no_text_notice() -> None:
    result = parse_document("scan.pdf", (FIXTURES / "scanned.pdf").read_bytes())

    assert result.spans == ()
    assert result.notice == NO_TEXT_NOTICE
    assert "no text found" in NO_TEXT_NOTICE.lower()


def test_unsupported_file_type_is_rejected_naming_supported_types() -> None:
    with pytest.raises(DocumentRejectedError) as raised:
        parse_document("controls.xlsx", b"PK\x03\x04")

    message = str(raised.value)
    assert ".xlsx" in message
    for supported in (".pdf", ".docx", ".md", ".txt"):
        assert supported in message


def test_editing_one_paragraph_marks_only_that_span_changed() -> None:
    md = (FIXTURES / "access_control.md").read_text()
    edited = md.replace("every quarter", "every six months").replace(
        "It applies to all", "It   applies\nto  all"
    )
    old = parse_document("v1.md", md.encode())
    new = parse_document("v2.md", edited.encode())

    diff = diff_spans(old.spans, new.spans)

    kinds = [mark.kind for mark in diff.marks]
    assert kinds.count("changed") == 1
    assert kinds.count("unchanged") == 5
    changed = next(m for m in diff.marks if m.kind == "changed")
    changed_span = next(s for s in new.spans if s.span_id == changed.span_id)
    assert "every six months" in changed_span.text
    old_reviews = next(s for s in old.spans if "every quarter" in s.text)
    assert changed.previous_span_id == old_reviews.span_id
    for mark in diff.marks:
        if mark.kind == "unchanged":
            prev = next(s for s in old.spans if s.span_id == mark.previous_span_id)
            cur = next(s for s in new.spans if s.span_id == mark.span_id)
            assert prev.text_key == cur.text_key
    assert diff.removed == ()


def test_added_and_removed_paragraphs_are_reported() -> None:
    old = parse_document("v1.md", b"# A\n\nKeep me.\n\nDrop me.\n\n# B\n\nOther.\n")
    new = parse_document("v2.md", b"# A\n\nKeep me.\n\n# C\n\nBrand new.\n\n# B\n\nOther.\n")

    diff = diff_spans(old.spans, new.spans)

    assert [m.kind for m in diff.marks] == ["unchanged", "new", "unchanged"]
    assert diff.removed == (old.spans[1].span_id,)
