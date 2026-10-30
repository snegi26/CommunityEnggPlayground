"""Parse uploaded policies into addressable spans and diff spans across versions (KTD14).

A span is one body paragraph: its section heading path, its paragraph index, its character
offsets into the version's extracted text, and its whitespace-normalized text. The span id
is derived from the version's content hash, section path and offsets, so it is stable for
one file and distinct across versions; ``text_key`` is the version-independent key that the
F3 diff (R20) compares.

Formats: PDF (``pypdf``, headings inferred from font size), DOCX (``python-docx``, heading
styles), Markdown (ATX ``#`` headings) and plain text (paragraphs only). No OCR in v1.
"""

import hashlib
import io
import itertools
import json
import re
from collections import defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any, Literal, Protocol

import docx
import pypdf

SUPPORTED_EXTENSIONS: dict[str, str] = {
    ".docx": "docx",
    ".markdown": "markdown",
    ".md": "markdown",
    ".pdf": "pdf",
    ".txt": "text",
}

NO_TEXT_NOTICE = (
    "No text found in this file. It may be a scanned image; upload a text-based PDF, "
    "DOCX or Markdown version so claims can be drafted from it."
)

_PARAGRAPH_SEPARATOR = "\n\n"


class DocumentRejectedError(ValueError):
    """An upload was refused (unsupported type or over the size cap); the message says why."""


def supported_types_text() -> str:
    return ", ".join(sorted(SUPPORTED_EXTENSIONS))


def detect_format(filename: str) -> str:
    extension = PurePath(filename).suffix.lower()
    try:
        return SUPPORTED_EXTENSIONS[extension]
    except KeyError:
        shown = extension or "(no extension)"
        raise DocumentRejectedError(
            f"Unsupported file type '{shown}'. Supported policy types: {supported_types_text()}."
        ) from None


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def text_key(text: str) -> str:
    """Version-independent key of a span: the hash of its whitespace-normalized text."""
    return hashlib.sha256(normalize_whitespace(text).encode()).hexdigest()


def span_id_for(version_hash: str, section_path: Sequence[str], start: int, end: int) -> str:
    material = json.dumps([version_hash, list(section_path), start, end], separators=(",", ":"))
    return "sp_" + hashlib.sha256(material.encode()).hexdigest()[:40]


@dataclass(frozen=True)
class Block:
    """One heading or paragraph in reading order, before span assembly."""

    kind: Literal["heading", "paragraph"]
    text: str
    level: int = 0


@dataclass(frozen=True)
class ParsedSpan:
    span_id: str
    section_path: tuple[str, ...]
    paragraph_index: int
    char_start: int
    char_end: int
    text: str
    text_key: str


@dataclass(frozen=True)
class ParseResult:
    content_hash: str
    # Extracted text the span offsets index into: normalized blocks joined by blank lines.
    text: str
    spans: tuple[ParsedSpan, ...]
    # Set when the file parsed but yielded no text (for example a scanned PDF).
    notice: str | None


def parse_document(filename: str, data: bytes) -> ParseResult:
    kind = detect_format(filename)
    if kind == "pdf":
        blocks = _pdf_blocks(data)
    elif kind == "docx":
        blocks = _docx_blocks(data)
    else:
        blocks = _markdown_blocks(data.decode("utf-8", errors="replace"), kind == "markdown")
    return assemble_spans(content_hash(data), blocks)


def assemble_spans(version_hash: str, blocks: Sequence[Block]) -> ParseResult:
    parts: list[str] = []
    offset = 0
    headings: list[tuple[int, str]] = []
    spans: list[ParsedSpan] = []
    for block in blocks:
        text = normalize_whitespace(block.text)
        if not text:
            continue
        if parts:
            offset += len(_PARAGRAPH_SEPARATOR)
        start, end = offset, offset + len(text)
        parts.append(text)
        offset = end
        if block.kind == "heading":
            while headings and headings[-1][0] >= block.level:
                headings.pop()
            headings.append((block.level, text))
            continue
        path = tuple(h for _, h in headings)
        spans.append(
            ParsedSpan(
                span_id=span_id_for(version_hash, path, start, end),
                section_path=path,
                paragraph_index=len(spans),
                char_start=start,
                char_end=end,
                text=text,
                text_key=text_key(text),
            )
        )
    return ParseResult(
        content_hash=version_hash,
        text=_PARAGRAPH_SEPARATOR.join(parts),
        spans=tuple(spans),
        notice=None if spans else NO_TEXT_NOTICE,
    )


# --- Markdown and plain text ---------------------------------------------------------

_ATX_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")


def _markdown_blocks(text: str, headings: bool) -> list[Block]:
    blocks: list[Block] = []
    lines: list[str] = []

    def flush() -> None:
        if lines:
            blocks.append(Block("paragraph", " ".join(lines)))
            lines.clear()

    for line in text.splitlines():
        heading = _ATX_HEADING.match(line) if headings else None
        if heading:
            flush()
            blocks.append(Block("heading", heading.group(2), len(heading.group(1))))
        elif not line.strip():
            flush()
        else:
            if headings and _LIST_ITEM.match(line):
                flush()
            lines.append(line.strip())
    flush()
    return blocks


# --- DOCX ----------------------------------------------------------------------------

_HEADING_STYLE = re.compile(r"^heading\s*(\d*)$", re.IGNORECASE)


def _docx_blocks(data: bytes) -> list[Block]:
    blocks: list[Block] = []
    for paragraph in docx.Document(io.BytesIO(data)).paragraphs:
        style = (paragraph.style.name if paragraph.style is not None else "") or ""
        heading = _HEADING_STYLE.match(style.strip())
        if style.strip().lower() == "title":
            blocks.append(Block("heading", paragraph.text, 0))
        elif heading:
            blocks.append(Block("heading", paragraph.text, int(heading.group(1) or 1)))
        else:
            blocks.append(Block("paragraph", paragraph.text))
    return blocks


# --- PDF -----------------------------------------------------------------------------


@dataclass
class _Line:
    page: int
    y: float
    size: float
    text: str


def _pdf_lines(data: bytes) -> list[_Line]:
    lines: list[_Line] = []
    for page_number, page in enumerate(pypdf.PdfReader(io.BytesIO(data)).pages):

        def visit(
            text: str,
            cm: list[float],
            tm: list[float],
            font_dict: Any,
            font_size: float,
            page_number: int = page_number,
        ) -> None:
            if not text.strip():
                return
            y = tm[4] * cm[1] + tm[5] * cm[3] + cm[5]
            size = round(font_size * (abs(tm[3] * cm[3]) or 1.0), 1)
            last = lines[-1] if lines else None
            if last and last.page == page_number and abs(last.y - y) < 1.0:
                last.text += text
                last.size = max(last.size, size)
            else:
                lines.append(_Line(page_number, y, size, text))

        page.extract_text(visitor_text=visit)
    return lines


def _join_wrapped(left: str, right: str) -> str:
    left, right = left.rstrip(), right.strip()
    # A line ending in a hyphen keeps it ("break-" + "glass"); other wraps get a space.
    return left + right if left.endswith("-") else f"{left} {right}"


def _pdf_blocks(data: bytes) -> list[Block]:
    lines = [line for line in _pdf_lines(data) if line.text.strip()]
    if not lines:
        return []
    chars_by_size: dict[float, int] = defaultdict(int)
    for line in lines:
        chars_by_size[line.size] += len(line.text)
    body_size = max(chars_by_size, key=lambda s: (chars_by_size[s], -s))
    heading_sizes = sorted((s for s in chars_by_size if s > body_size * 1.1), reverse=True)
    gaps = [
        prev.y - cur.y
        for prev, cur in itertools.pairwise(lines)
        if prev.page == cur.page and prev.size == cur.size == body_size and prev.y > cur.y
    ]
    # Line spacing within a paragraph: the tightest ordinary gap between body lines.
    leading = min((g for g in gaps if g >= body_size * 0.8), default=body_size * 1.2)

    blocks: list[Block] = []
    current: _Line | None = None
    text = ""

    def flush() -> None:
        if current is None:
            return
        if current.size in heading_sizes:
            blocks.append(Block("heading", text, heading_sizes.index(current.size) + 1))
        else:
            blocks.append(Block("paragraph", text))

    for line in lines:
        limit = line.size * 1.5 if line.size in heading_sizes else leading * 1.3
        continues = (
            current is not None
            and line.page == current.page
            and line.size == current.size
            and 0 < current.y - line.y <= limit
        )
        if continues:
            text = _join_wrapped(text, line.text)
            current = _Line(line.page, line.y, line.size, "")
        else:
            flush()
            current = _Line(line.page, line.y, line.size, "")
            text = line.text.strip()
    flush()
    return blocks


# --- version diff (F3, R20) ----------------------------------------------------------


class SpanLike(Protocol):
    @property
    def span_id(self) -> str: ...

    @property
    def section_path(self) -> Sequence[str]: ...

    @property
    def text_key(self) -> str: ...


ChangeKind = Literal["unchanged", "changed", "new"]


@dataclass(frozen=True)
class SpanMark:
    span_id: str
    kind: ChangeKind
    # The previous version's span this one corresponds to (unchanged or changed).
    previous_span_id: str | None


@dataclass(frozen=True)
class SpanDiff:
    marks: tuple[SpanMark, ...]
    # Previous-version span ids with no counterpart in the new version.
    removed: tuple[str, ...]


def diff_spans(previous: Sequence[SpanLike], current: Sequence[SpanLike]) -> SpanDiff:
    """Mark each current span unchanged, changed or new against the previous version.

    Unchanged: same whitespace-normalized text as an unmatched previous span (in order, so
    moved paragraphs still match). Changed: an unmatched span paired in order with an
    unmatched previous span in the same section. Everything else is new or removed.
    """
    by_key: dict[str, deque[int]] = defaultdict(deque)
    for index, span in enumerate(previous):
        by_key[span.text_key].append(index)
    pairs: dict[int, int] = {}
    for index, span in enumerate(current):
        if by_key[span.text_key]:
            pairs[index] = by_key[span.text_key].popleft()
    unchanged = set(pairs)

    leftover_by_section: dict[tuple[str, ...], deque[int]] = defaultdict(deque)
    matched_previous = set(pairs.values())
    for index, span in enumerate(previous):
        if index not in matched_previous:
            leftover_by_section[tuple(span.section_path)].append(index)
    for index, span in enumerate(current):
        if index not in pairs and leftover_by_section[tuple(span.section_path)]:
            pairs[index] = leftover_by_section[tuple(span.section_path)].popleft()

    marks = []
    for index, span in enumerate(current):
        if index in unchanged:
            kind: ChangeKind = "unchanged"
        elif index in pairs:
            kind = "changed"
        else:
            kind = "new"
        prev = pairs.get(index)
        marks.append(
            SpanMark(span.span_id, kind, previous[prev].span_id if prev is not None else None)
        )
    paired = set(pairs.values())
    removed = tuple(s.span_id for i, s in enumerate(previous) if i not in paired)
    return SpanDiff(marks=tuple(marks), removed=removed)
