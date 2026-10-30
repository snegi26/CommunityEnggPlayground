"""The drafting agent's tools, created per run with one org and one version bound in (KTD10).

The model can read spans of the run's document version, list the registered predicates, and
propose claims. Nothing here confirms, approves, or edits a claim: those operations do not
exist on the agent's side, and proposals are only collected for code to verify (KTD4).
"""

import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from anthropic.types.beta import BetaToolParam
from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.documents.models import DocumentSpan
from passport.predicates.registry import Predicate, PredicateRegistry

UNSUPPORTED = "unsupported"

READ_SPAN = "read_span"
LIST_PREDICATES = "list_predicates"
PROPOSE_CLAIMS = "propose_claims"

# JSON Schema keywords strict tool schemas do not accept; validation re-checks them in code.
_UNSUPPORTED_KEYWORDS = frozenset(
    {
        "title",
        "default",
        "description",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minItems",
        "maxItems",
    }
)


@dataclass(frozen=True)
class SpanText:
    span_id: str
    section_path: tuple[str, ...]
    text: str


class SpanSource(Protocol):
    """Where a run reads spans from; every lookup is confined to one version."""

    def get(self, span_id: str) -> SpanText | None: ...


class VersionSpans:
    """Spans of one document version in one org, read from the database.

    The query filters on both ids, and row-level security on ``document_spans`` confines
    the session to its org context, so a span id from another org or version is not found.
    """

    def __init__(self, session: Session, *, org_id: uuid.UUID, version_id: uuid.UUID) -> None:
        self._session = session
        self._org_id = org_id
        self._version_id = version_id

    def get(self, span_id: str) -> SpanText | None:
        row = self._session.scalars(
            select(DocumentSpan).where(
                DocumentSpan.org_id == self._org_id,
                DocumentSpan.document_version_id == self._version_id,
                DocumentSpan.span_id == span_id,
            )
        ).one_or_none()
        if row is None:
            return None
        return SpanText(row.span_id, tuple(row.section_path), row.text)


class InMemorySpans:
    """Spans held in memory (the eval suite drafts from parsed fixtures with no database)."""

    def __init__(self, spans: Iterable[SpanText]) -> None:
        self._spans = {s.span_id: s for s in spans}

    def get(self, span_id: str) -> SpanText | None:
        return self._spans.get(span_id)


@dataclass(frozen=True)
class Proposal:
    """One claim as the model proposed it, before any verification."""

    span_id: str
    quote: str
    predicate: str
    parameters: Mapping[str, Any]
    rationale: str


@dataclass(frozen=True)
class ToolResult:
    content: str
    is_error: bool = False


def _strict(schema: Any) -> Any:
    """Drop keywords strict mode rejects and close every object schema."""
    if isinstance(schema, list):
        return [_strict(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    out = {k: _strict(v) for k, v in schema.items() if k not in _UNSUPPORTED_KEYWORDS}
    if out.get("type") == "object":
        out["additionalProperties"] = False
        out["required"] = sorted(out.get("properties", {}))
    return out


def parameters_schema(predicate: Predicate[Any]) -> dict[str, Any]:
    """The predicate's parameter schema, with ``scope`` limited to its rule's keywords."""
    schema: dict[str, Any] = _strict(predicate.params_model.model_json_schema())
    schema["properties"]["scope"] = {
        "anyOf": [
            {"type": "string", "enum": sorted(predicate.scope_rule.keywords)},
            {"type": "array", "items": {"type": "string"}},
        ]
    }
    return schema


def _claim_variant(predicate_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "span_id": {"type": "string"},
            "quote": {"type": "string"},
            "predicate": {"type": "string", "enum": [predicate_id]},
            "parameters": parameters,
            "rationale": {"type": "string"},
        },
        "required": ["parameters", "predicate", "quote", "rationale", "span_id"],
        "additionalProperties": False,
    }


def latest_predicates(registry: PredicateRegistry) -> list[Predicate[Any]]:
    return [registry.latest(pid) for pid in sorted({p.id for p in registry.all()})]


def propose_claims_schema(registry: PredicateRegistry) -> dict[str, Any]:
    """One claim variant per registered predicate, plus ``unsupported`` with no parameters."""
    variants = [_claim_variant(p.id, parameters_schema(p)) for p in latest_predicates(registry)]
    variants.append(
        _claim_variant(
            UNSUPPORTED,
            {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        )
    )
    return {
        "type": "object",
        "properties": {"claims": {"type": "array", "items": {"anyOf": variants}}},
        "required": ["claims"],
        "additionalProperties": False,
    }


def predicate_catalog(registry: PredicateRegistry) -> list[dict[str, Any]]:
    """What the model is told about each predicate: its meaning and its parameters."""
    catalog = []
    for predicate in latest_predicates(registry):
        catalog.append(
            {
                "id": predicate.id,
                "title": predicate.title,
                "checks": predicate.description_template,
                "scope_keywords": dict(sorted(predicate.scope_rule.keywords.items())),
                "scope_named_identifiers": predicate.scope_rule.named_plural,
                "other_parameters": {
                    name: str(info.annotation)
                    for name, info in predicate.params_model.model_fields.items()
                    if name != "scope"
                },
            }
        )
    return catalog


class DraftingTools:
    """The tool set for one drafting run. Construct one per run; do not share across runs."""

    def __init__(self, spans: SpanSource, registry: PredicateRegistry) -> None:
        self._spans = spans
        self._registry = registry
        self.proposals: list[Proposal] = []
        # Proposals whose shape was unusable (missing fields, wrong types).
        self.malformed = 0

    def definitions(self) -> list[BetaToolParam]:
        return [
            {
                "name": READ_SPAN,
                "description": (
                    "Read one span (paragraph) of the policy version being drafted, by span"
                    " id. Returns its section path and text, or an error if no such span"
                    " exists in this version."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {"span_id": {"type": "string"}},
                    "required": ["span_id"],
                    "additionalProperties": False,
                },
                "strict": True,
            },
            {
                "name": LIST_PREDICATES,
                "description": (
                    "List the checkable claim types (predicates): id, what each checks, its"
                    " scope keywords, and its other parameters."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False,
                },
                "strict": True,
            },
            {
                "name": PROPOSE_CLAIMS,
                "description": (
                    "Submit the drafted claims. Each claim cites one span id, quotes the exact"
                    " policy words it rests on, and names a predicate with its parameters, or"
                    " 'unsupported' when the requirement fits no predicate. Drafts are checked"
                    " by code and reviewed by a person; this tool cannot confirm anything."
                ),
                "input_schema": propose_claims_schema(self._registry),
                "strict": True,
            },
        ]

    def execute(self, name: str, tool_input: Mapping[str, Any]) -> ToolResult:
        if name == READ_SPAN:
            return self._read_span(tool_input)
        if name == LIST_PREDICATES:
            return ToolResult(json.dumps(predicate_catalog(self._registry)))
        if name == PROPOSE_CLAIMS:
            return self._propose(tool_input)
        return ToolResult(f"unknown tool {name!r}", is_error=True)

    def _read_span(self, tool_input: Mapping[str, Any]) -> ToolResult:
        span_id = tool_input.get("span_id")
        span = self._spans.get(span_id) if isinstance(span_id, str) else None
        if span is None:
            return ToolResult(f"span {span_id!r} not found in this document version", True)
        return ToolResult(
            json.dumps(
                {"span_id": span.span_id, "section": list(span.section_path), "text": span.text}
            )
        )

    def _propose(self, tool_input: Mapping[str, Any]) -> ToolResult:
        claims = tool_input.get("claims")
        if not isinstance(claims, list):
            return ToolResult("'claims' must be a list", is_error=True)
        received = 0
        for raw in claims:
            proposal = _proposal(raw)
            if proposal is None:
                self.malformed += 1
                continue
            self.proposals.append(proposal)
            received += 1
        return ToolResult(f"received {received} draft claims for verification and human review")


def _proposal(raw: Any) -> Proposal | None:
    if not isinstance(raw, Mapping):
        return None
    fields = ("span_id", "quote", "predicate", "rationale")
    if not all(isinstance(raw.get(f), str) for f in fields):
        return None
    parameters = raw.get("parameters", {})
    if not isinstance(parameters, Mapping):
        return None
    return Proposal(
        span_id=raw["span_id"],
        quote=raw["quote"],
        predicate=raw["predicate"],
        parameters=dict(parameters),
        rationale=raw["rationale"],
    )


def spans_payload(spans: Sequence[SpanText]) -> str:
    """Spans as JSON, so no policy text can close or escape the data block it sits in."""
    return json.dumps(
        [{"span_id": s.span_id, "section": list(s.section_path), "text": s.text} for s in spans],
        indent=1,
    )
