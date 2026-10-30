"""F3 version matching (U10, KTD14): which claims carry over to a new policy version."""

import uuid
from dataclasses import dataclass

import pytest

import passport.predicates.definitions  # noqa: F401  (registers v1 predicates)
from passport.claims.matching import SpanLink, current_revisions, plan_carry_over
from passport.claims.service import preview_check
from passport.predicates.registry import InvalidParametersError, UnknownPredicateError


@dataclass(frozen=True)
class FakeClaim:
    id: uuid.UUID
    span_id: str
    revision_of: uuid.UUID | None = None


def _claim(span_id: str, revision_of: uuid.UUID | None = None) -> FakeClaim:
    return FakeClaim(uuid.uuid4(), span_id, revision_of)


def test_claims_on_unchanged_spans_carry_to_the_new_span_id() -> None:
    a, b = _claim("v1:a"), _claim("v1:b")
    spans = [SpanLink("v2:a", "unchanged", "v1:a"), SpanLink("v2:b", "unchanged", "v1:b")]

    plan = plan_carry_over(spans, [a, b])

    assert [(c.claim, c.to_span_id) for c in plan] == [(a, "v2:a"), (b, "v2:b")]


def test_claims_on_changed_new_or_removed_spans_never_carry() -> None:
    changed, removed = _claim("v1:changed"), _claim("v1:removed")
    spans = [SpanLink("v2:changed", "changed", "v1:changed"), SpanLink("v2:new", "new", None)]

    assert plan_carry_over(spans, [changed, removed]) == []


def test_every_claim_on_an_unchanged_span_carries_in_order() -> None:
    first, second, other = _claim("v1:a"), _claim("v1:a"), _claim("v1:b")
    spans = [SpanLink("v2:b", "unchanged", "v1:b"), SpanLink("v2:a", "unchanged", "v1:a")]

    plan = plan_carry_over(spans, [first, second, other])

    assert [c.claim for c in plan] == [other, first, second]


def test_only_the_latest_revision_of_an_edited_claim_carries() -> None:
    original = _claim("v1:a")
    edited = _claim("v1:a", revision_of=original.id)

    assert current_revisions([original, edited]) == [edited]
    plan = plan_carry_over([SpanLink("v2:a", "unchanged", "v1:a")], [original, edited])
    assert [c.claim for c in plan] == [edited]


def test_preview_describes_the_check_with_the_latest_predicate_version() -> None:
    preview = preview_check(
        "password_min_length", {"scope": "all_production_accounts", "min_length": 14}
    )

    assert preview.predicate_id == "password_min_length"
    assert preview.predicate_version == 1
    assert preview.parameters == {"scope": "all_production_accounts", "min_length": 14}
    assert "at least 14 characters" in preview.check_description
    assert "every production AWS account" in preview.check_description


def test_preview_rejects_unknown_predicates_and_invalid_parameters() -> None:
    with pytest.raises(UnknownPredicateError):
        preview_check("no_such_predicate", {"scope": "all_accounts"})
    with pytest.raises(InvalidParametersError):
        preview_check("password_min_length", {"scope": "all_accounts", "min_length": 0})
