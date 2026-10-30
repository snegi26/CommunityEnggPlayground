"""Observations carry the IPE fields of KTD7; failures are typed outcomes."""

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone

import pytest

from passport.connectors.base import Capability
from passport.connectors.observation import Failure, FailureKind, Observed


def _observed(rows: list[dict[str, object]], **kwargs: object) -> Observed:
    defaults: dict[str, object] = {
        "capability": Capability.LIST_USERS_MFA,
        "endpoint": "iam:GetCredentialReport",
        "parameters": {},
        "rows": rows,
        "raw_response": {"users": rows},
        "collector_version": "aws-1",
        "collected_at": datetime(2026, 10, 30, 12, tzinfo=UTC),
        "scope": ("111111111111",),
    }
    defaults.update(kwargs)
    return Observed(**defaults)  # type: ignore[arg-type]


def test_received_rows_fewer_than_the_reported_total_are_flagged_incomplete() -> None:
    obs = _observed([{"user": "a", "mfa": True}], total_count=2)
    assert obs.row_count == 1
    assert obs.total_count == 2
    assert obs.complete is False


def test_received_rows_matching_the_reported_total_are_complete() -> None:
    obs = _observed([{"user": "a", "mfa": True}, {"user": "b", "mfa": False}], total_count=2)
    assert obs.complete is True


def test_unfinished_pagination_is_incomplete_even_without_a_reported_total() -> None:
    obs = _observed([{"user": "a", "mfa": True}], pagination_complete=False)
    assert obs.total_count is None
    assert obs.complete is False


def test_an_empty_user_list_is_an_explicitly_empty_observation() -> None:
    obs = _observed([], total_count=0)
    assert obs.row_count == 0
    assert obs.is_empty is True
    # Emptiness is reported, never collapsed into "no offenders" (KTD7).
    assert obs.checkable is False


def test_a_complete_non_empty_observation_is_checkable() -> None:
    obs = _observed([{"user": "a", "mfa": True}])
    assert obs.is_empty is False
    assert obs.checkable is True


def test_an_incomplete_observation_is_not_checkable() -> None:
    assert _observed([{"user": "a"}], total_count=3).checkable is False


def test_response_hash_is_sha256_of_the_canonical_raw_response() -> None:
    raw = {"b": [1, 2], "a": "x"}
    obs = _observed([{"a": 1}], raw_response=raw)
    expected = hashlib.sha256(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert obs.response_sha256 == expected
    assert obs.raw_response == raw


def test_collection_time_is_normalised_to_utc() -> None:
    local = datetime(2026, 10, 30, 14, tzinfo=timezone(timedelta(hours=2)))
    obs = _observed([{"a": 1}], collected_at=local)
    assert obs.collected_at == datetime(2026, 10, 30, 12, tzinfo=UTC)
    assert obs.collected_at.tzinfo == UTC


def test_a_naive_collection_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone"):
        _observed([{"a": 1}], collected_at=datetime(2026, 10, 30, 12))


def test_scope_identifiers_are_kept() -> None:
    obs = _observed([{"a": 1}], scope=("111111111111", "222222222222"))
    assert obs.scope == ("111111111111", "222222222222")


@pytest.mark.parametrize("kind", list(FailureKind))
def test_failures_are_typed_and_carry_no_observed_data(kind: FailureKind) -> None:
    failure = Failure(
        capability=Capability.LIST_USERS_MFA,
        kind=kind,
        detail="provider said no",
        endpoint="admin:directory.users.list",
        parameters={},
        collector_version="google-1",
        collected_at=datetime(2026, 10, 30, tzinfo=UTC),
        scope=("example.com",),
    )
    assert failure.kind is kind
    assert failure.outcome == kind.value
    assert not hasattr(failure, "rows")
    assert not hasattr(failure, "raw_response")


def test_failure_kinds_cover_the_typed_outcomes() -> None:
    assert {k.value for k in FailureKind} == {
        "unauthorized",
        "rate_limited",
        "timeout",
        "incomplete_pagination",
    }
