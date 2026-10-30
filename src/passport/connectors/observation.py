"""Connector results shaped as information produced by the entity (IPE, KTD7).

A read either yields an :class:`Observed` carrying the endpoint, parameters, row and
total counts, a completeness flag, a SHA-256 of the canonical raw response, the
collector version, the UTC collection time, and the scope identifiers it covered; or
a typed :class:`Failure`. An empty or incomplete observation is never checkable:
the status engine (U12) maps it to not checkable, never to compliant.
"""

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from passport.connectors.base import Capability
from passport.db.models import Observation
from passport.provenance.actor import Actor
from passport.provenance.service import append_event, canonical, sha256_hex

OBSERVED = "observed"


class FailureKind(enum.StrEnum):
    UNAUTHORIZED = "unauthorized"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    # Pagination broke off (for example an expired cursor): no usable rows at all.
    INCOMPLETE_PAGINATION = "incomplete_pagination"


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("collected_at must carry a timezone")
    return value.astimezone(UTC)


@dataclass(frozen=True)
class Observed:
    capability: Capability
    endpoint: str
    parameters: dict[str, Any]
    rows: list[dict[str, Any]]
    raw_response: Any
    collector_version: str
    collected_at: datetime
    scope: tuple[str, ...]
    # The provider's own count of matching rows, when it reports one.
    total_count: int | None = None
    # False when the connector stopped before the last page.
    pagination_complete: bool = True
    response_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "collected_at", _as_utc(self.collected_at))
        object.__setattr__(self, "scope", tuple(self.scope))
        object.__setattr__(self, "response_sha256", sha256_hex(canonical(self.raw_response)))

    @property
    def outcome(self) -> str:
        return OBSERVED

    @property
    def row_count(self) -> int:
        return len(self.rows)

    @property
    def complete(self) -> bool:
        """Every page was read and no fewer rows arrived than the provider reported."""
        if not self.pagination_complete:
            return False
        return self.total_count is None or self.row_count >= self.total_count

    @property
    def is_empty(self) -> bool:
        return self.row_count == 0

    @property
    def checkable(self) -> bool:
        """Whether a predicate may evaluate this at all; empty or incomplete never may."""
        return self.complete and not self.is_empty


@dataclass(frozen=True)
class Failure:
    """A read that produced no observation, with the reason typed."""

    capability: Capability
    kind: FailureKind
    detail: str
    endpoint: str
    parameters: dict[str, Any]
    collector_version: str
    collected_at: datetime
    scope: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "collected_at", _as_utc(self.collected_at))
        object.__setattr__(self, "scope", tuple(self.scope))

    @property
    def outcome(self) -> str:
        return self.kind.value


CollectionResult = Observed | Failure


def record_result(
    session: Session,
    *,
    org_id: uuid.UUID,
    actor: Actor,
    connection_id: uuid.UUID | None,
    result: CollectionResult,
    check_run_id: uuid.UUID | None = None,
) -> Observation:
    """Persist a read's result as an ``Observation`` row plus a provenance event.

    A failure is stored too, with its kind as the outcome and no rows, so the latest
    row for a capability tells the status engine the check failed (R2, R12).
    """
    if isinstance(result, Observed):
        row = Observation(
            outcome=OBSERVED,
            raw_response=result.raw_response,
            response_sha256=result.response_sha256,
            row_count=result.row_count,
            total_count=result.total_count,
            complete=result.complete,
        )
        event_type = "observation.recorded"
    else:
        raw = {"failure": result.kind.value, "detail": result.detail}
        row = Observation(
            outcome=result.kind.value,
            raw_response=raw,
            response_sha256=sha256_hex(canonical(raw)),
            row_count=0,
            total_count=None,
            complete=False,
        )
        event_type = "observation.failed"
    row.org_id = org_id
    row.check_run_id = check_run_id
    row.connection_id = connection_id
    row.capability = result.capability.value
    row.endpoint = result.endpoint
    row.parameters = result.parameters
    row.scope = list(result.scope)
    row.collector_version = result.collector_version
    row.collected_at = result.collected_at
    session.add(row)
    session.flush()
    append_event(
        session,
        org_id=org_id,
        actor=actor,
        event_type=event_type,
        subject_kind="observation",
        subject_id=row.id,
        payload={
            "connection_id": str(connection_id) if connection_id else None,
            "check_run_id": str(check_run_id) if check_run_id else None,
            "capability": row.capability,
            "outcome": row.outcome,
            "endpoint": row.endpoint,
            "row_count": row.row_count,
            "total_count": row.total_count,
            "complete": row.complete,
            "response_sha256": row.response_sha256,
            "scope": row.scope,
            "collector_version": row.collector_version,
            "collected_at": row.collected_at.isoformat(),
        },
    )
    return row
