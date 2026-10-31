"""The status engine: a pure function from claims, check facts, dates, and settings (KTD9).

No database and no model call. Given each item's claims with their latest check facts,
its review date or collection date, the frameworks it maps to, and each framework's
settings, it returns one status per item and framework with trust and causes. It
follows the plan's rollup pseudo-code:

    checkable(c)  = c has a predicate and is not rejected (or dismissed)
    item_status   = worst of every claim result, every date check, and ``unconfirmed``
                    when any checkable claim is not confirmed,
                    in the order contradicted > expired > check_failed > expiring_soon
                    > unconfirmed > not_checkable > current (R17)
    claim_result  = not_checkable if not checkable or no connected system serves it
                    check_failed  if the latest read failed
                    not_checkable if the latest read is empty or incomplete (KTD7)
                    else the predicate's evaluation: contradicted or current
    trusted       = the claims producing the worst status are all confirmed, and at
                    least one confirmed checkable claim exists (R8)

A claim may be read from several connected systems (``mfa_enforced`` is served by AWS
and Google Workspace). The predicate evaluates only the checkable reads; a failure is
check_failed unless the checkable reads already contradict the claim, which is the more
severe result and stands on its own evidence (both causes are listed). A system that
returned an empty or incomplete read leaves its scope unchecked, so a pass elsewhere is
flagged partially checked rather than vacuously complete (R18).

Partially checked is a cause on a current claim, never a status. An item with nothing
to check at all is not checkable, never vacuously current.
"""

import enum
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from passport.controls.models import AuditType, Framework, ItemKind, OrgFrameworkSettings
from passport.controls.settings import DEFAULT_AUDIT_TYPE, DEFAULT_EXPIRING_SOON_DAYS
from passport.db.models import ClaimState
from passport.predicates.registry import Evaluation
from passport.status import causes as templates

ENGINE_VERSION = "status-engine/1"


class Status(enum.StrEnum):
    CONTRADICTED = "contradicted"
    EXPIRED = "expired"
    CHECK_FAILED = "check_failed"
    EXPIRING_SOON = "expiring_soon"
    UNCONFIRMED = "unconfirmed"
    NOT_CHECKABLE = "not_checkable"
    CURRENT = "current"


# R17: most severe first.
SEVERITY: tuple[Status, ...] = tuple(Status)
_RANK = {status: rank for rank, status in enumerate(SEVERITY)}


def worst(statuses: Iterable[Status]) -> Status | None:
    ranked = sorted(statuses, key=_RANK.__getitem__)
    return ranked[0] if ranked else None


# --- Check facts (written by the check runner, U11) ---------------------------------

OBSERVED = "observed"
ERROR = "error"


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


@dataclass(frozen=True)
class SystemRead:
    """One connected system's read for a claim's capability."""

    connection_id: str | None
    name: str
    kind: str
    scope: tuple[str, ...]
    # ``observed``, a failure kind (unauthorized, rate_limited, ...), or ``error``.
    outcome: str
    complete: bool = True
    row_count: int = 0
    collected_at: datetime | None = None
    detail: str = ""

    @property
    def failed(self) -> bool:
        return self.outcome != OBSERVED

    @property
    def empty(self) -> bool:
        return not self.failed and self.row_count == 0

    @property
    def checkable(self) -> bool:
        """KTD7: an empty or incomplete read is never evaluated."""
        return not self.failed and self.complete and self.row_count > 0

    def to_json(self) -> dict[str, Any]:
        return {
            "connection_id": self.connection_id,
            "name": self.name,
            "kind": self.kind,
            "scope": list(self.scope),
            "outcome": self.outcome,
            "complete": self.complete,
            "row_count": self.row_count,
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
            "detail": self.detail,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "SystemRead":
        return cls(
            connection_id=data.get("connection_id"),
            name=data["name"],
            kind=data["kind"],
            scope=tuple(data.get("scope", ())),
            outcome=data["outcome"],
            complete=bool(data.get("complete", False)),
            row_count=int(data.get("row_count", 0)),
            collected_at=_dt(data.get("collected_at")),
            detail=data.get("detail", ""),
        )


@dataclass(frozen=True)
class EvaluationFacts:
    """A predicate evaluation over the checkable reads, as stored on the outcome."""

    passed: bool
    offenders: tuple[str, ...] = ()
    observed_scope: tuple[str, ...] = ()
    checked: tuple[str, ...] = ()
    unchecked: tuple[str, ...] = ()
    undeclared: tuple[str, ...] = ()
    partial_cause: str | None = None

    @classmethod
    def from_evaluation(cls, evaluation: Evaluation) -> "EvaluationFacts":
        return cls(
            passed=evaluation.passed,
            offenders=evaluation.offenders,
            observed_scope=evaluation.observed_scope,
            checked=evaluation.coverage.checked,
            unchecked=evaluation.coverage.unchecked,
            undeclared=evaluation.coverage.undeclared,
            partial_cause=evaluation.partial_cause,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "offenders": list(self.offenders),
            "observed_scope": list(self.observed_scope),
            "checked": list(self.checked),
            "unchecked": list(self.unchecked),
            "undeclared": list(self.undeclared),
            "partial_cause": self.partial_cause,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "EvaluationFacts":
        return cls(
            passed=bool(data["passed"]),
            offenders=tuple(data.get("offenders", ())),
            observed_scope=tuple(data.get("observed_scope", ())),
            checked=tuple(data.get("checked", ())),
            unchecked=tuple(data.get("unchecked", ())),
            undeclared=tuple(data.get("undeclared", ())),
            partial_cause=data.get("partial_cause"),
        )


# Why a claim was not read at all in a run.
NO_CONNECTION = "no_connection"
UNKNOWN_PREDICATE = "unknown_predicate"
DEADLINE_EXCEEDED = "deadline_exceeded"


@dataclass(frozen=True)
class ClaimCheck:
    """The facts one run recorded for one claim."""

    checked_at: datetime
    systems: tuple[SystemRead, ...] = ()
    evaluation: EvaluationFacts | None = None
    # The run could not read for this claim: deadline_exceeded (check failed).
    failure: str | None = None
    # The claim could not be checked at all: no_connection, unknown_predicate.
    not_checkable: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "systems": [s.to_json() for s in self.systems],
            "evaluation": self.evaluation.to_json() if self.evaluation else None,
            "failure": self.failure,
            "not_checkable": self.not_checkable,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any], checked_at: datetime) -> "ClaimCheck":
        evaluation = data.get("evaluation")
        return cls(
            checked_at=checked_at,
            systems=tuple(SystemRead.from_json(s) for s in data.get("systems", ())),
            evaluation=EvaluationFacts.from_json(evaluation) if evaluation else None,
            failure=data.get("failure"),
            not_checkable=data.get("not_checkable"),
        )


# --- Claim results ------------------------------------------------------------------


class Reason(enum.StrEnum):
    PASSED = "passed"
    CONTRADICTED = "contradicted"
    NO_PREDICATE = "no_predicate"
    UNKNOWN_PREDICATE = "unknown_predicate"
    NO_CONNECTION = "no_connection"
    NOT_CHECKED_YET = "not_checked_yet"
    SYSTEM_FAILED = "system_failed"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    EMPTY = "empty"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class ClaimResult:
    status: Status
    reason: Reason
    partially_checked: bool = False
    # Also failed on another system while the checkable reads contradicted the claim.
    also_failed: bool = False


def is_checkable(predicate_id: str | None, state: ClaimState) -> bool:
    return predicate_id is not None and state not in (ClaimState.REJECTED, ClaimState.DISMISSED)


def claim_result(
    *,
    predicate_id: str | None,
    state: ClaimState,
    served: bool,
    check: ClaimCheck | None,
) -> ClaimResult:
    """One claim's result from its latest check facts, per the HTD pseudo-code."""
    if not is_checkable(predicate_id, state):
        return ClaimResult(Status.NOT_CHECKABLE, Reason.NO_PREDICATE)
    if not served or (check is not None and check.not_checkable == NO_CONNECTION):
        return ClaimResult(Status.NOT_CHECKABLE, Reason.NO_CONNECTION)
    if check is None:
        return ClaimResult(Status.NOT_CHECKABLE, Reason.NOT_CHECKED_YET)
    if check.not_checkable is not None:
        return ClaimResult(Status.NOT_CHECKABLE, Reason.UNKNOWN_PREDICATE)
    any_failed = check.failure is not None or any(s.failed for s in check.systems)
    evaluation = check.evaluation
    if evaluation is not None and not evaluation.passed:
        return ClaimResult(Status.CONTRADICTED, Reason.CONTRADICTED, also_failed=any_failed)
    if check.failure is not None:
        return ClaimResult(Status.CHECK_FAILED, Reason.DEADLINE_EXCEEDED)
    if any_failed:
        return ClaimResult(Status.CHECK_FAILED, Reason.SYSTEM_FAILED)
    if evaluation is None:
        incomplete = any(not s.complete for s in check.systems if not s.failed)
        return ClaimResult(Status.NOT_CHECKABLE, Reason.INCOMPLETE if incomplete else Reason.EMPTY)
    skipped = any(not s.checkable for s in check.systems)
    return ClaimResult(
        Status.CURRENT,
        Reason.PASSED,
        partially_checked=evaluation.partial_cause is not None or skipped,
    )


# --- Items --------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimInput:
    claim_id: uuid.UUID
    quote: str
    predicate_id: str | None
    state: ClaimState
    # Some active connection serves the predicate's capability now.
    served: bool
    latest: ClaimCheck | None = None
    # When a check of this claim last completed (passed or contradicted).
    last_verified_at: datetime | None = None
    check_description: str | None = None

    @property
    def checkable(self) -> bool:
        return is_checkable(self.predicate_id, self.state)

    @property
    def confirmed(self) -> bool:
        return self.state is ClaimState.CONFIRMED


@dataclass(frozen=True)
class FrameworkSettings:
    """A plain copy of one framework's settings (R19)."""

    framework: Framework
    audit_type: AuditType
    as_of_date: date | None = None
    window_start: date | None = None
    window_end: date | None = None
    expiring_soon_days: int = DEFAULT_EXPIRING_SOON_DAYS

    @classmethod
    def from_row(cls, row: OrgFrameworkSettings) -> "FrameworkSettings":
        return cls(
            framework=Framework(row.framework),
            audit_type=AuditType(row.audit_type),
            as_of_date=row.as_of_date,
            window_start=row.window_start,
            window_end=row.window_end,
            expiring_soon_days=row.expiring_soon_days,
        )

    @classmethod
    def default(cls, framework: Framework) -> "FrameworkSettings":
        return cls(framework=framework, audit_type=DEFAULT_AUDIT_TYPE[framework])

    @property
    def has_window(self) -> bool:
        """SOC 2 Type I is a point in time: it has no window to fall outside of."""
        return (
            self.audit_type is not AuditType.SOC2_TYPE1
            and self.window_start is not None
            and self.window_end is not None
        )


@dataclass(frozen=True)
class ItemInput:
    kind: ItemKind
    item_id: uuid.UUID
    title: str
    claims: tuple[ClaimInput, ...] = ()
    # Next review date from the last approval (document versions and evidence).
    review_due_on: date | None = None
    # Evidence only: when it was collected, checked against the audit window.
    collected_at: datetime | None = None
    # Frameworks of the controls the item maps to; empty means unmapped.
    frameworks: tuple[Framework, ...] = ()


@dataclass(frozen=True)
class Cause:
    kind: str
    # The status this cause contributes; None for a flag (partially checked, unmapped).
    status: Status | None
    text: str
    fields: Mapping[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "status": self.status.value if self.status else None,
            "text": self.text,
            **self.fields,
        }


@dataclass(frozen=True)
class ItemResult:
    item_kind: ItemKind
    item_id: uuid.UUID
    framework: Framework
    status: Status
    trusted: bool
    causes: tuple[Cause, ...]
    unmapped: bool = False

    def causes_json(self) -> list[dict[str, Any]]:
        return [c.to_json() for c in self.causes]


def frameworks_for(
    item: ItemInput, settings: Mapping[Framework, FrameworkSettings]
) -> tuple[tuple[Framework, ...], bool]:
    """The item's frameworks, or the org's first configured one when unmapped."""
    if item.frameworks:
        return tuple(f for f in Framework if f in item.frameworks), False
    configured = [f for f in Framework if f in settings]
    return ((configured[0] if configured else next(iter(Framework))),), True


def _cause(kind: str, status: Status | None, **fields: Any) -> Cause:
    return Cause(kind, status, templates.render(kind, fields), fields)


def _label(system: SystemRead) -> str:
    return templates.system_label(system.name, system.scope)


def _date_checks(
    item: ItemInput, settings: FrameworkSettings, today: date
) -> list[tuple[Status, Cause | None]]:
    results: list[tuple[Status, Cause | None]] = []
    lead = settings.expiring_soon_days
    due = item.review_due_on
    if due is not None:
        if today > due:
            results.append(
                (Status.EXPIRED, _cause("review_overdue", Status.EXPIRED, due_on=due.isoformat()))
            )
        elif (due - today) <= timedelta(days=lead):
            cause = _cause(
                "review_due_soon", Status.EXPIRING_SOON, due_on=due.isoformat(), lead_days=lead
            )
            results.append((Status.EXPIRING_SOON, cause))
        else:
            results.append((Status.CURRENT, None))
    if item.kind is ItemKind.EVIDENCE and item.collected_at is not None and settings.has_window:
        start, end = settings.window_start, settings.window_end
        assert start is not None and end is not None
        window = {"window_start": start.isoformat(), "window_end": end.isoformat()}
        collected = item.collected_at.date()
        if collected < start or collected > end:
            cause = _cause(
                "outside_window", Status.EXPIRED, collected_on=collected.isoformat(), **window
            )
            results.append((Status.EXPIRED, cause))
        elif today <= end and (end - today) <= timedelta(days=lead):
            cause = _cause("window_ending", Status.EXPIRING_SOON, lead_days=lead, **window)
            results.append((Status.EXPIRING_SOON, cause))
        else:
            results.append((Status.CURRENT, None))
    return results


def _failed_cause(claim: ClaimInput, check: ClaimCheck | None) -> Cause:
    systems = check.systems if check else ()
    failed = [s for s in systems if s.failed]
    verified = claim.last_verified_at
    return _cause(
        "check_failed",
        Status.CHECK_FAILED,
        claim_id=str(claim.claim_id),
        quote=claim.quote,
        reason=check.failure if check and check.failure else Reason.SYSTEM_FAILED.value,
        systems=[_label(s) for s in failed],
        failures=[templates.failure_label(_label(s), s.outcome) for s in failed],
        last_verified_on=verified.date().isoformat() if verified else None,
    )


def _claim_causes(claim: ClaimInput, result: ClaimResult) -> list[Cause]:
    check = claim.latest
    systems = check.systems if check else ()
    claim_id = str(claim.claim_id)
    if result.status is Status.CONTRADICTED:
        assert check is not None and check.evaluation is not None
        found = [
            _cause(
                "contradicted",
                Status.CONTRADICTED,
                claim_id=claim_id,
                quote=claim.quote,
                offenders=list(check.evaluation.offenders),
                systems=[_label(s) for s in systems if s.checkable],
            )
        ]
        if result.also_failed:
            found.append(_failed_cause(claim, check))
        return found
    if result.status is Status.CHECK_FAILED:
        return [_failed_cause(claim, check)]
    if result.status is Status.NOT_CHECKABLE:
        return [
            _cause(
                "not_checkable",
                Status.NOT_CHECKABLE,
                claim_id=claim_id,
                quote=claim.quote,
                reason=result.reason.value,
                systems=[_label(s) for s in systems],
            )
        ]
    if result.partially_checked:
        assert check is not None and check.evaluation is not None
        evaluation = check.evaluation
        skipped = [i for s in systems if not s.checkable for i in s.scope]
        unchecked = list(dict.fromkeys([*evaluation.unchecked, *skipped]))
        return [
            _cause(
                "partially_checked",
                None,
                claim_id=claim_id,
                quote=claim.quote,
                systems=[_label(s) for s in systems if s.checkable],
                checked=list(evaluation.checked or evaluation.observed_scope),
                unchecked=unchecked,
                undeclared=list(evaluation.undeclared),
                partial_cause=evaluation.partial_cause,
            )
        ]
    return []


def evaluate_framework(
    item: ItemInput,
    settings: FrameworkSettings,
    today: date,
    *,
    unmapped: bool = False,
) -> ItemResult:
    """The item's status, trust, and causes in one framework's view."""
    entries: list[tuple[Status, Cause | None]] = []
    producers: dict[Status, list[ClaimInput]] = {}
    passed_systems: list[SystemRead] = []
    passed = 0
    for claim in item.claims:
        result = claim_result(
            predicate_id=claim.predicate_id,
            state=claim.state,
            served=claim.served,
            check=claim.latest,
        )
        producers.setdefault(result.status, []).append(claim)
        causes = _claim_causes(claim, result)
        if not causes:
            entries.append((result.status, None))
        for cause in causes:
            # A flag adds a cause without changing the claim's status.
            entries.append((cause.status or result.status, cause))
        if result.status is Status.CURRENT and claim.latest is not None:
            passed += 1
            passed_systems.extend(s for s in claim.latest.systems if s.checkable)

    awaiting = [c for c in item.claims if c.checkable and not c.confirmed]
    if awaiting:
        producers.setdefault(Status.UNCONFIRMED, []).extend(awaiting)
        entries.extend(
            (
                Status.UNCONFIRMED,
                _cause(
                    "unconfirmed",
                    Status.UNCONFIRMED,
                    claim_id=str(c.claim_id),
                    quote=c.quote,
                    state=c.state.value,
                ),
            )
            for c in awaiting
        )
    entries.extend(_date_checks(item, settings, today))

    status = worst(s for s, _ in entries)
    if status is None:
        status = Status.NOT_CHECKABLE
        entries.append((status, _cause("nothing_to_check", status, item_kind=item.kind.value)))

    trusted = all(c.confirmed for c in producers.get(status, ())) and any(
        c.checkable and c.confirmed for c in item.claims
    )

    ordered = sorted(
        (cause for _, cause in entries if cause is not None),
        key=lambda c: _RANK[c.status] if c.status else len(SEVERITY),
    )
    if status is Status.CURRENT and passed:
        labels = [_label(s) for s in _unique_systems(passed_systems)]
        ordered.insert(0, _cause("all_passed", Status.CURRENT, count=passed, systems=labels))
    if unmapped:
        ordered.append(_cause("unmapped", None, framework=settings.framework.value))
    return ItemResult(
        item_kind=item.kind,
        item_id=item.item_id,
        framework=settings.framework,
        status=status,
        trusted=trusted,
        causes=tuple(ordered),
        unmapped=unmapped,
    )


def _unique_systems(systems: Sequence[SystemRead]) -> list[SystemRead]:
    seen: dict[tuple[str | None, str], SystemRead] = {}
    for system in systems:
        seen.setdefault((system.connection_id, system.name), system)
    return list(seen.values())


def evaluate_item(
    item: ItemInput,
    settings: Mapping[Framework, FrameworkSettings],
    today: date,
) -> list[ItemResult]:
    """One result per framework the item maps to (or the first configured, if unmapped)."""
    frameworks, unmapped = frameworks_for(item, settings)
    return [
        evaluate_framework(
            item,
            settings.get(framework) or FrameworkSettings.default(framework),
            today,
            unmapped=unmapped,
        )
        for framework in frameworks
    ]
