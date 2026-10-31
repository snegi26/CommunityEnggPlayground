"""The check runner: evaluate an org's claims against its connected systems.

No model runs here (KTD2). A run loads the claims a check covers
(``checkable_claims``), groups them by the connector capability their predicate needs,
and reads each capability once from every active connection that serves it. Each read
is recorded as an observation (``record_result``), then every claim needing that
capability is evaluated against the checkable reads only and its outcome is stored
(``CheckOutcome``). A rate limit, timeout, or revoked credential is a check failure,
never a finding (KTD11); an empty or incomplete read is not checkable (KTD7).

Idempotency: a run commits after each capability group, so a run interrupted part way
keeps the groups it finished. Executing the same run again skips claims that already
have an outcome and reads only what is left. A run past its deadline finishes with the
remaining claims marked check failed. After the claims, statuses are recomputed;
the weekly report is built from the run and the statuses.

Actor: every event a run writes names the freshness agent (A4) as an ``Agent`` whose
``run_id`` is the check run and whose ``model_id`` is ``"none"``: deterministic code
acted and no model ran. The actor model has only people and the agent, and a run is
not a person.

On-demand runs are owner-only. While a run for the org is queued or running, a further
request (on demand or scheduled) returns that run instead of creating another.
"""

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

import passport.predicates.definitions  # noqa: F401  (registers the v1 predicates)
from passport.checks.models import CheckOutcome
from passport.claims.service import ActingMember, ForbiddenError, checkable_claims
from passport.connectors.base import Capability, Connector, collect
from passport.connectors.models import Connection, ConnectionKind, ConnectionStatus
from passport.connectors.observation import Observed, record_result
from passport.connectors.registry import kinds_serving
from passport.controls.models import ScopeEntry
from passport.db.base import utcnow
from passport.db.models import CheckRun, Claim, Observation, RunStatus
from passport.db.rls import set_org_context
from passport.predicates.registry import PredicateError, PredicateRegistry
from passport.predicates.registry import registry as default_registry
from passport.provenance.actor import Actor, Agent, require_human
from passport.provenance.service import append_event
from passport.status.engine import (
    DEADLINE_EXCEEDED,
    ERROR,
    NO_CONNECTION,
    UNKNOWN_PREDICATE,
    ClaimCheck,
    EvaluationFacts,
    SystemRead,
    claim_result,
)
from passport.status.service import recompute_statuses
from passport.tenancy.models import Role

RUNNER_VERSION = "check-runner/1"
# No model runs during a check (KTD2); events record that explicitly.
NO_MODEL = "none"
DEFAULT_MAX_DURATION = timedelta(hours=1)
# A queued or running run older than this was abandoned (its worker died) and no longer
# blocks new runs; weekly cadence leaves ample room.
STALE_AFTER = timedelta(hours=24)

SCHEDULED = "scheduled"
ON_DEMAND = "on_demand"

ConnectorFactory = Callable[[Session, Connection], Connector]
Clock = Callable[[], datetime]


def check_actor(run_id: uuid.UUID) -> Agent:
    """The freshness agent acting through deterministic code for one run."""
    return Agent(run_id=run_id, model_id=NO_MODEL, prompt_version=RUNNER_VERSION)


class RunNotFoundError(LookupError):
    pass


def _lock_org_runs(session: Session, org_id: uuid.UUID) -> None:
    """Serialize run requests per org for the rest of the transaction."""
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"check_run:{org_id}"}
    )


def active_run(session: Session, org_id: uuid.UUID) -> CheckRun | None:
    return session.scalars(
        select(CheckRun)
        .where(
            CheckRun.org_id == org_id,
            CheckRun.status.in_((RunStatus.QUEUED, RunStatus.RUNNING)),
        )
        .order_by(CheckRun.created_at.desc())
    ).first()


def request_run(
    session: Session,
    org_id: uuid.UUID,
    *,
    trigger: str,
    actor: Actor | None = None,
    clock: Clock = utcnow,
) -> tuple[CheckRun, bool]:
    """Create a queued run, or return the org's queued or running run.

    Returns ``(run, created)``. The caller commits and then enqueues the job only when
    ``created`` is true.
    """
    _lock_org_runs(session, org_id)
    now = clock()
    existing = active_run(session, org_id)
    if existing is not None:
        if now - existing.created_at < STALE_AFTER:
            return existing, False
        _finish(
            session,
            existing,
            RunStatus.FAILED,
            now,
            reason="abandoned: the run did not finish within "
            f"{int(STALE_AFTER.total_seconds() // 3600)} hours",
        )
    run = CheckRun(org_id=org_id, trigger=trigger, status=RunStatus.QUEUED, created_at=now)
    session.add(run)
    session.flush()
    append_event(
        session,
        org_id=org_id,
        actor=actor or check_actor(run.id),
        event_type="check_run.requested",
        subject_kind="check_run",
        subject_id=run.id,
        payload={"trigger": trigger},
    )
    return run, True


def request_rerun(session: Session, acting: ActingMember) -> tuple[CheckRun, bool]:
    """An owner's on-demand re-run (R10); other roles and the agent are refused."""
    human = require_human(acting.actor)
    if acting.role is not Role.OWNER:
        raise ForbiddenError(f"a {acting.role.value} may not re-run checks; owners only")
    return request_run(session, acting.org_id, trigger=ON_DEMAND, actor=human)


@dataclass(frozen=True)
class SystemCoverage:
    connection_id: str
    name: str
    kind: str
    reachable: bool
    outcomes: tuple[str, ...]


@dataclass(frozen=True)
class Coverage:
    """How much a run actually checked (R12)."""

    claims: int
    current: int
    contradicted: int
    check_failed: int
    not_checkable: int
    deadline_exceeded: int
    systems: tuple[SystemCoverage, ...] = field(default=())

    @property
    def checked(self) -> int:
        """Claims evaluated against live data (passed or contradicted)."""
        return self.current + self.contradicted

    def to_json(self) -> dict[str, Any]:
        return {
            "claims": self.claims,
            "checked": self.checked,
            "current": self.current,
            "contradicted": self.contradicted,
            "check_failed": self.check_failed,
            "not_checkable": self.not_checkable,
            "deadline_exceeded": self.deadline_exceeded,
            "systems": [
                {
                    "connection_id": s.connection_id,
                    "name": s.name,
                    "kind": s.kind,
                    "reachable": s.reachable,
                    "outcomes": list(s.outcomes),
                }
                for s in self.systems
            ],
        }


def run_coverage(session: Session, org_id: uuid.UUID, run_id: uuid.UUID) -> Coverage:
    """Counts from a run's outcomes, and which connected systems answered."""
    outcomes = list(
        session.scalars(
            select(CheckOutcome).where(
                CheckOutcome.org_id == org_id, CheckOutcome.check_run_id == run_id
            )
        )
    )
    counts = {"current": 0, "contradicted": 0, "check_failed": 0, "not_checkable": 0}
    for outcome in outcomes:
        counts[outcome.outcome] += 1
    deadline = sum(1 for o in outcomes if o.detail.get("failure") == DEADLINE_EXCEEDED)

    reads: dict[str, list[str]] = {}
    for connection_id, read_outcome in session.execute(
        select(Observation.connection_id, Observation.outcome)
        .where(Observation.org_id == org_id, Observation.check_run_id == run_id)
        .order_by(Observation.created_at)
    ):
        reads.setdefault(str(connection_id), []).append(read_outcome)
    systems: list[SystemCoverage] = []
    for connection in _active_connections(session, org_id):
        seen = reads.get(str(connection.id))
        if seen is None:
            continue
        systems.append(
            SystemCoverage(
                connection_id=str(connection.id),
                name=connection.display_name,
                kind=connection.kind,
                reachable=all(o == "observed" for o in seen),
                outcomes=tuple(dict.fromkeys(seen)),
            )
        )
    return Coverage(
        claims=len(outcomes),
        deadline_exceeded=deadline,
        systems=tuple(systems),
        **counts,
    )


@dataclass(frozen=True)
class RunSummary:
    run_id: uuid.UUID
    status: RunStatus
    coverage: Coverage


def _checkpoint(session: Session, org_id: uuid.UUID) -> None:
    """Commit finished work; the org context is transaction-local, so set it again."""
    session.commit()
    set_org_context(session, org_id)


def _finish(
    session: Session,
    run: CheckRun,
    status: RunStatus,
    now: datetime,
    *,
    reason: str | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    run.status = status
    run.finished_at = now
    run.failure_reason = reason
    session.flush()
    append_event(
        session,
        org_id=run.org_id,
        actor=check_actor(run.id),
        event_type="check_run.finished" if status is RunStatus.SUCCEEDED else "check_run.failed",
        subject_kind="check_run",
        subject_id=run.id,
        payload={"status": status.value, "reason": reason, **(payload or {})},
    )


def fail_run(session: Session, org_id: uuid.UUID, run_id: uuid.UUID, reason: str) -> None:
    """Record that a run stopped on an error; its finished outcomes are kept."""
    run = session.scalars(
        select(CheckRun).where(CheckRun.id == run_id, CheckRun.org_id == org_id)
    ).one_or_none()
    if run is None or run.status in (RunStatus.SUCCEEDED, RunStatus.FAILED):
        return
    _finish(session, run, RunStatus.FAILED, utcnow(), reason=reason)


def _active_connections(session: Session, org_id: uuid.UUID) -> list[Connection]:
    return list(
        session.scalars(
            select(Connection)
            .where(
                Connection.org_id == org_id,
                Connection.status == ConnectionStatus.ACTIVE.value,
            )
            .order_by(Connection.created_at, Connection.id)
        )
    )


@dataclass
class _Group:
    capability: Capability
    claims: list[Claim] = field(default_factory=list)


class _Reader:
    """Builds each connection's connector once per run and reads capabilities from it."""

    def __init__(self, session: Session, factory: ConnectorFactory) -> None:
        self._session = session
        self._factory = factory
        self._connectors: dict[uuid.UUID, Connector | Exception] = {}

    def read(self, connection: Connection, capability: Capability) -> Any:
        connector = self._connectors.get(connection.id)
        if connector is None:
            try:
                connector = self._factory(self._session, connection)
            except Exception as exc:  # a broken connection fails only its own checks
                connector = exc
            self._connectors[connection.id] = connector
        if isinstance(connector, Exception):
            raise connector
        return collect(connector, capability)


def _system(connection: Connection, result: Any, row: Observation | None) -> SystemRead:
    if row is None:
        return SystemRead(
            connection_id=str(connection.id),
            name=connection.display_name,
            kind=connection.kind,
            scope=(),
            outcome=ERROR,
            complete=False,
            detail=f"{type(result).__name__}: {result}",
        )
    return SystemRead(
        connection_id=str(connection.id),
        name=connection.display_name,
        kind=connection.kind,
        scope=tuple(row.scope),
        outcome=row.outcome,
        complete=row.complete,
        row_count=row.row_count,
        collected_at=row.collected_at,
    )


def _store_outcome(
    session: Session,
    run: CheckRun,
    claim: Claim,
    check: ClaimCheck,
    observation_ids: Sequence[uuid.UUID] = (),
) -> CheckOutcome:
    result = claim_result(
        predicate_id=claim.predicate_id, state=claim.state, served=True, check=check
    )
    outcome = CheckOutcome(
        org_id=run.org_id,
        check_run_id=run.id,
        claim_id=claim.id,
        outcome=result.status.value,
        observation_ids=[str(i) for i in observation_ids],
        detail=check.to_json(),
        checked_at=check.checked_at,
    )
    session.add(outcome)
    session.flush()
    return outcome


def execute_run(
    session: Session,
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    connector_factory: ConnectorFactory,
    max_duration: timedelta = DEFAULT_MAX_DURATION,
    clock: Clock = utcnow,
    registry: PredicateRegistry = default_registry,
    today: date | None = None,
) -> RunSummary:
    """Run (or resume) one check run for the org in ``session``'s org context.

    Commits after starting, after each capability group, and at the end. A run that
    already finished is returned unchanged.
    """
    run = session.scalars(
        select(CheckRun).where(CheckRun.id == run_id, CheckRun.org_id == org_id)
    ).one_or_none()
    if run is None:
        raise RunNotFoundError(f"check run {run_id} not found")
    if run.status in (RunStatus.SUCCEEDED, RunStatus.FAILED):
        return RunSummary(run.id, run.status, run_coverage(session, org_id, run.id))
    actor = check_actor(run.id)
    if run.status is RunStatus.QUEUED or run.started_at is None:
        run.status = RunStatus.RUNNING
        run.started_at = clock()
        session.flush()
        append_event(
            session,
            org_id=org_id,
            actor=actor,
            event_type="check_run.started",
            subject_kind="check_run",
            subject_id=run.id,
            payload={"trigger": run.trigger},
        )
        _checkpoint(session, org_id)
    assert run.started_at is not None
    deadline = run.started_at + max_duration

    done = set(
        session.scalars(
            select(CheckOutcome.claim_id).where(
                CheckOutcome.org_id == org_id, CheckOutcome.check_run_id == run.id
            )
        )
    )
    groups: dict[Capability, _Group] = {}
    for claim in checkable_claims(session, org_id):
        if claim.id in done:
            continue
        assert claim.predicate_id is not None and claim.predicate_version is not None
        try:
            predicate = registry.get(claim.predicate_id, claim.predicate_version)
        except PredicateError:
            check = ClaimCheck(checked_at=clock(), not_checkable=UNKNOWN_PREDICATE)
            _store_outcome(session, run, claim, check)
            continue
        groups.setdefault(predicate.capability, _Group(predicate.capability)).claims.append(claim)
    _checkpoint(session, org_id)

    connections = _active_connections(session, org_id)
    inventory = list(session.scalars(select(ScopeEntry).where(ScopeEntry.org_id == org_id)))
    reader = _Reader(session, connector_factory)
    for group in groups.values():
        kinds = set(kinds_serving(group.capability))
        serving = [c for c in connections if ConnectionKind(c.kind) in kinds]
        if not serving:
            for claim in group.claims:
                check = ClaimCheck(checked_at=clock(), not_checkable=NO_CONNECTION)
                _store_outcome(session, run, claim, check)
        elif clock() >= deadline:
            for claim in group.claims:
                check = ClaimCheck(checked_at=clock(), failure=DEADLINE_EXCEEDED)
                _store_outcome(session, run, claim, check)
        else:
            _check_group(session, run, actor, group, serving, reader, inventory, clock, registry)
        _checkpoint(session, org_id)

    recompute_statuses(session, org_id, actor=actor, today=today or clock().date())
    coverage = run_coverage(session, org_id, run.id)
    _finish(session, run, RunStatus.SUCCEEDED, clock(), payload={"coverage": coverage.to_json()})
    _checkpoint(session, org_id)
    return RunSummary(run.id, run.status, coverage)


def _check_group(
    session: Session,
    run: CheckRun,
    actor: Agent,
    group: _Group,
    serving: Sequence[Connection],
    reader: _Reader,
    inventory: Sequence[ScopeEntry],
    clock: Clock,
    registry: PredicateRegistry,
) -> None:
    """Read the group's capability once per serving connection, then evaluate each claim."""
    systems: list[SystemRead] = []
    observed: list[Observed] = []
    observation_ids: list[uuid.UUID] = []
    for connection in serving:
        try:
            result = reader.read(connection, group.capability)
        except Exception as exc:
            systems.append(_system(connection, exc, None))
            continue
        row = record_result(
            session,
            org_id=run.org_id,
            actor=actor,
            connection_id=connection.id,
            result=result,
            check_run_id=run.id,
        )
        observation_ids.append(row.id)
        systems.append(_system(connection, result, row))
        if isinstance(result, Observed) and result.checkable:
            observed.append(result)
    checked_at = clock()
    for claim in group.claims:
        assert claim.predicate_id is not None and claim.predicate_version is not None
        evaluation = None
        if observed:
            evaluation = EvaluationFacts.from_evaluation(
                registry.evaluate(
                    claim.predicate_id,
                    claim.predicate_version,
                    claim.parameters,
                    observed,
                    inventory,
                )
            )
        check = ClaimCheck(checked_at=checked_at, systems=tuple(systems), evaluation=evaluation)
        _store_outcome(session, run, claim, check, observation_ids)
