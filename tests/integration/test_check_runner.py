"""Check runner and scheduler (U11): runs against fake connectors, idempotency, scheduling."""

import asyncio
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from procrastinate.testing import InMemoryConnector
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from passport.checks.jobs import (
    create_scheduled_runs,
    enqueue_run,
    run_checks_for_org,
    schedule_weekly_runs,
    stagger_offset,
)
from passport.checks.models import CheckOutcome
from passport.checks.runner import (
    ON_DEMAND,
    SCHEDULED,
    ConnectorFactory,
    execute_run,
    request_rerun,
    request_run,
    run_coverage,
)
from passport.claims.service import ActingMember, ForbiddenError
from passport.connectors.base import Capability, Connector
from passport.connectors.fakes import FakeConnector, Rows, failure, partial, users_mfa
from passport.connectors.models import Connection, ConnectionKind
from passport.connectors.observation import FailureKind
from passport.connectors.registry import create_connection
from passport.controls.models import ScopeKind
from passport.controls.settings import add_scope_entry
from passport.db.engine import get_sessionmaker
from passport.db.models import (
    CheckRun,
    Claim,
    ClaimState,
    Document,
    DocumentVersion,
    Event,
    ItemStatus,
    Observation,
    RunStatus,
)
from passport.db.rls import set_org_context
from passport.jobs import app
from passport.provenance.actor import Agent, AgentNotPermittedError, Human
from passport.provenance.service import verify_chain
from passport.tenancy.models import Role
from tests.helpers import SignedInUser, create_org, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")

AWS_PROD = "111111111111"
AWS_STAGING = "222222222222"
DOMAIN = "example.com"
GITHUB_ORG = "acme"


@dataclass
class Org:
    org_id: uuid.UUID
    owner: SignedInUser
    connections: dict[str, uuid.UUID] = field(default_factory=dict)


def _session(org_id: uuid.UUID) -> Session:
    db = get_sessionmaker()()
    set_org_context(db, org_id)
    return db


def _commit(db: Session, org_id: uuid.UUID) -> None:
    db.commit()
    set_org_context(db, org_id)


@pytest.fixture
def org() -> Org:
    owner = sign_up()
    return Org(create_org(owner), owner)


def connect(org: Org, kind: ConnectionKind, name: str, scope: list[tuple[ScopeKind, str]]) -> None:
    actor = Human(org.owner.user_id)
    with _session(org.org_id) as db:
        conn = create_connection(db, org_id=org.org_id, actor=actor, kind=kind, display_name=name)
        for scope_kind, identifier in scope:
            add_scope_entry(db, org.org_id, actor, scope_kind, identifier, production=True)
        org.connections[name] = conn.id
        db.commit()


def add_policy(
    org: Org,
    claims: list[tuple[str, str | None, dict[str, Any], ClaimState]],
    title: str = "Access policy",
) -> list[uuid.UUID]:
    """A document with one version and the given (quote, predicate, params, state) claims."""
    with _session(org.org_id) as db:
        document = Document(org_id=org.org_id, title=title)
        db.add(document)
        db.flush()
        version = DocumentVersion(
            org_id=org.org_id,
            document_id=document.id,
            version_number=1,
            filename="policy.md",
            content_hash="0" * 64,
            storage_key="k",
        )
        db.add(version)
        db.flush()
        ids = []
        for i, (quote, predicate, params, state) in enumerate(claims):
            claim = Claim(
                org_id=org.org_id,
                document_version_id=version.id,
                span_id=f"s{i}",
                quote=quote,
                predicate_id=predicate,
                predicate_version=1 if predicate else None,
                parameters=params,
                state=state,
                created_at=datetime(2026, 10, 1, tzinfo=UTC) + timedelta(seconds=i),
            )
            db.add(claim)
            db.flush()
            ids.append(claim.id)
        db.commit()
        return ids


MFA = ("MFA is required on all production accounts.", "mfa_enforced")
ROOT = ("The root user of every AWS account has MFA.", "root_mfa_enabled")
MEMBERS = ("Every GitHub member has 2FA.", "github_members_2fa_enabled")


def mfa_claim(
    state: ClaimState = ClaimState.CONFIRMED,
) -> tuple[str, str, dict[str, Any], ClaimState]:
    return (MFA[0], MFA[1], {"scope": "all_production_accounts"}, state)


def root_claim(
    state: ClaimState = ClaimState.CONFIRMED,
) -> tuple[str, str, dict[str, Any], ClaimState]:
    return (ROOT[0], ROOT[1], {"scope": "all_accounts"}, state)


def factory(fakes: Mapping[str, Connector]) -> ConnectorFactory:
    def build(session: Session, connection: Connection) -> Connector:
        return fakes[connection.display_name]

    return build


def new_run(org: Org, trigger: str = SCHEDULED) -> uuid.UUID:
    with _session(org.org_id) as db:
        run, created = request_run(db, org.org_id, trigger=trigger)
        assert created
        db.commit()
        return run.id


def run_once(org: Org, fakes: Mapping[str, Connector], **kwargs: Any) -> uuid.UUID:
    run_id = new_run(org)
    with _session(org.org_id) as db:
        execute_run(db, org.org_id, run_id, connector_factory=factory(fakes), **kwargs)
    return run_id


def outcomes(org: Org, run_id: uuid.UUID) -> dict[uuid.UUID, CheckOutcome]:
    with _session(org.org_id) as db:
        rows = db.scalars(select(CheckOutcome).where(CheckOutcome.check_run_id == run_id))
        return {row.claim_id: row for row in rows}


def aws(responses: Mapping[Capability, Any], scope: tuple[str, ...] = (AWS_PROD,)) -> FakeConnector:
    return FakeConnector(ConnectionKind.AWS, scope=scope, responses=responses)


def root_ok() -> Rows:
    return Rows([{"account_id": AWS_PROD, "root_mfa": True}])


# --- AE1 -----------------------------------------------------------------------------


def test_a_confirmed_mfa_claim_is_contradicted_naming_the_account(org: Org) -> None:
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    [claim_id] = add_policy(org, [mfa_claim()])
    fake = aws({Capability.LIST_USERS_MFA: users_mfa({"alice": True, "bob": False})})

    run_id = run_once(org, {"AWS prod": fake})

    outcome = outcomes(org, run_id)[claim_id]
    assert outcome.outcome == "contradicted"
    assert outcome.detail["evaluation"]["offenders"] == ["bob"]
    assert outcome.detail["systems"][0]["name"] == "AWS prod"
    with _session(org.org_id) as db:
        observation = db.scalars(select(Observation)).one()
        assert observation.check_run_id == run_id
        assert [str(observation.id)] == outcome.observation_ids
        assert observation.connection_id == org.connections["AWS prod"]
        status = db.scalars(select(ItemStatus)).one()
        assert (status.status, status.trusted) == ("contradicted", True)
        assert "bob" in status.causes[0]["text"]
        run = db.get(CheckRun, run_id)
        assert run is not None and run.status is RunStatus.SUCCEEDED
        assert verify_chain(db, org.org_id).ok


def test_each_capability_is_read_once_for_all_claims_needing_it(org: Org) -> None:
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    add_policy(org, [mfa_claim(), mfa_claim(ClaimState.UNCONFIRMED)], "Access")
    add_policy(org, [mfa_claim(), root_claim()], "Cloud")
    fake = aws(
        {
            Capability.LIST_USERS_MFA: users_mfa({"alice": True}),
            Capability.GET_ROOT_MFA: root_ok(),
        }
    )

    run_id = run_once(org, {"AWS prod": fake})

    assert sorted(fake.calls) == sorted([Capability.LIST_USERS_MFA, Capability.GET_ROOT_MFA])
    assert len(outcomes(org, run_id)) == 4


# --- AE6 -----------------------------------------------------------------------------


def test_an_unauthorized_identity_provider_fails_its_claims_while_cloud_claims_evaluate(
    org: Org,
) -> None:
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    connect(
        org, ConnectionKind.GOOGLE_WORKSPACE, "Workspace", [(ScopeKind.WORKSPACE_DOMAIN, DOMAIN)]
    )
    mfa_id, root_id = add_policy(org, [mfa_claim(), root_claim()])
    google = FakeConnector(
        ConnectionKind.GOOGLE_WORKSPACE,
        scope=(DOMAIN,),
        responses={Capability.LIST_USERS_MFA: failure(FailureKind.UNAUTHORIZED, "token revoked")},
    )
    cloud = aws(
        {Capability.LIST_USERS_MFA: users_mfa({"alice": True}), Capability.GET_ROOT_MFA: root_ok()}
    )

    run_id = run_once(org, {"AWS prod": cloud, "Workspace": google})

    found = outcomes(org, run_id)
    assert found[mfa_id].outcome == "check_failed"
    assert found[root_id].outcome == "current"
    with _session(org.org_id) as db:
        failed = db.scalars(select(Observation).where(Observation.outcome == "unauthorized")).one()
        assert failed.connection_id == org.connections["Workspace"]
        coverage = run_coverage(db, org.org_id, run_id)
        reachable = {s.name: s.reachable for s in coverage.systems}
        assert reachable == {"AWS prod": True, "Workspace": False}


def test_an_empty_user_list_is_not_checkable_never_current(org: Org) -> None:
    connect(
        org, ConnectionKind.GOOGLE_WORKSPACE, "Workspace", [(ScopeKind.WORKSPACE_DOMAIN, DOMAIN)]
    )
    [claim_id] = add_policy(org, [mfa_claim()])
    google = FakeConnector(
        ConnectionKind.GOOGLE_WORKSPACE,
        scope=(DOMAIN,),
        responses={Capability.LIST_USERS_MFA: users_mfa({})},
    )

    run_id = run_once(org, {"Workspace": google})

    assert outcomes(org, run_id)[claim_id].outcome == "not_checkable"
    with _session(org.org_id) as db:
        status = db.scalars(select(ItemStatus)).one()
        assert status.status == "not_checkable"
        assert "returned no records" in status.causes[0]["text"]


def test_an_incomplete_read_is_not_checkable(org: Org) -> None:
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    [claim_id] = add_policy(org, [mfa_claim()])
    fake = aws({Capability.LIST_USERS_MFA: partial(users_mfa({"alice": True}), total=3)})

    run_id = run_once(org, {"AWS prod": fake})

    assert outcomes(org, run_id)[claim_id].outcome == "not_checkable"


@pytest.mark.parametrize("kind", [FailureKind.RATE_LIMITED, FailureKind.TIMEOUT])
def test_a_rate_limit_or_timeout_is_a_failed_check_never_a_contradiction(
    org: Org, kind: FailureKind
) -> None:
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    [claim_id] = add_policy(org, [mfa_claim()])
    fake = aws({Capability.LIST_USERS_MFA: failure(kind)})

    run_id = run_once(org, {"AWS prod": fake})

    assert outcomes(org, run_id)[claim_id].outcome == "check_failed"
    with _session(org.org_id) as db:
        status = db.scalars(select(ItemStatus)).one()
        assert status.status == "check_failed"
        assert all(c["kind"] != "contradicted" for c in status.causes)


def test_a_connector_that_cannot_be_built_fails_only_its_own_claims(org: Org) -> None:
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    connect(org, ConnectionKind.GITHUB, "GitHub", [(ScopeKind.GITHUB_ORG, GITHUB_ORG)])
    root_id, members_id = add_policy(
        org, [root_claim(), (MEMBERS[0], MEMBERS[1], {"scope": "all_orgs"}, ClaimState.CONFIRMED)]
    )
    cloud = aws({Capability.GET_ROOT_MFA: root_ok()})

    def build(session: Session, connection: Connection) -> Connector:
        if connection.display_name == "GitHub":
            raise RuntimeError("installation removed")
        return cloud

    run_id = new_run(org)
    with _session(org.org_id) as db:
        execute_run(db, org.org_id, run_id, connector_factory=build)

    found = outcomes(org, run_id)
    assert found[root_id].outcome == "current"
    assert found[members_id].outcome == "check_failed"
    assert found[members_id].detail["systems"][0]["outcome"] == "error"


def test_a_claim_no_connected_system_serves_is_not_checkable(org: Org) -> None:
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    [members_id] = add_policy(
        org, [(MEMBERS[0], MEMBERS[1], {"scope": "all_orgs"}, ClaimState.CONFIRMED)]
    )
    fake = aws({})

    run_id = run_once(org, {"AWS prod": fake})

    outcome = outcomes(org, run_id)[members_id]
    assert outcome.outcome == "not_checkable"
    assert outcome.detail["not_checkable"] == "no_connection"
    assert fake.calls == []


# --- Idempotency and deadline ---------------------------------------------------------


class WorkerKilled(BaseException):
    """Simulates the worker process dying mid-run (not an ordinary error)."""


def test_resuming_a_half_completed_run_does_not_duplicate_finished_claims(org: Org) -> None:
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    connect(org, ConnectionKind.GITHUB, "GitHub", [(ScopeKind.GITHUB_ORG, GITHUB_ORG)])
    mfa_id, members_id = add_policy(
        org, [mfa_claim(), (MEMBERS[0], MEMBERS[1], {"scope": "all_orgs"}, ClaimState.CONFIRMED)]
    )
    cloud = aws({Capability.LIST_USERS_MFA: users_mfa({"alice": True})})
    github = FakeConnector(
        ConnectionKind.GITHUB,
        scope=(GITHUB_ORG,),
        responses={Capability.LIST_ORG_MEMBERS: Rows([{"login": "octo", "two_factor": True}])},
    )

    def dying(session: Session, connection: Connection) -> Connector:
        if connection.display_name == "GitHub":
            raise WorkerKilled
        return cloud

    run_id = new_run(org)
    with _session(org.org_id) as db, pytest.raises(WorkerKilled):
        execute_run(db, org.org_id, run_id, connector_factory=dying)

    half = outcomes(org, run_id)
    assert set(half) == {mfa_id}
    with _session(org.org_id) as db:
        run = db.get(CheckRun, run_id)
        assert run is not None and run.status is RunStatus.RUNNING

    # The worker retries the same run.
    with _session(org.org_id) as db:
        execute_run(
            db, org.org_id, run_id, connector_factory=factory({"AWS prod": cloud, "GitHub": github})
        )

    assert cloud.calls == [Capability.LIST_USERS_MFA]
    assert github.calls == [Capability.LIST_ORG_MEMBERS]
    final = outcomes(org, run_id)
    assert set(final) == {mfa_id, members_id}
    assert final[mfa_id].id == half[mfa_id].id
    with _session(org.org_id) as db:
        per_capability = dict(
            db.execute(
                select(Observation.capability, func.count()).group_by(Observation.capability)
            ).all()
        )
        assert per_capability == {"list_users_mfa": 1, "list_org_members": 1}
        assert db.scalar(select(func.count()).select_from(CheckOutcome)) == 2
        # Executing a finished run again does nothing.
        execute_run(db, org.org_id, run_id, connector_factory=dying)
        assert db.scalar(select(func.count()).select_from(Observation)) == 2


def test_a_run_past_its_deadline_marks_the_remaining_claims_check_failed(org: Org) -> None:
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    mfa_id, root_id = add_policy(org, [mfa_claim(), root_claim()])
    start = datetime(2026, 10, 26, 3, tzinfo=UTC)
    ticks = iter(start + timedelta(minutes=m) for m in [0, 1, 2] + [120] * 20)
    fake = aws(
        {Capability.LIST_USERS_MFA: users_mfa({"alice": True}), Capability.GET_ROOT_MFA: root_ok()}
    )

    run_id = run_once(
        org, {"AWS prod": fake}, clock=lambda: next(ticks), max_duration=timedelta(hours=1)
    )

    found = outcomes(org, run_id)
    assert found[mfa_id].outcome == "current"
    assert found[root_id].outcome == "check_failed"
    assert found[root_id].detail["failure"] == "deadline_exceeded"
    assert fake.calls == [Capability.LIST_USERS_MFA]
    with _session(org.org_id) as db:
        run = db.get(CheckRun, run_id)
        assert run is not None and run.status is RunStatus.SUCCEEDED
        finished = db.scalars(select(Event).where(Event.event_type == "check_run.finished")).one()
        assert finished.payload["coverage"]["deadline_exceeded"] == 1


# --- No model during a check ---------------------------------------------------------


def test_no_model_client_is_constructed_during_a_run(
    org: Org, monkeypatch: pytest.MonkeyPatch
) -> None:
    import anthropic

    from passport.agent import client as agent_client

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("a check run constructed a model client")

    monkeypatch.setattr(anthropic.Anthropic, "__init__", refuse)
    monkeypatch.setattr(agent_client.AnthropicModelClient, "__init__", refuse)
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    add_policy(org, [mfa_claim(), root_claim()])
    fake = aws(
        {Capability.LIST_USERS_MFA: users_mfa({"alice": True}), Capability.GET_ROOT_MFA: root_ok()}
    )
    run_id = new_run(org)

    result = run_checks_for_org(org.org_id, run_id, connector_factory=factory({"AWS prod": fake}))

    assert result["status"] == "succeeded"
    with _session(org.org_id) as db:
        agents = db.scalars(select(Event).where(Event.actor_kind == "agent")).all()
        assert agents and {e.model_id for e in agents} == {"none"}


# --- On-demand and scheduling --------------------------------------------------------


def _acting(org: Org, role: Role, actor: Human | Agent | None = None) -> ActingMember:
    return ActingMember(org.org_id, actor or Human(org.owner.user_id), role)


def test_a_rerun_requested_while_one_is_running_returns_that_run(org: Org) -> None:
    connector = InMemoryConnector()
    with app.replace_connector(connector), _session(org.org_id) as db:
        first, created = request_rerun(db, _acting(org, Role.OWNER))
        assert created and first.trigger == ON_DEMAND
        _commit(db, org.org_id)
        enqueue_run(org.org_id, first.id)

        first.status = RunStatus.RUNNING
        _commit(db, org.org_id)
        again, created_again = request_rerun(db, _acting(org, Role.OWNER))
        assert (again.id, created_again) == (first.id, False)
        scheduled, created_scheduled = request_run(db, org.org_id, trigger=SCHEDULED)
        assert (scheduled.id, created_scheduled) == (first.id, False)
        _commit(db, org.org_id)

        assert db.scalar(select(func.count()).select_from(CheckRun)) == 1
        assert len(connector.jobs) == 1
        requested = db.scalars(select(Event).where(Event.event_type == "check_run.requested")).one()
        assert (requested.actor_kind, requested.actor_user_id) == ("human", org.owner.user_id)


def test_only_an_owner_may_request_a_rerun(org: Org) -> None:
    with _session(org.org_id) as db:
        for role in (Role.APPROVER, Role.VIEWER):
            with pytest.raises(ForbiddenError):
                request_rerun(db, _acting(org, role))
        agent = Agent(run_id=uuid.uuid4(), model_id="m", prompt_version="p")
        with pytest.raises(AgentNotPermittedError):
            request_rerun(db, _acting(org, Role.OWNER, agent))
        assert db.scalar(select(func.count()).select_from(CheckRun)) == 0


def test_a_stale_run_no_longer_blocks_a_new_one(org: Org) -> None:
    long_ago = datetime(2026, 10, 1, tzinfo=UTC)
    with _session(org.org_id) as db:
        stale, _ = request_run(db, org.org_id, trigger=SCHEDULED, clock=lambda: long_ago)
        fresh, created = request_run(db, org.org_id, trigger=SCHEDULED)
        assert created and fresh.id != stale.id
        assert stale.status is RunStatus.FAILED
        assert stale.failure_reason is not None and "abandoned" in stale.failure_reason


def test_the_weekly_schedule_enqueues_one_staggered_job_per_org(org: Org) -> None:
    other = Org(create_org(sign_up(), "Other"), org.owner)
    busy = Org(create_org(sign_up(), "Busy"), org.owner)
    busy_run = new_run(busy, ON_DEMAND)
    connector = InMemoryConnector()
    before = datetime.now(UTC)

    with app.replace_connector(connector):
        created = asyncio.run(schedule_weekly_runs())

    assert created == 2
    jobs = list(connector.jobs.values())
    assert {j["task_name"] for j in jobs} == {"passport.checks.run_org_checks"}
    by_org = {uuid.UUID(j["args"]["org_id"]): j for j in jobs}
    assert set(by_org) == {org.org_id, other.org_id}
    for org_id, job in by_org.items():
        delay = job["scheduled_at"] - before
        assert abs(delay - stagger_offset(org_id)) < timedelta(seconds=30)
        with _session(org_id) as db:
            run = db.get(CheckRun, uuid.UUID(job["args"]["run_id"]))
            assert run is not None and run.trigger == SCHEDULED
    assert stagger_offset(org.org_id) == stagger_offset(org.org_id)
    assert stagger_offset(org.org_id) != stagger_offset(other.org_id)
    # The busy org keeps its one running run.
    with _session(busy.org_id) as db:
        assert db.scalars(select(CheckRun.id)).all() == [busy_run]


def test_the_scheduler_lists_orgs_only_through_the_definer_function(org: Org) -> None:
    with get_sessionmaker()() as db:
        # Without an org context the app role sees no orgs' domain rows...
        assert db.scalar(text("SELECT count(*) FROM check_runs")) == 0
    created = create_scheduled_runs()
    assert [o for o, _ in created] == [org.org_id]


def test_the_periodic_task_is_registered_weekly() -> None:
    from passport.checks import jobs

    periodic = {p.task.name: p for p in app.periodic_registry.periodic_tasks.values()}
    assert periodic["passport.checks.schedule_weekly"].cron == jobs.WEEKLY_CRON
    assert jobs.WEEKLY_CRON.split()[-1] == "1"


# --- Verification: a seeded org's full run ---------------------------------------------


def test_a_seeded_org_full_run_records_coverage_counts(org: Org) -> None:
    connect(org, ConnectionKind.AWS, "AWS prod", [(ScopeKind.AWS_ACCOUNT, AWS_PROD)])
    connect(
        org, ConnectionKind.GOOGLE_WORKSPACE, "Workspace", [(ScopeKind.WORKSPACE_DOMAIN, DOMAIN)]
    )
    add_policy(
        org,
        [
            mfa_claim(),
            root_claim(),
            (MEMBERS[0], MEMBERS[1], {"scope": "all_orgs"}, ClaimState.CONFIRMED),
            ("Laptops are encrypted.", None, {}, ClaimState.UNCONFIRMED),
        ],
    )
    cloud = aws(
        {
            Capability.LIST_USERS_MFA: users_mfa({"alice": True, "bob": False}),
            Capability.GET_ROOT_MFA: root_ok(),
        }
    )
    google = FakeConnector(
        ConnectionKind.GOOGLE_WORKSPACE,
        scope=(DOMAIN,),
        responses={Capability.LIST_USERS_MFA: users_mfa({"carol": True})},
    )

    run_id = new_run(org)
    result = run_checks_for_org(
        org.org_id, run_id, connector_factory=factory({"AWS prod": cloud, "Workspace": google})
    )

    coverage = result["coverage"]
    assert (
        coverage["claims"],
        coverage["checked"],
        coverage["contradicted"],
        coverage["current"],
        coverage["check_failed"],
        coverage["not_checkable"],
    ) == (3, 2, 1, 1, 0, 1)
    assert {s["name"]: s["reachable"] for s in coverage["systems"]} == {
        "AWS prod": True,
        "Workspace": True,
    }
    with _session(org.org_id) as db:
        status = db.scalars(select(ItemStatus)).one()
        assert status.status == "contradicted"
        assert verify_chain(db, org.org_id).ok


def test_a_finished_run_queues_its_weekly_report(org: Org, monkeypatch: pytest.MonkeyPatch) -> None:
    from passport.checks import jobs as check_jobs

    run = new_run(org, ON_DEMAND)
    monkeypatch.setattr(check_jobs, "run_checks_for_org", lambda o, r: {"run_id": str(r)})
    connector = InMemoryConnector()

    with app.replace_connector(connector):
        check_jobs.run_org_checks(org_id=str(org.org_id), run_id=str(run))

    jobs = list(connector.jobs.values())
    assert [(j["task_name"], j["args"]["run_id"]) for j in jobs] == [
        ("passport.reports.build_and_send", str(run))
    ]
