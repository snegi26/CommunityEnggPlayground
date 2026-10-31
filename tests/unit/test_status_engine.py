"""Status engine (U12): pure, table-driven cases for R2, R3, R8, R9, R17, R18, R19."""

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest

import passport.predicates.definitions  # noqa: F401  (registers v1 predicates)
from passport.connectors.base import Capability
from passport.connectors.fakes import FakeConnector, users_mfa
from passport.connectors.models import ConnectionKind
from passport.connectors.observation import Observed
from passport.controls.models import AuditType, Framework, ItemKind, ScopeKind
from passport.db.models import ClaimState
from passport.predicates.registry import InventoryEntry, registry
from passport.status.engine import (
    SEVERITY,
    ClaimCheck,
    ClaimInput,
    EvaluationFacts,
    FrameworkSettings,
    ItemInput,
    ItemResult,
    Status,
    SystemRead,
    evaluate_item,
    worst,
)

TODAY = date(2026, 10, 30)
CHECKED = datetime(2026, 10, 26, 3, tzinfo=UTC)
PROD, STAGING = "111111111111", "222222222222"

SOC2 = FrameworkSettings(
    Framework.SOC2,
    AuditType.SOC2_TYPE2,
    window_start=date(2026, 1, 1),
    window_end=date(2026, 12, 31),
)
ISO = FrameworkSettings(
    Framework.ISO27001,
    AuditType.ISO27001_CERTIFICATION,
    window_start=date(2026, 6, 1),
    window_end=date(2027, 5, 31),
)
SETTINGS = {Framework.SOC2: SOC2, Framework.ISO27001: ISO}


def aws_read(outcome: str = "observed", rows: int = 2, complete: bool = True) -> SystemRead:
    return SystemRead(
        connection_id="c-aws",
        name="AWS prod",
        kind="aws",
        scope=(PROD,),
        outcome=outcome,
        complete=complete,
        row_count=rows,
        collected_at=CHECKED,
    )


def passed(**facts: object) -> ClaimCheck:
    return ClaimCheck(
        checked_at=CHECKED,
        systems=(aws_read(),),
        evaluation=EvaluationFacts(passed=True, observed_scope=(PROD,), checked=(PROD,), **facts),  # type: ignore[arg-type]
    )


def contradicted(*offenders: str) -> ClaimCheck:
    return ClaimCheck(
        checked_at=CHECKED,
        systems=(aws_read(),),
        evaluation=EvaluationFacts(passed=False, offenders=offenders, observed_scope=(PROD,)),
    )


def failed(kind: str = "unauthorized") -> ClaimCheck:
    return ClaimCheck(checked_at=CHECKED, systems=(aws_read(kind, rows=0, complete=False),))


def claim(
    check: ClaimCheck | None,
    state: ClaimState = ClaimState.CONFIRMED,
    *,
    quote: str = "MFA is required on all production accounts.",
    predicate: str | None = "mfa_enforced",
    served: bool = True,
    last_verified_at: datetime | None = None,
) -> ClaimInput:
    return ClaimInput(
        claim_id=uuid.uuid4(),
        quote=quote,
        predicate_id=predicate,
        state=state,
        served=served,
        latest=check,
        last_verified_at=last_verified_at,
    )


def policy(*claims: ClaimInput, **kwargs: object) -> ItemInput:
    return ItemInput(
        kind=ItemKind.DOCUMENT,
        item_id=uuid.uuid4(),
        title="Access policy",
        claims=claims,
        frameworks=kwargs.pop("frameworks", (Framework.SOC2,)),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


def evidence(collected: date, **kwargs: object) -> ItemInput:
    return ItemInput(
        kind=ItemKind.EVIDENCE,
        item_id=uuid.uuid4(),
        title="Access review export",
        collected_at=datetime.combine(collected, datetime.min.time(), UTC),
        frameworks=kwargs.pop("frameworks", (Framework.SOC2,)),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


def one(item: ItemInput, settings: dict[Framework, FrameworkSettings] = SETTINGS) -> ItemResult:
    [result] = evaluate_item(item, settings, TODAY)
    return result


def kinds(result: ItemResult) -> list[str]:
    return [c.kind for c in result.causes]


def text(result: ItemResult) -> str:
    return " ".join(c.text for c in result.causes)


# --- Acceptance examples --------------------------------------------------------------


def test_ae1_one_contradicted_confirmed_claim_among_four_passing_is_contradicted_and_trusted() -> (
    None
):
    result = one(policy(claim(contradicted("bob")), *(claim(passed()) for _ in range(4))))
    assert (result.status, result.trusted) == (Status.CONTRADICTED, True)
    assert kinds(result) == ["contradicted"]
    assert "bob" in result.causes[0].text and "AWS prod (111111111111)" in result.causes[0].text
    assert result.causes[0].fields["offenders"] == ["bob"]


def test_ae2_the_same_contradiction_on_an_unconfirmed_claim_is_untrusted() -> None:
    result = one(policy(claim(contradicted("bob"), ClaimState.UNCONFIRMED)))
    assert (result.status, result.trusted) == (Status.CONTRADICTED, False)
    assert kinds(result) == ["contradicted", "unconfirmed"]


def test_ae3_evidence_collected_a_day_before_the_window_is_expired_with_both_dates() -> None:
    result = one(evidence(date(2025, 12, 31)))
    assert result.status is Status.EXPIRED
    assert "2026-01-01" in text(result) and "2026-12-31" in text(result)
    assert result.causes[0].fields["collected_on"] == "2025-12-31"


def test_ae6_a_failed_check_with_a_prior_success_shows_the_last_verified_date() -> None:
    last = datetime(2026, 10, 19, 3, tzinfo=UTC)
    result = one(policy(claim(failed(), last_verified_at=last)))
    assert result.status is Status.CHECK_FAILED
    assert "Last verified on 2026-10-19" in text(result)
    assert "access was denied" in text(result)


def test_ae6_a_failed_check_never_verified_says_so() -> None:
    result = one(policy(claim(failed("rate_limited"))))
    assert result.status is Status.CHECK_FAILED
    assert "Never verified successfully" in text(result)


def test_ae7_a_partial_scope_pass_is_current_and_flagged_partially_checked() -> None:
    inventory = [
        InventoryEntry(ScopeKind.AWS_ACCOUNT, PROD, production=True),
        InventoryEntry(ScopeKind.AWS_ACCOUNT, STAGING, production=True),
    ]
    fake = FakeConnector(
        ConnectionKind.AWS,
        scope=(PROD,),
        responses={Capability.LIST_USERS_MFA: users_mfa({"alice": True})},
    )
    observed = fake.list_users_mfa()
    assert isinstance(observed, Observed)
    evaluation = registry.evaluate(
        "mfa_enforced", 1, {"scope": "all_production_accounts"}, observed, inventory
    )
    check = ClaimCheck(
        checked_at=CHECKED,
        systems=(aws_read(rows=1),),
        evaluation=EvaluationFacts.from_evaluation(evaluation),
    )
    result = one(policy(claim(check)))
    assert (result.status, result.trusted) == (Status.CURRENT, True)
    assert kinds(result) == ["all_passed", "partially_checked"]
    flag = result.causes[1]
    assert flag.status is None
    assert flag.fields["checked"] == [PROD] and flag.fields["unchecked"] == [STAGING]
    assert PROD in flag.text and f"{STAGING} was not checked" in flag.text


# --- Rollup and trust ------------------------------------------------------------------


def test_all_passing_but_one_unconfirmed_is_unconfirmed_and_untrusted() -> None:
    result = one(policy(claim(passed()), claim(passed(), ClaimState.NEEDS_REVIEW)))
    assert (result.status, result.trusted) == (Status.UNCONFIRMED, False)
    assert kinds(result) == ["unconfirmed"]


def test_a_confirmed_contradiction_stays_trusted_beside_an_unrelated_unconfirmed_claim() -> None:
    result = one(policy(claim(contradicted("bob")), claim(passed(), ClaimState.UNCONFIRMED)))
    assert (result.status, result.trusted) == (Status.CONTRADICTED, True)
    assert kinds(result) == ["contradicted", "unconfirmed"]


@pytest.mark.parametrize(
    "claims",
    [
        (),
        (claim(None, ClaimState.UNCONFIRMED, predicate=None),),
    ],
    ids=["no claims", "only not-checkable claims"],
)
def test_an_item_with_no_claims_or_only_not_checkable_claims_is_untrusted(
    claims: tuple[ClaimInput, ...],
) -> None:
    result = one(policy(*claims))
    assert result.status is Status.NOT_CHECKABLE
    assert result.trusted is False


def test_an_item_whose_only_claims_are_not_checkable_shows_not_checkable() -> None:
    result = one(policy(claim(None, ClaimState.UNCONFIRMED, predicate=None, served=False)))
    assert result.status is Status.NOT_CHECKABLE
    assert "No supported check covers" in text(result)


def test_an_item_both_expired_and_contradicted_shows_contradicted_with_both_causes() -> None:
    result = one(policy(claim(contradicted("bob")), review_due_on=date(2026, 10, 1)))
    assert result.status is Status.CONTRADICTED
    assert kinds(result) == ["contradicted", "review_overdue"]
    assert "2026-10-01" in text(result)


def test_a_contradiction_on_one_system_stands_beside_a_failure_on_another() -> None:
    google = SystemRead(
        connection_id="c-g",
        name="Workspace",
        kind="google_workspace",
        scope=("example.com",),
        outcome="unauthorized",
        complete=False,
    )
    check = ClaimCheck(
        checked_at=CHECKED,
        systems=(aws_read(), google),
        evaluation=EvaluationFacts(passed=False, offenders=("bob",), observed_scope=(PROD,)),
    )
    result = one(policy(claim(check)))
    assert result.status is Status.CONTRADICTED
    assert kinds(result) == ["contradicted", "check_failed"]


# --- Not checkable (KTD7) ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("check", "served", "phrase"),
    [
        (
            ClaimCheck(checked_at=CHECKED, systems=(aws_read(rows=0),)),
            True,
            "returned no records",
        ),
        (
            ClaimCheck(checked_at=CHECKED, systems=(aws_read(complete=False),)),
            True,
            "incomplete records",
        ),
        (passed(), False, "No connected system can check"),
        (None, True, "has not been checked yet"),
    ],
    ids=["empty read", "incomplete read", "no connected system", "never checked"],
)
def test_reads_that_cannot_be_evaluated_are_not_checkable_never_current(
    check: ClaimCheck | None, served: bool, phrase: str
) -> None:
    result = one(policy(claim(check, served=served)))
    assert result.status is Status.NOT_CHECKABLE
    assert phrase in text(result)
    # A confirmed checkable claim keeps the item's trust; the status is still not current.
    assert result.trusted is True


# --- Dates per framework (R9, R19) -------------------------------------------------------


def test_evidence_inside_the_soc2_window_but_outside_the_iso_window_differs_by_view() -> None:
    results = evaluate_item(
        evidence(date(2026, 3, 1), frameworks=(Framework.SOC2, Framework.ISO27001)),
        SETTINGS,
        TODAY,
    )
    by_framework = {r.framework: r.status for r in results}
    assert by_framework == {Framework.SOC2: Status.CURRENT, Framework.ISO27001: Status.EXPIRED}


def test_a_review_date_twenty_days_away_with_a_thirty_day_lead_is_expiring_soon() -> None:
    result = one(policy(claim(passed()), review_due_on=TODAY + timedelta(days=20)))
    assert result.status is Status.EXPIRING_SOON
    assert result.trusted is True
    assert "2026-11-19" in text(result) and "30-day" in text(result)


def test_a_review_date_past_due_is_expired() -> None:
    result = one(policy(claim(passed()), review_due_on=TODAY - timedelta(days=1)))
    assert result.status is Status.EXPIRED


def test_a_review_date_beyond_the_lead_time_is_current() -> None:
    result = one(policy(claim(passed()), review_due_on=TODAY + timedelta(days=31)))
    assert result.status is Status.CURRENT


def test_an_audit_window_ending_within_the_lead_time_is_expiring_soon() -> None:
    ending = FrameworkSettings(
        Framework.SOC2,
        AuditType.SOC2_TYPE2,
        window_start=date(2026, 1, 1),
        window_end=TODAY + timedelta(days=10),
    )
    result = one(evidence(date(2026, 5, 1)), {Framework.SOC2: ending})
    assert result.status is Status.EXPIRING_SOON
    assert kinds(result) == ["window_ending"]


def test_a_soc2_type1_org_has_no_outside_window_check() -> None:
    type1 = FrameworkSettings(Framework.SOC2, AuditType.SOC2_TYPE1, as_of_date=date(2026, 9, 30))
    result = one(
        evidence(date(2026, 10, 15), review_due_on=date(2027, 1, 1)), {Framework.SOC2: type1}
    )
    assert result.status is Status.CURRENT
    assert "outside_window" not in kinds(result)


def test_an_unmapped_item_uses_the_first_configured_framework_and_is_labelled() -> None:
    results = evaluate_item(
        policy(claim(passed()), frameworks=()), {Framework.ISO27001: ISO}, TODAY
    )
    [result] = results
    assert (result.framework, result.unmapped) == (Framework.ISO27001, True)
    assert result.causes[-1].kind == "unmapped"
    assert "ISO" in result.causes[-1].text or "iso27001" in result.causes[-1].text


# --- Ordering and reachability -------------------------------------------------------


def test_severity_order_matches_r17() -> None:
    assert [s.value for s in SEVERITY] == [
        "contradicted",
        "expired",
        "check_failed",
        "expiring_soon",
        "unconfirmed",
        "not_checkable",
        "current",
    ]
    assert worst([Status.CURRENT, Status.UNCONFIRMED, Status.CHECK_FAILED]) is Status.CHECK_FAILED
    assert worst([Status.EXPIRING_SOON, Status.EXPIRED]) is Status.EXPIRED
    assert worst([Status.NOT_CHECKABLE, Status.UNCONFIRMED]) is Status.UNCONFIRMED


def test_every_r2_status_is_reachable() -> None:
    reached = {
        one(policy(claim(contradicted("bob")))).status,
        one(policy(claim(passed()), review_due_on=TODAY - timedelta(days=1))).status,
        one(policy(claim(failed()))).status,
        one(policy(claim(passed()), review_due_on=TODAY + timedelta(days=5))).status,
        one(policy(claim(passed(), ClaimState.UNCONFIRMED))).status,
        one(policy(claim(None, predicate=None))).status,
        one(policy(claim(passed()))).status,
    }
    assert reached == set(Status)


def test_the_same_inputs_give_identical_causes() -> None:
    item = policy(claim(contradicted("bob")), review_due_on=date(2026, 10, 1))
    first = evaluate_item(item, SETTINGS, TODAY)
    later = evaluate_item(item, SETTINGS, TODAY + timedelta(days=3))
    assert [r.causes_json() for r in first] == [r.causes_json() for r in later]


def test_a_review_due_today_is_expiring_soon_not_yet_expired() -> None:
    result = one(policy(claim(passed()), review_due_on=TODAY))
    assert result.status is Status.EXPIRING_SOON
