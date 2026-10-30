"""The predicate registry: comparisons, scope coverage (R18, AE7), descriptions, versions."""

import importlib
from collections.abc import Mapping
from typing import Any

import pytest

from passport.connectors.base import Capability, collect
from passport.connectors.fakes import FakeConnector, FakeResponse, users_mfa
from passport.connectors.models import ConnectionKind
from passport.connectors.observation import Observed
from passport.controls.models import ScopeKind
from passport.predicates import registry
from passport.predicates.definitions import ALL_PREDICATES
from passport.predicates.registry import (
    SCOPE_NOT_DECLARED,
    UNCHECKED_SCOPE,
    DuplicatePredicateError,
    InvalidParametersError,
    InventoryEntry,
    ObservationMismatchError,
    Outcome,
    Predicate,
    PredicateParams,
    PredicateRegistry,
    ScopeRule,
    UnknownPredicateError,
)

PROD_A = "111111111111"
PROD_B = "222222222222"
STAGING = "333333333333"

TWO_PROD_ACCOUNTS = [
    InventoryEntry(ScopeKind.AWS_ACCOUNT, PROD_A, production=True),
    InventoryEntry(ScopeKind.AWS_ACCOUNT, PROD_B, production=True),
    InventoryEntry(ScopeKind.AWS_ACCOUNT, STAGING, production=False),
]


def observe(
    capability: Capability,
    response: FakeResponse,
    *,
    scope: tuple[str, ...] = (PROD_A,),
    kind: ConnectionKind = ConnectionKind.AWS,
) -> Observed:
    connector = FakeConnector(kind, scope=scope, responses={capability: response})
    result = collect(connector, capability)
    assert isinstance(result, Observed)
    return result


# --- mfa_enforced ----------------------------------------------------------------


def test_mfa_enforced_all_users_passes_when_every_user_has_mfa() -> None:
    observed = observe(Capability.LIST_USERS_MFA, users_mfa({"alice": True, "bob": True}))
    inventory = [InventoryEntry(ScopeKind.AWS_ACCOUNT, PROD_A, production=True)]

    result = registry.evaluate("mfa_enforced", 1, {"scope": "all_users"}, observed, inventory)

    assert result.passed
    assert result.offenders == ()
    assert not result.partially_checked
    assert result.coverage.checked == (PROD_A,)


def test_mfa_enforced_all_users_fails_naming_each_user_without_mfa() -> None:
    observed = observe(
        Capability.LIST_USERS_MFA,
        users_mfa({"alice": True, "bob": False, "carol": False}),
    )
    inventory = [InventoryEntry(ScopeKind.AWS_ACCOUNT, PROD_A, production=True)]

    result = registry.evaluate("mfa_enforced", 1, {"scope": "all_users"}, observed, inventory)

    assert not result.passed
    assert result.offenders == ("bob", "carol")
    # A failing claim is contradicted; the partial-scope flag is only for passes.
    assert not result.partially_checked


def test_mfa_enforced_combines_offenders_across_observations() -> None:
    aws = observe(Capability.LIST_USERS_MFA, users_mfa({"alice": True}), scope=(PROD_A,))
    workspace = observe(
        Capability.LIST_USERS_MFA,
        users_mfa({"dan@example.com": False}),
        scope=("example.com",),
        kind=ConnectionKind.GOOGLE_WORKSPACE,
    )
    inventory = [
        InventoryEntry(ScopeKind.AWS_ACCOUNT, PROD_A, production=True),
        InventoryEntry(ScopeKind.WORKSPACE_DOMAIN, "example.com", production=True),
    ]

    result = registry.evaluate(
        "mfa_enforced", 1, {"scope": "all_users"}, [aws, workspace], inventory
    )

    assert not result.passed
    assert result.offenders == ("dan@example.com",)
    assert result.coverage.checked == (PROD_A, "example.com")
    assert result.observed_scope == (PROD_A, "example.com")


# --- Scope coverage (R18, AE7) ---------------------------------------------------


def test_ae7_pass_on_one_of_two_production_accounts_is_partially_checked() -> None:
    observed = observe(Capability.LIST_USERS_MFA, users_mfa({"alice": True}), scope=(PROD_A,))

    result = registry.evaluate(
        "mfa_enforced",
        1,
        {"scope": "all_production_accounts"},
        observed,
        TWO_PROD_ACCOUNTS,
    )

    assert result.passed
    assert result.partially_checked
    assert result.partial_cause == UNCHECKED_SCOPE
    assert result.coverage.checked == (PROD_A,)
    assert result.coverage.unchecked == (PROD_B,)
    # The non-production account is outside the claim's scope, so it is not unchecked.
    assert STAGING not in result.coverage.declared


def test_ae7_same_claim_with_no_production_accounts_declared_is_scope_not_declared() -> None:
    observed = observe(Capability.LIST_USERS_MFA, users_mfa({"alice": True}), scope=(PROD_A,))
    no_production = [InventoryEntry(ScopeKind.AWS_ACCOUNT, PROD_A, production=False)]

    result = registry.evaluate(
        "mfa_enforced", 1, {"scope": "all_production_accounts"}, observed, no_production
    )

    assert result.passed
    assert result.partially_checked
    assert result.partial_cause == SCOPE_NOT_DECLARED
    assert result.coverage.declared == ()


def test_full_coverage_of_production_accounts_is_not_partial() -> None:
    observed = observe(
        Capability.LIST_USERS_MFA, users_mfa({"alice": True}), scope=(PROD_A, PROD_B)
    )

    result = registry.evaluate(
        "mfa_enforced", 1, {"scope": "all_production_accounts"}, observed, TWO_PROD_ACCOUNTS
    )

    assert result.passed
    assert not result.partially_checked
    assert result.partial_cause is None
    assert result.coverage.checked == (PROD_A, PROD_B)


def test_named_scope_names_unchecked_and_undeclared_identifiers() -> None:
    observed = observe(Capability.LIST_USERS_MFA, users_mfa({"alice": True}), scope=(PROD_A,))

    result = registry.evaluate(
        "mfa_enforced",
        1,
        {"scope": [PROD_A, PROD_B, "999999999999"]},
        observed,
        TWO_PROD_ACCOUNTS,
    )

    assert result.passed
    assert result.partially_checked
    assert result.coverage.unchecked == (PROD_B,)
    assert result.coverage.undeclared == ("999999999999",)


def test_inventory_entries_of_other_kinds_do_not_count_toward_scope() -> None:
    observed = observe(
        Capability.GET_ORG_TWO_FACTOR_REQUIREMENT,
        [{"org": "acme", "required": True}],
        scope=("acme",),
        kind=ConnectionKind.GITHUB,
    )

    # Only AWS accounts are declared: a GitHub claim's scope matches nothing.
    result = registry.evaluate(
        "github_org_2fa_required", 1, {"scope": "all_orgs"}, observed, TWO_PROD_ACCOUNTS
    )

    assert result.passed
    assert result.partial_cause == SCOPE_NOT_DECLARED


# --- Other predicates ------------------------------------------------------------


@pytest.mark.parametrize(
    ("predicate_id", "capability", "kind", "params", "passing", "failing", "offenders"),
    [
        (
            "root_mfa_enabled",
            Capability.GET_ROOT_MFA,
            ConnectionKind.AWS,
            {"scope": "all_accounts"},
            [{"account": PROD_A, "root_mfa": True}],
            [{"account": PROD_A, "root_mfa": False}],
            (PROD_A,),
        ),
        (
            "password_min_length",
            Capability.GET_PASSWORD_POLICY,
            ConnectionKind.AWS,
            {"scope": "all_accounts", "min_length": 14},
            [{"account": PROD_A, "minimum_length": 14}],
            [{"account": PROD_A, "minimum_length": 8}],
            (PROD_A,),
        ),
        (
            "cloudtrail_enabled",
            Capability.LIST_CLOUDTRAIL_TRAILS,
            ConnectionKind.AWS,
            {"scope": "all_accounts", "multi_region": True},
            [
                {"name": "org-trail", "logging": True, "multi_region": True},
                {"name": "old", "logging": False, "multi_region": False},
            ],
            [
                {"name": "local", "logging": True, "multi_region": False},
                {"name": "off", "logging": False, "multi_region": True},
            ],
            ("local", "off"),
        ),
        (
            "s3_encryption_enabled",
            Capability.LIST_S3_BUCKET_ENCRYPTION,
            ConnectionKind.AWS,
            {"scope": "all_accounts"},
            [{"bucket": "logs", "encrypted": True}],
            [{"bucket": "logs", "encrypted": True}, {"bucket": "raw", "encrypted": False}],
            ("raw",),
        ),
        (
            "s3_public_access_blocked",
            Capability.GET_S3_PUBLIC_ACCESS_BLOCK,
            ConnectionKind.AWS,
            {"scope": "all_accounts"},
            [
                {
                    "account": PROD_A,
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": True,
                    "restrict_public_buckets": True,
                }
            ],
            [
                {
                    "account": PROD_A,
                    "block_public_acls": True,
                    "ignore_public_acls": True,
                    "block_public_policy": False,
                    "restrict_public_buckets": True,
                }
            ],
            (PROD_A,),
        ),
        (
            "github_org_2fa_required",
            Capability.GET_ORG_TWO_FACTOR_REQUIREMENT,
            ConnectionKind.GITHUB,
            {"scope": "all_orgs"},
            [{"org": "acme", "required": True}],
            [{"org": "acme", "required": False}],
            ("acme",),
        ),
        (
            "github_members_2fa_enabled",
            Capability.LIST_ORG_MEMBERS,
            ConnectionKind.GITHUB,
            {"scope": "all_orgs"},
            [{"login": "octocat", "two_factor_enabled": True}],
            [{"login": "octocat", "two_factor_enabled": False}],
            ("octocat",),
        ),
        (
            "branch_protection_required",
            Capability.GET_BRANCH_PROTECTION,
            ConnectionKind.GITHUB,
            {"scope": "all_orgs", "min_reviews": 2},
            [{"repo": "api", "branch": "main", "protected": True, "required_reviews": 2}],
            [
                {"repo": "api", "branch": "main", "protected": True, "required_reviews": 1},
                {"repo": "web", "branch": "main", "protected": False, "required_reviews": 0},
                {"repo": "ok", "branch": "main", "protected": True, "required_reviews": 3},
            ],
            ("api:main", "web:main"),
        ),
    ],
)
def test_each_predicate_passes_and_fails_naming_offenders(
    predicate_id: str,
    capability: Capability,
    kind: ConnectionKind,
    params: dict[str, Any],
    passing: list[dict[str, Any]],
    failing: list[dict[str, Any]],
    offenders: tuple[str, ...],
) -> None:
    scope = ("acme",) if kind is ConnectionKind.GITHUB else (PROD_A,)
    inventory = [
        InventoryEntry(ScopeKind.AWS_ACCOUNT, PROD_A, production=True),
        InventoryEntry(ScopeKind.GITHUB_ORG, "acme", production=True),
    ]

    good = registry.evaluate(
        predicate_id, 1, params, observe(capability, passing, scope=scope, kind=kind), inventory
    )
    bad = registry.evaluate(
        predicate_id, 1, params, observe(capability, failing, scope=scope, kind=kind), inventory
    )

    assert good.passed and good.offenders == ()
    assert not good.partially_checked
    assert not bad.passed
    assert bad.offenders == offenders


def test_a_row_missing_the_compared_field_never_passes() -> None:
    observed = observe(Capability.GET_ROOT_MFA, [{"account": PROD_A}])

    result = registry.evaluate("root_mfa_enabled", 1, {"scope": "all_accounts"}, observed, [])

    assert not result.passed
    assert result.offenders == (PROD_A,)


def test_cloudtrail_without_multi_region_requirement_accepts_a_single_region_trail() -> None:
    observed = observe(
        Capability.LIST_CLOUDTRAIL_TRAILS,
        [{"name": "local", "logging": True, "multi_region": False}],
    )

    result = registry.evaluate(
        "cloudtrail_enabled", 1, {"scope": "all_accounts", "multi_region": False}, observed, []
    )

    assert result.passed


# --- Parameters ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("predicate_id", "params"),
    [
        ("password_min_length", {"scope": "all_accounts", "min_length": -1}),
        ("password_min_length", {"scope": "all_accounts", "min_length": 0}),
        ("password_min_length", {"scope": "all_accounts"}),
        ("branch_protection_required", {"scope": "all_orgs", "min_reviews": -2}),
        ("mfa_enforced", {"scope": "everyone"}),
        ("mfa_enforced", {"scope": []}),
        ("mfa_enforced", {"scope": "all_users", "unexpected": True}),
        ("mfa_enforced", {}),
    ],
)
def test_invalid_parameters_are_rejected(predicate_id: str, params: Mapping[str, Any]) -> None:
    observed = observe(Capability.LIST_USERS_MFA, users_mfa({"alice": True}))

    with pytest.raises(InvalidParametersError, match=predicate_id):
        registry.get(predicate_id, 1).parse_params(params)
    with pytest.raises(InvalidParametersError):
        registry.describe(predicate_id, 1, params)
    if predicate_id == "mfa_enforced":
        with pytest.raises(InvalidParametersError):
            registry.evaluate(predicate_id, 1, params, observed, [])


def test_unknown_predicate_or_version_raises() -> None:
    with pytest.raises(UnknownPredicateError, match="no_such_check"):
        registry.get("no_such_check", 1)
    with pytest.raises(UnknownPredicateError, match="version 99"):
        registry.get("mfa_enforced", 99)


def test_an_observation_of_another_capability_is_refused() -> None:
    observed = observe(Capability.GET_ROOT_MFA, [{"account": PROD_A, "root_mfa": True}])

    with pytest.raises(ObservationMismatchError):
        registry.evaluate("mfa_enforced", 1, {"scope": "all_users"}, observed, [])


def test_evaluate_needs_at_least_one_observation() -> None:
    with pytest.raises(ValueError, match="at least one observation"):
        registry.evaluate("mfa_enforced", 1, {"scope": "all_users"}, [], [])


# --- Descriptions (R7) -----------------------------------------------------------


SAMPLE_PARAMS: dict[str, dict[str, Any]] = {
    "mfa_enforced": {"scope": "all_production_accounts"},
    "root_mfa_enabled": {"scope": "all_accounts"},
    "password_min_length": {"scope": [PROD_A], "min_length": 14},
    "cloudtrail_enabled": {"scope": "all_production_accounts", "multi_region": True},
    "s3_encryption_enabled": {"scope": "all_accounts"},
    "s3_public_access_blocked": {"scope": "all_production_accounts"},
    "github_org_2fa_required": {"scope": "all_orgs"},
    "github_members_2fa_enabled": {"scope": ["acme"]},
    "branch_protection_required": {"scope": "all_production_orgs", "min_reviews": 2},
}


def test_every_registered_predicate_has_sample_parameters_here() -> None:
    assert {p.id for p in registry.all()} == set(SAMPLE_PARAMS)


@pytest.mark.parametrize("predicate_id", sorted(SAMPLE_PARAMS))
def test_description_renders_a_readable_sentence(predicate_id: str) -> None:
    text = registry.describe(predicate_id, 1, SAMPLE_PARAMS[predicate_id])

    assert text[0].isupper() and text.endswith(".")
    assert "{" not in text and "}" not in text
    assert "_" not in text  # no raw parameter names or scope keywords leak through


def test_descriptions_carry_parameter_values() -> None:
    assert registry.describe(
        "password_min_length", 1, {"scope": [PROD_A], "min_length": 14}
    ).startswith(
        f"The AWS account password policy in AWS account {PROD_A} requires passwords"
        " of at least 14 characters."
    )
    assert registry.describe(
        "cloudtrail_enabled", 1, {"scope": "all_accounts", "multi_region": True}
    ).startswith("Every AWS account has at least one CloudTrail trail that is logging covering")
    assert "covering" not in registry.describe(
        "cloudtrail_enabled", 1, {"scope": "all_accounts", "multi_region": False}
    )
    assert "at least 2 approving reviews" in registry.describe(
        "branch_protection_required", 1, {"scope": "all_orgs", "min_reviews": 2}
    )
    assert "every production AWS account and Google Workspace domain" in registry.describe(
        "mfa_enforced", 1, {"scope": "all_production_accounts"}
    )


def test_registry_lists_every_predicate_with_capability_and_description() -> None:
    listed = registry.all()
    assert listed == sorted(listed, key=lambda p: (p.id, p.version))
    for predicate in listed:
        assert predicate.title
        assert predicate.description_template
        assert isinstance(predicate.capability, Capability)


def test_registry_module_docstring_lists_every_predicate() -> None:
    module = importlib.import_module("passport.predicates.registry")
    assert module.__doc__ is not None
    for predicate in registry.all():
        assert f"``{predicate.id}``" in module.__doc__


# --- Versions --------------------------------------------------------------------


class _StrictParams(PredicateParams):
    pass


def _strict_v2(observed: Observed, params: _StrictParams) -> Outcome:
    # Version 2 never passes, so a claim evaluated with it differs observably.
    offenders = [str(r["user"]) for r in observed.rows if r.get("mfa") is not True]
    return Outcome(passed=False, offenders=tuple(offenders) or ("v2",))


def test_a_claim_on_version_1_still_evaluates_with_version_1_after_version_2() -> None:
    local = PredicateRegistry()
    for predicate in ALL_PREDICATES:
        local.register(predicate)
    v1 = local.get("mfa_enforced", 1)
    observed = observe(Capability.LIST_USERS_MFA, users_mfa({"alice": True}))
    before = local.evaluate("mfa_enforced", 1, {"scope": "all_users"}, observed, [])

    local.register(
        Predicate(
            id="mfa_enforced",
            version=2,
            title="MFA enforced (strict)",
            capability=Capability.LIST_USERS_MFA,
            params_model=_StrictParams,
            scope_rule=v1.scope_rule,
            description_template="Every user in {scope} has MFA (strict).",
            evaluate=_strict_v2,
        )
    )

    after = local.evaluate("mfa_enforced", 1, {"scope": "all_users"}, observed, [])
    v2 = local.evaluate("mfa_enforced", 2, {"scope": "all_users"}, observed, [])
    assert local.get("mfa_enforced", 1) is v1
    assert before.passed and after.passed and after.version == 1
    assert not v2.passed and v2.version == 2
    assert local.latest("mfa_enforced").version == 2


def test_registering_the_same_id_and_version_twice_is_refused() -> None:
    local = PredicateRegistry()
    predicate = ALL_PREDICATES[0]
    local.register(predicate)

    with pytest.raises(DuplicatePredicateError):
        local.register(predicate)


def test_scope_rule_keywords_must_resolve_to_a_known_selector() -> None:
    with pytest.raises(ValueError, match="selector"):
        ScopeRule(kinds=(ScopeKind.AWS_ACCOUNT,), noun="AWS account", keywords={"x": "bogus"})
