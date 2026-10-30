"""GitHub code-hosting predicates.

Expected rows per capability:

- ``get_org_two_factor_requirement``: ``{"org": str, "required": bool}``
- ``list_org_members``: ``{"login": str, "two_factor_enabled": bool}``
- ``get_branch_protection``: ``{"repo": str, "branch": str, "protected": bool,
  "required_reviews": int}``, one row per repository's default branch
"""

from collections.abc import Mapping
from typing import Any

from pydantic import Field

from passport.connectors.base import Capability
from passport.connectors.observation import Observed
from passport.controls.models import ScopeKind
from passport.predicates.registry import (
    ALL,
    PRODUCTION,
    Outcome,
    Predicate,
    PredicateParams,
    ScopeRule,
    field_label,
    is_true,
    rows_where,
)

GITHUB_SCOPE = ScopeRule(
    kinds=(ScopeKind.GITHUB_ORG,),
    noun="GitHub organization",
    keywords={"all_orgs": ALL, "all_production_orgs": PRODUCTION},
)


class OrgParams(PredicateParams):
    """Parameters for a GitHub predicate with no setting beyond its scope."""


# --- github_org_2fa_required -----------------------------------------------------


def _org_2fa_required(observed: Observed, params: OrgParams) -> Outcome:
    return rows_where(observed, is_true("required"), field_label("org"))


GITHUB_ORG_2FA_REQUIRED = Predicate(
    id="github_org_2fa_required",
    version=1,
    title="GitHub organization requires 2FA",
    capability=Capability.GET_ORG_TWO_FACTOR_REQUIREMENT,
    params_model=OrgParams,
    scope_rule=GITHUB_SCOPE,
    description_template=(
        "{scope} requires two-factor authentication for all members."
        " Checked by reading the organization's two-factor requirement setting."
    ),
    evaluate=_org_2fa_required,
)


# --- github_members_2fa_enabled --------------------------------------------------


def _members_2fa_enabled(observed: Observed, params: OrgParams) -> Outcome:
    return rows_where(observed, is_true("two_factor_enabled"), field_label("login"))


GITHUB_MEMBERS_2FA_ENABLED = Predicate(
    id="github_members_2fa_enabled",
    version=1,
    title="GitHub members use 2FA",
    capability=Capability.LIST_ORG_MEMBERS,
    params_model=OrgParams,
    scope_rule=GITHUB_SCOPE,
    description_template=(
        "Every member of {scope} has two-factor authentication turned on."
        " Checked by listing the organization's members; any member without it is named."
    ),
    evaluate=_members_2fa_enabled,
)


# --- branch_protection_required --------------------------------------------------


class BranchProtectionParams(PredicateParams):
    min_reviews: int = Field(default=1, ge=0, le=6)


def _branch_protection_required(observed: Observed, params: BranchProtectionParams) -> Outcome:
    def protected(row: Mapping[str, Any]) -> bool:
        reviews = row.get("required_reviews")
        return (
            row.get("protected") is True
            and isinstance(reviews, int)
            and reviews >= params.min_reviews
        )

    def label(row: Mapping[str, Any]) -> str:
        return f"{row.get('repo', 'unnamed')}:{row.get('branch', 'default')}"

    return rows_where(observed, protected, label)


def _branch_protection_extra(params: BranchProtectionParams) -> Mapping[str, object]:
    reviews = params.min_reviews
    if reviews == 0:
        return {"reviews": ""}
    noun = "review" if reviews == 1 else "reviews"
    return {"reviews": f" and needs at least {reviews} approving {noun} before merging"}


BRANCH_PROTECTION_REQUIRED = Predicate(
    id="branch_protection_required",
    version=1,
    title="Branch protection required",
    capability=Capability.GET_BRANCH_PROTECTION,
    params_model=BranchProtectionParams,
    scope_rule=GITHUB_SCOPE,
    description_template=(
        "The default branch of every repository in {scope} is protected{reviews}."
        " Checked by reading each default branch's protection rules; any branch"
        " falling short is named."
    ),
    evaluate=_branch_protection_required,
    describe_extra=_branch_protection_extra,
)


PREDICATES: tuple[Predicate[Any], ...] = (
    GITHUB_ORG_2FA_REQUIRED,
    GITHUB_MEMBERS_2FA_ENABLED,
    BRANCH_PROTECTION_REQUIRED,
)
