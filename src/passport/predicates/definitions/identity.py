"""Identity predicates, served by AWS IAM or the Google Workspace directory.

Expected ``list_users_mfa`` rows: ``{"user": str, "mfa": bool}``.
"""

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

IDENTITY_SCOPE = ScopeRule(
    kinds=(ScopeKind.AWS_ACCOUNT, ScopeKind.WORKSPACE_DOMAIN),
    noun="AWS account and Google Workspace domain",
    named_noun="account or domain",
    named_plural="accounts and domains",
    keywords={"all_users": ALL, "all_production_accounts": PRODUCTION},
)


class MfaEnforcedParams(PredicateParams):
    pass


def _mfa_enforced(observed: Observed, params: MfaEnforcedParams) -> Outcome:
    return rows_where(observed, is_true("mfa"), field_label("user"))


MFA_ENFORCED = Predicate(
    id="mfa_enforced",
    version=1,
    title="Multi-factor authentication enforced",
    capability=Capability.LIST_USERS_MFA,
    params_model=MfaEnforcedParams,
    scope_rule=IDENTITY_SCOPE,
    description_template=(
        "Every user in {scope} has multi-factor authentication turned on."
        " Checked by listing each user and their MFA status in AWS IAM or the"
        " Google Workspace directory; any user without MFA is named."
    ),
    evaluate=_mfa_enforced,
)

PREDICATES: tuple[Predicate[MfaEnforcedParams], ...] = (MFA_ENFORCED,)
