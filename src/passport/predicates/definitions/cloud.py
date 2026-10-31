"""AWS cloud predicates.

Expected rows per capability:

- ``get_root_mfa``: ``{"account": str, "root_mfa": bool}``
- ``get_password_policy``: ``{"account": str, "minimum_length": int}``
- ``list_cloudtrail_trails``: ``{"name": str, "logging": bool, "multi_region": bool}``
- ``list_s3_bucket_encryption``: ``{"bucket": str, "encrypted": bool}``
- ``get_s3_public_access_block``: ``{"account": str}`` plus the four boolean settings
  ``block_public_acls``, ``ignore_public_acls``, ``block_public_policy`` and
  ``restrict_public_buckets``
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

AWS_SCOPE = ScopeRule(
    kinds=(ScopeKind.AWS_ACCOUNT,),
    noun="AWS account",
    keywords={"all_accounts": ALL, "all_production_accounts": PRODUCTION},
)


class AccountParams(PredicateParams):
    """Parameters for an AWS predicate with no setting beyond its scope."""


def _root_mfa_enabled(observed: Observed, params: AccountParams) -> Outcome:
    return rows_where(observed, is_true("root_mfa"), field_label("account"))


ROOT_MFA_ENABLED = Predicate(
    id="root_mfa_enabled",
    version=1,
    title="Root user MFA enabled",
    capability=Capability.GET_ROOT_MFA,
    params_model=AccountParams,
    scope_rule=AWS_SCOPE,
    description_template=(
        "The root user of {scope} has multi-factor authentication turned on."
        " Checked by reading the account summary in AWS IAM."
    ),
    evaluate=_root_mfa_enabled,
)


class PasswordMinLengthParams(PredicateParams):
    min_length: int = Field(ge=1, le=128)


def _password_min_length(observed: Observed, params: PasswordMinLengthParams) -> Outcome:
    def long_enough(row: Mapping[str, Any]) -> bool:
        length = row.get("minimum_length")
        return isinstance(length, int) and length >= params.min_length

    return rows_where(observed, long_enough, field_label("account"))


PASSWORD_MIN_LENGTH = Predicate(
    id="password_min_length",
    version=1,
    title="Minimum password length",
    capability=Capability.GET_PASSWORD_POLICY,
    params_model=PasswordMinLengthParams,
    scope_rule=AWS_SCOPE,
    description_template=(
        "The AWS account password policy in {scope} requires passwords of at least"
        " {min_length} characters. Checked by reading the IAM account password policy."
    ),
    evaluate=_password_min_length,
)


class CloudTrailParams(PredicateParams):
    multi_region: bool = True


def _cloudtrail_enabled(observed: Observed, params: CloudTrailParams) -> Outcome:
    def qualifies(row: Mapping[str, Any]) -> bool:
        return row.get("logging") is True and (
            not params.multi_region or row.get("multi_region") is True
        )

    if any(qualifies(row) for row in observed.rows):
        return Outcome(passed=True)
    # No trail qualifies: name each trail that falls short.
    return rows_where(observed, qualifies, field_label("name"))


def _cloudtrail_extra(params: CloudTrailParams) -> Mapping[str, object]:
    return {"regions": " covering every region" if params.multi_region else ""}


CLOUDTRAIL_ENABLED = Predicate(
    id="cloudtrail_enabled",
    version=1,
    title="CloudTrail logging enabled",
    capability=Capability.LIST_CLOUDTRAIL_TRAILS,
    params_model=CloudTrailParams,
    scope_rule=AWS_SCOPE,
    description_template=(
        "{scope} has at least one CloudTrail trail that is logging{regions}."
        " Checked by listing the account's trails and their logging status."
    ),
    evaluate=_cloudtrail_enabled,
    describe_extra=_cloudtrail_extra,
)


def _s3_encryption_enabled(observed: Observed, params: AccountParams) -> Outcome:
    return rows_where(observed, is_true("encrypted"), field_label("bucket"))


S3_ENCRYPTION_ENABLED = Predicate(
    id="s3_encryption_enabled",
    version=1,
    title="S3 default encryption enabled",
    capability=Capability.LIST_S3_BUCKET_ENCRYPTION,
    params_model=AccountParams,
    scope_rule=AWS_SCOPE,
    description_template=(
        "Every S3 bucket in {scope} encrypts stored data by default."
        " Checked by reading each bucket's default encryption setting; any bucket"
        " without it is named."
    ),
    evaluate=_s3_encryption_enabled,
)


PUBLIC_ACCESS_SETTINGS = (
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
)


def _s3_public_access_blocked(observed: Observed, params: AccountParams) -> Outcome:
    def all_blocked(row: Mapping[str, Any]) -> bool:
        return all(row.get(setting) is True for setting in PUBLIC_ACCESS_SETTINGS)

    return rows_where(observed, all_blocked, field_label("account", "bucket"))


S3_PUBLIC_ACCESS_BLOCKED = Predicate(
    id="s3_public_access_blocked",
    version=1,
    title="S3 public access blocked",
    capability=Capability.GET_S3_PUBLIC_ACCESS_BLOCK,
    params_model=AccountParams,
    scope_rule=AWS_SCOPE,
    description_template=(
        "S3 Block Public Access is fully turned on in {scope}."
        " Checked by reading the account's four Block Public Access settings."
    ),
    evaluate=_s3_public_access_blocked,
)


PREDICATES: tuple[Predicate[Any], ...] = (
    ROOT_MFA_ENABLED,
    PASSWORD_MIN_LENGTH,
    CLOUDTRAIL_ENABLED,
    S3_ENCRYPTION_ENABLED,
    S3_PUBLIC_ACCESS_BLOCKED,
)
