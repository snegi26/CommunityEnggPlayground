"""The read-only connector interface (R5, KTD7).

A connector exposes one method per capability, each named for what it reads and
taking no arguments, so there is no way to send a provider an arbitrary request
or a write. Each method returns an :class:`~passport.connectors.observation.Observed`
or a typed :class:`~passport.connectors.observation.Failure`.
"""

import enum
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any

from passport.connectors.models import ConnectionKind

if TYPE_CHECKING:
    from passport.connectors.observation import CollectionResult, Failure, FailureKind


class Capability(enum.StrEnum):
    """Every read a connector may perform. Predicates name the one they need."""

    # AWS
    LIST_ACCOUNTS = "list_accounts"
    LIST_USERS_MFA = "list_users_mfa"
    GET_ROOT_MFA = "get_root_mfa"
    GET_PASSWORD_POLICY = "get_password_policy"  # noqa: S105 - a capability name
    LIST_CLOUDTRAIL_TRAILS = "list_cloudtrail_trails"
    LIST_S3_BUCKET_ENCRYPTION = "list_s3_bucket_encryption"
    GET_S3_PUBLIC_ACCESS_BLOCK = "get_s3_public_access_block"
    # GitHub
    GET_ORG_TWO_FACTOR_REQUIREMENT = "get_org_two_factor_requirement"
    LIST_ORG_MEMBERS = "list_org_members"
    GET_BRANCH_PROTECTION = "get_branch_protection"


class UnsupportedCapabilityError(NotImplementedError):
    """The connector's kind does not serve this capability."""


class Connector:
    """Base for every connector. Subclasses override the capabilities their kind serves.

    An unserved capability raises :class:`UnsupportedCapabilityError` rather than
    returning an empty result, so a missing read can never look compliant.
    """

    kind: ConnectionKind
    collector_version: str
    # Scope identifiers this connection covers: account ids, a domain, an org login (R18).
    scope: tuple[str, ...] = ()
    _clock: Callable[[], datetime]

    def _failure(
        self,
        capability: "Capability",
        endpoint: str,
        parameters: dict[str, Any],
        kind: "FailureKind",
        detail: str,
    ) -> "Failure":
        from passport.connectors.observation import Failure

        return Failure(
            capability=capability,
            kind=kind,
            detail=detail,
            endpoint=endpoint,
            parameters=parameters,
            collector_version=self.collector_version,
            collected_at=self._clock(),
            scope=self.scope,
        )

    def _unsupported(self, capability: Capability) -> "CollectionResult":
        raise UnsupportedCapabilityError(f"{type(self).__name__} does not serve {capability}")

    def list_accounts(self) -> "CollectionResult":
        return self._unsupported(Capability.LIST_ACCOUNTS)

    def list_users_mfa(self) -> "CollectionResult":
        return self._unsupported(Capability.LIST_USERS_MFA)

    def get_root_mfa(self) -> "CollectionResult":
        return self._unsupported(Capability.GET_ROOT_MFA)

    def get_password_policy(self) -> "CollectionResult":
        return self._unsupported(Capability.GET_PASSWORD_POLICY)

    def list_cloudtrail_trails(self) -> "CollectionResult":
        return self._unsupported(Capability.LIST_CLOUDTRAIL_TRAILS)

    def list_s3_bucket_encryption(self) -> "CollectionResult":
        return self._unsupported(Capability.LIST_S3_BUCKET_ENCRYPTION)

    def get_s3_public_access_block(self) -> "CollectionResult":
        return self._unsupported(Capability.GET_S3_PUBLIC_ACCESS_BLOCK)

    def get_org_two_factor_requirement(self) -> "CollectionResult":
        return self._unsupported(Capability.GET_ORG_TWO_FACTOR_REQUIREMENT)

    def list_org_members(self) -> "CollectionResult":
        return self._unsupported(Capability.LIST_ORG_MEMBERS)

    def get_branch_protection(self) -> "CollectionResult":
        return self._unsupported(Capability.GET_BRANCH_PROTECTION)


def implements(cls: type[Connector], capability: Capability) -> bool:
    """True when ``cls`` overrides the base method for ``capability``."""
    return getattr(cls, capability.value) is not getattr(Connector, capability.value)


def collect(connector: Connector, capability: Capability) -> "CollectionResult":
    """Run one capability read by name; the runner iterates capabilities this way."""
    method = getattr(connector, Capability(capability).value)
    result: CollectionResult = method()
    return result
