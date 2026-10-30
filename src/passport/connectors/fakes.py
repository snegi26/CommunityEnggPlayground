"""Scriptable fake connectors for tests (U6).

A :class:`FakeConnector` stands in for any connection kind. Each test scripts the
system state per capability (rows, a partial page set, or a typed failure), and can
script successive states to show a change between runs. Together they reproduce
the states AE1-AE8 need: users with and without MFA, one connection per account
or domain (scope), unauthorized, rate limit, timeout, an empty list, and
incomplete pagination.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from passport.connectors.base import Capability, Connector, UnsupportedCapabilityError
from passport.connectors.models import ConnectionKind
from passport.connectors.observation import (
    CollectionResult,
    Failure,
    FailureKind,
    Observed,
)
from passport.connectors.registry import capabilities_for
from passport.db.base import utcnow


@dataclass(frozen=True)
class Rows:
    """A scripted successful read."""

    rows: list[dict[str, Any]]
    total: int | None = None
    pagination_complete: bool = True


@dataclass(frozen=True)
class ScriptedFailure:
    kind: FailureKind
    detail: str = ""


FakeResponse = Rows | ScriptedFailure | list[dict[str, Any]]


def users_mfa(users: Mapping[str, bool]) -> Rows:
    """Users and whether each has MFA; an empty mapping is an empty user list."""
    return Rows([{"user": name, "mfa": on} for name, on in users.items()])


def partial(response: Rows | list[dict[str, Any]], *, total: int) -> Rows:
    """Fewer rows than the provider reports: an incomplete observation."""
    rows = response.rows if isinstance(response, Rows) else response
    return Rows(list(rows), total=total)


def failure(kind: FailureKind, detail: str = "") -> ScriptedFailure:
    return ScriptedFailure(kind, detail or f"scripted {kind.value}")


@dataclass
class _Script:
    responses: list[FakeResponse] = field(default_factory=list)
    served: int = 0

    def next(self) -> FakeResponse:
        # Successive calls walk the script; the last state then repeats.
        response = self.responses[min(self.served, len(self.responses) - 1)]
        self.served += 1
        return response


class FakeConnector(Connector):
    def __init__(
        self,
        kind: ConnectionKind,
        *,
        scope: Sequence[str],
        responses: Mapping[Capability, FakeResponse] | None = None,
        collector_version: str = "fake-1",
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.kind = ConnectionKind(kind)
        self.scope = tuple(scope)
        self.collector_version = collector_version
        self.clock = clock
        self.calls: list[Capability] = []
        self._scripts: dict[Capability, _Script] = {}
        for capability, response in (responses or {}).items():
            self.script(capability, response)

    def script(self, capability: Capability, *responses: FakeResponse) -> "FakeConnector":
        """Set the responses ``capability`` returns on successive reads."""
        self._require_served(capability)
        if not responses:
            raise ValueError("script at least one response")
        self._scripts[capability] = _Script(list(responses))
        return self

    def _require_served(self, capability: Capability) -> None:
        if capability not in capabilities_for(self.kind):
            raise UnsupportedCapabilityError(f"{self.kind} does not serve {capability}")

    def _read(self, capability: Capability) -> CollectionResult:
        self._require_served(capability)
        self.calls.append(capability)
        script = self._scripts.get(capability)
        if script is None:
            raise LookupError(f"fake {self.kind} has no scripted response for {capability}")
        response = script.next()
        common: dict[str, Any] = {
            "capability": capability,
            "endpoint": f"fake://{self.kind.value}/{capability.value}",
            "parameters": {},
            "collector_version": self.collector_version,
            "collected_at": self.clock(),
            "scope": self.scope,
        }
        if isinstance(response, ScriptedFailure):
            return Failure(kind=response.kind, detail=response.detail, **common)
        rows = response if isinstance(response, Rows) else Rows(response)
        return Observed(
            rows=list(rows.rows),
            raw_response={"items": rows.rows, "total": rows.total},
            total_count=rows.total,
            pagination_complete=rows.pagination_complete,
            **common,
        )

    def list_accounts(self) -> CollectionResult:
        return self._read(Capability.LIST_ACCOUNTS)

    def list_users_mfa(self) -> CollectionResult:
        return self._read(Capability.LIST_USERS_MFA)

    def get_root_mfa(self) -> CollectionResult:
        return self._read(Capability.GET_ROOT_MFA)

    def get_password_policy(self) -> CollectionResult:
        return self._read(Capability.GET_PASSWORD_POLICY)

    def list_cloudtrail_trails(self) -> CollectionResult:
        return self._read(Capability.LIST_CLOUDTRAIL_TRAILS)

    def list_s3_bucket_encryption(self) -> CollectionResult:
        return self._read(Capability.LIST_S3_BUCKET_ENCRYPTION)

    def get_s3_public_access_block(self) -> CollectionResult:
        return self._read(Capability.GET_S3_PUBLIC_ACCESS_BLOCK)

    def get_org_two_factor_requirement(self) -> CollectionResult:
        return self._read(Capability.GET_ORG_TWO_FACTOR_REQUIREMENT)

    def list_org_members(self) -> CollectionResult:
        return self._read(Capability.LIST_ORG_MEMBERS)

    def get_branch_protection(self) -> CollectionResult:
        return self._read(Capability.GET_BRANCH_PROTECTION)
