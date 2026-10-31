"""The closed, versioned predicate registry (KTD3).

A predicate is one checkable claim type: an id and version, a pydantic parameter
schema, the connector capability it needs, a comparison that turns an observation
into pass or fail with named offenders, a scope rule for R18, and a plain-language
description shown to approvers (R7). A policy sentence that maps to no predicate
yields a not-checkable claim; that decision belongs to drafting, not here.

Predicates in v1 (each one the existing connector capabilities can serve):

Identity (``definitions/identity.py``)
  - ``mfa_enforced`` (``list_users_mfa``, AWS or Google Workspace): every user has MFA.

Cloud (``definitions/cloud.py``, AWS)
  - ``root_mfa_enabled`` (``get_root_mfa``): the root user of each account has MFA.
  - ``password_min_length`` (``get_password_policy``, ``min_length``): the password
    policy requires at least ``min_length`` characters.
  - ``cloudtrail_enabled`` (``list_cloudtrail_trails``, ``multi_region``): at least one
    trail is logging, across all regions when ``multi_region`` is set.
  - ``s3_encryption_enabled`` (``list_s3_bucket_encryption``): every bucket encrypts
    data at rest by default.
  - ``s3_public_access_blocked`` (``get_s3_public_access_block``): all four S3 Block
    Public Access settings are on.

Code (``definitions/code.py``, GitHub)
  - ``github_org_2fa_required`` (``get_org_two_factor_requirement``): the organization
    requires two-factor authentication.
  - ``github_members_2fa_enabled`` (``list_org_members``): every member has 2FA on.
  - ``branch_protection_required`` (``get_branch_protection``, ``min_reviews``): every
    default branch is protected and needs at least ``min_reviews`` approving reviews.

Every predicate takes a ``scope`` parameter: one of its scope rule's keywords (for
example ``all_users``, ``all_production_accounts``, ``all_orgs``) or a non-empty list
of named identifiers. The rule resolves the scope against the org scope inventory
and compares it with the identifiers the observations covered: inventory
entries the observations did not cover are named as unchecked scope, and a claim
scope that matches no inventory entry is flagged with the cause "scope not declared".

Versions: lookups take the version stored on the claim, and registering a new version
never replaces an old one, so a later change cannot silently alter confirmed claims.

Callers must pass only observations whose ``checkable`` property is true. Deciding
that an empty or incomplete observation is not checkable is the status engine's job
(KTD7); a predicate evaluates whatever rows it is given, so an empty row set
would pass vacuously.
"""

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from passport.connectors.base import Capability
from passport.connectors.observation import Observed
from passport.controls.models import ScopeKind

# Scope selectors a scope rule's keywords resolve to.
ALL = "all"
PRODUCTION = "production"
Selector = Literal["all", "production"]
_SELECTORS = frozenset({ALL, PRODUCTION})

# Why a passing claim is only partially checked (R18).
UNCHECKED_SCOPE = "unchecked scope"
SCOPE_NOT_DECLARED = "scope not declared"


class PredicateError(Exception):
    pass


class UnknownPredicateError(PredicateError, LookupError):
    pass


class DuplicatePredicateError(PredicateError):
    pass


class InvalidParametersError(PredicateError, ValueError):
    pass


class ObservationMismatchError(PredicateError, ValueError):
    """The observation was read by a capability other than the predicate's."""


class PredicateParams(BaseModel):
    """Base parameter schema; every predicate's parameters carry a scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # A scope keyword of the predicate's rule, or named identifiers.
    scope: str | list[str] = Field(min_length=1)


class ScopeLike(Protocol):
    """An org scope inventory entry; a ``ScopeEntry`` row satisfies this."""

    @property
    def kind(self) -> str: ...

    @property
    def identifier(self) -> str: ...

    @property
    def production(self) -> bool: ...


@dataclass(frozen=True)
class InventoryEntry:
    """A plain-value inventory entry, for callers that do not hold ORM rows."""

    kind: ScopeKind
    identifier: str
    production: bool = False


@dataclass(frozen=True)
class ScopeCoverage:
    """How far the observations reached into the claim's declared scope."""

    # Inventory identifiers the claim's scope reaches, in inventory (or named) order.
    declared: tuple[str, ...]
    checked: tuple[str, ...]
    unchecked: tuple[str, ...]
    # Named identifiers that are not in the inventory under the rule's kinds.
    undeclared: tuple[str, ...]

    @property
    def causes(self) -> tuple[str, ...]:
        causes: list[str] = []
        if not self.declared:
            causes.append(SCOPE_NOT_DECLARED)
        if self.unchecked:
            causes.append(UNCHECKED_SCOPE)
        if self.undeclared and SCOPE_NOT_DECLARED not in causes:
            causes.append(SCOPE_NOT_DECLARED)
        return tuple(causes)

    @property
    def partial(self) -> bool:
        return bool(self.causes)


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _join(values: Sequence[str]) -> str:
    if len(values) == 1:
        return values[0]
    return f"{', '.join(values[:-1])} and {values[-1]}"


@dataclass(frozen=True)
class ScopeRule:
    """Which inventory kinds a predicate ranges over and the scope keywords it accepts."""

    kinds: tuple[ScopeKind, ...]
    # Read after "every" / "every production" in descriptions.
    noun: str
    keywords: Mapping[str, str]
    # Read before named identifiers; default to ``noun`` and ``noun + "s"``.
    named_noun: str = ""
    named_plural: str = ""

    def __post_init__(self) -> None:
        unknown = sorted(set(self.keywords.values()) - _SELECTORS)
        if unknown:
            raise ValueError(f"scope keywords must map to a selector in {sorted(_SELECTORS)}")
        if not self.named_noun:
            object.__setattr__(self, "named_noun", self.noun)
        if not self.named_plural:
            object.__setattr__(self, "named_plural", f"{self.named_noun}s")

    def phrase(self, scope: str | Sequence[str]) -> str:
        if isinstance(scope, str):
            prefix = "every production" if self.keywords[scope] == PRODUCTION else "every"
            return f"{prefix} {self.noun}"
        names = list(scope)
        noun = self.named_noun if len(names) == 1 else self.named_plural
        return f"{noun} {_join(names)}"

    def coverage(
        self,
        scope: str | Sequence[str],
        observed_scope: Iterable[str],
        inventory: Iterable[ScopeLike],
    ) -> ScopeCoverage:
        entries = [e for e in inventory if ScopeKind(e.kind) in self.kinds]
        undeclared: tuple[str, ...] = ()
        if isinstance(scope, str):
            production_only = self.keywords[scope] == PRODUCTION
            declared = _dedupe(e.identifier for e in entries if e.production or not production_only)
        else:
            known = {e.identifier for e in entries}
            declared = _dedupe(name for name in scope if name in known)
            undeclared = _dedupe(name for name in scope if name not in known)
        covered = set(observed_scope)
        return ScopeCoverage(
            declared=declared,
            checked=tuple(i for i in declared if i in covered),
            unchecked=tuple(i for i in declared if i not in covered),
            undeclared=undeclared,
        )


@dataclass(frozen=True)
class Outcome:
    """A comparison's result for one observation."""

    passed: bool
    offenders: tuple[str, ...] = ()


def rows_where(
    observed: Observed,
    ok: Callable[[Mapping[str, Any]], bool],
    label: Callable[[Mapping[str, Any]], str],
) -> Outcome:
    """Pass when every row is ``ok``; otherwise name each row that is not."""
    offenders = tuple(label(row) for row in observed.rows if not ok(row))
    return Outcome(passed=not offenders, offenders=offenders)


def field_label(*keys: str) -> Callable[[Mapping[str, Any]], str]:
    """Label a row by the first of ``keys`` it carries."""

    def label(row: Mapping[str, Any]) -> str:
        for key in keys:
            if row.get(key) is not None:
                return str(row[key])
        return "unnamed"

    return label


def is_true(key: str) -> Callable[[Mapping[str, Any]], bool]:
    """A row passes only when ``key`` is exactly ``True``; missing never passes."""
    return lambda row: row.get(key) is True


def _no_extra(_params: Any) -> Mapping[str, object]:
    return {}


@dataclass(frozen=True)
class Predicate[P: PredicateParams]:
    id: str
    version: int
    title: str
    capability: Capability
    params_model: type[P]
    scope_rule: ScopeRule
    # Formatted with the parameters, ``scope`` replaced by the rule's phrase, plus
    # any values ``describe_extra`` returns.
    description_template: str
    evaluate: Callable[[Observed, P], Outcome]
    describe_extra: Callable[[P], Mapping[str, object]] = field(default=_no_extra)

    def parse_params(self, raw: Mapping[str, Any]) -> P:
        try:
            params = self.params_model.model_validate(dict(raw))
        except ValidationError as exc:
            raise InvalidParametersError(f"{self.id} v{self.version}: {exc}") from exc
        if isinstance(params.scope, str) and params.scope not in self.scope_rule.keywords:
            allowed = ", ".join(sorted(self.scope_rule.keywords))
            raise InvalidParametersError(
                f"{self.id} v{self.version}: scope {params.scope!r} is not one of {allowed}"
                " or a list of named identifiers"
            )
        return params

    def describe(self, params: P) -> str:
        values: dict[str, object] = params.model_dump()
        values["scope"] = self.scope_rule.phrase(params.scope)
        values.update(self.describe_extra(params))
        text = self.description_template.format(**values)
        return text[:1].upper() + text[1:]


@dataclass(frozen=True)
class Evaluation:
    predicate_id: str
    version: int
    passed: bool
    offenders: tuple[str, ...]
    coverage: ScopeCoverage
    # Every scope identifier the observations covered: what it was checked against.
    observed_scope: tuple[str, ...]

    @property
    def partially_checked(self) -> bool:
        """A pass whose claim scope reaches beyond what was observed (R18)."""
        return self.passed and self.coverage.partial

    @property
    def partial_cause(self) -> str | None:
        return self.coverage.causes[0] if self.partially_checked else None


class PredicateRegistry:
    """Predicates keyed by ``(id, version)``."""

    def __init__(self) -> None:
        self._predicates: dict[tuple[str, int], Predicate[Any]] = {}

    def register[P: PredicateParams](self, predicate: Predicate[P]) -> Predicate[P]:
        key = (predicate.id, predicate.version)
        if predicate.version < 1:
            raise ValueError(f"{predicate.id}: versions start at 1")
        if key in self._predicates:
            raise DuplicatePredicateError(f"{predicate.id} v{predicate.version} is registered")
        self._predicates[key] = predicate
        return predicate

    def get(self, predicate_id: str, version: int) -> Predicate[Any]:
        try:
            return self._predicates[(predicate_id, version)]
        except KeyError:
            if any(pid == predicate_id for pid, _ in self._predicates):
                raise UnknownPredicateError(
                    f"predicate {predicate_id} has no version {version}"
                ) from None
            raise UnknownPredicateError(f"unknown predicate {predicate_id}") from None

    def latest(self, predicate_id: str) -> Predicate[Any]:
        versions = [v for pid, v in self._predicates if pid == predicate_id]
        if not versions:
            raise UnknownPredicateError(f"unknown predicate {predicate_id}")
        return self._predicates[(predicate_id, max(versions))]

    def all(self) -> list[Predicate[Any]]:
        return [self._predicates[key] for key in sorted(self._predicates)]

    def describe(self, predicate_id: str, version: int, params: Mapping[str, Any]) -> str:
        predicate = self.get(predicate_id, version)
        return predicate.describe(predicate.parse_params(params))

    def evaluate(
        self,
        predicate_id: str,
        version: int,
        params: Mapping[str, Any],
        observations: Observed | Sequence[Observed],
        inventory: Iterable[ScopeLike],
    ) -> Evaluation:
        """Evaluate a claim against checkable observations and the org scope inventory.

        Each observation must come from the predicate's capability; all must pass for
        the claim to pass, and offenders are combined in observation order.
        """
        predicate = self.get(predicate_id, version)
        parsed = predicate.parse_params(params)
        observed = [observations] if isinstance(observations, Observed) else list(observations)
        if not observed:
            raise ValueError("evaluate needs at least one observation")
        for item in observed:
            if item.capability != predicate.capability:
                raise ObservationMismatchError(
                    f"{predicate_id} needs {predicate.capability}, got {item.capability}"
                )
        outcomes = [predicate.evaluate(item, parsed) for item in observed]
        observed_scope = _dedupe(i for item in observed for i in item.scope)
        return Evaluation(
            predicate_id=predicate.id,
            version=predicate.version,
            passed=all(o.passed for o in outcomes),
            offenders=_dedupe(name for o in outcomes for name in o.offenders),
            coverage=predicate.scope_rule.coverage(parsed.scope, observed_scope, inventory),
            observed_scope=observed_scope,
        )


# The default registry; ``passport.predicates.definitions`` registers v1 into it.
registry = PredicateRegistry()
