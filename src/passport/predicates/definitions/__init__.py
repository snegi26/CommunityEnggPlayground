"""Version 1 of every predicate, registered into the default registry on import."""

from typing import Any

from passport.predicates.definitions import cloud, code, identity
from passport.predicates.registry import Predicate, registry

ALL_PREDICATES: tuple[Predicate[Any], ...] = (
    *identity.PREDICATES,
    *cloud.PREDICATES,
    *code.PREDICATES,
)

for _predicate in ALL_PREDICATES:
    registry.register(_predicate)
