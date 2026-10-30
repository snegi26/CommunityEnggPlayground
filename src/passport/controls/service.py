"""Control catalogs and item-to-control mappings (U4, R4).

Catalog files ship identifiers and short titles only. The migration loads them into
the global ``controls`` table; mappings are org-scoped and every change is an event.
"""

import json
import uuid
from dataclasses import dataclass
from importlib import resources
from typing import Any

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from passport.controls.models import Control, ControlMapping, Framework, ItemKind
from passport.provenance.actor import Actor
from passport.provenance.service import append_event

CATALOG_FILES: dict[Framework, str] = {
    Framework.SOC2: "soc2_2017_tsc.json",
    Framework.ISO27001: "iso27001_2022_annex_a.json",
}


class CatalogError(ValueError):
    """A catalog file is malformed: duplicate id, empty title, or wrong framework."""


class UnknownControlError(LookupError):
    """The framework's catalog has no such control."""


@dataclass(frozen=True)
class CatalogControl:
    framework: Framework
    control_id: str
    title: str


def load_catalog(framework: Framework) -> list[CatalogControl]:
    """Read and validate one framework's catalog file, in catalog order."""
    path = resources.files("passport.controls").joinpath("catalog", CATALOG_FILES[framework])
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if data.get("framework") != framework.value:
        raise CatalogError(f"{path.name} is not the {framework.value} catalog")
    controls: list[CatalogControl] = []
    seen: set[str] = set()
    for entry in data["controls"]:
        control_id, title = str(entry["id"]).strip(), str(entry["title"]).strip()
        if not control_id or not title:
            raise CatalogError(f"{path.name}: empty id or title in {entry!r}")
        if control_id in seen:
            raise CatalogError(f"{path.name}: duplicate control id {control_id}")
        seen.add(control_id)
        controls.append(CatalogControl(framework, control_id, title))
    return controls


def catalog_rows() -> list[dict[str, Any]]:
    """Rows for the ``controls`` reference table across both frameworks."""
    return [
        {
            "framework": c.framework.value,
            "control_id": c.control_id,
            "title": c.title,
            "position": i,
        }
        for framework in Framework
        for i, c in enumerate(load_catalog(framework))
    ]


def list_controls(session: Session, framework: Framework) -> list[Control]:
    return list(
        session.scalars(
            select(Control).where(Control.framework == framework.value).order_by(Control.position)
        )
    )


def _mapping_query(
    item_kind: ItemKind | str, item_id: uuid.UUID, framework: Framework, control_id: str
) -> Select[ControlMapping]:
    return select(ControlMapping).where(
        ControlMapping.item_kind == ItemKind(item_kind).value,
        ControlMapping.item_id == item_id,
        ControlMapping.framework == framework.value,
        ControlMapping.control_id == control_id,
    )


def _payload(
    item_kind: ItemKind | str, item_id: uuid.UUID, framework: Framework, control_id: str
) -> dict[str, Any]:
    return {
        "item_kind": ItemKind(item_kind).value,
        "item_id": str(item_id),
        "framework": framework.value,
        "control_id": control_id,
    }


def map_item(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    item_kind: ItemKind | str,
    item_id: uuid.UUID,
    framework: Framework,
    control_id: str,
) -> ControlMapping:
    """Map an item to a control; mapping an existing pair is a no-op without an event."""
    if session.get(Control, (framework.value, control_id)) is None:
        raise UnknownControlError(f"{framework.value} has no control {control_id}")
    existing = session.scalars(_mapping_query(item_kind, item_id, framework, control_id)).first()
    if existing is not None:
        return existing
    mapping = ControlMapping(
        org_id=org_id,
        item_kind=ItemKind(item_kind).value,
        item_id=item_id,
        framework=framework.value,
        control_id=control_id,
    )
    session.add(mapping)
    session.flush()
    append_event(
        session,
        org_id=org_id,
        actor=actor,
        event_type="control_mapping.added",
        subject_kind=ItemKind(item_kind).value,
        subject_id=item_id,
        payload=_payload(item_kind, item_id, framework, control_id),
    )
    return mapping


def unmap_item(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    item_kind: ItemKind | str,
    item_id: uuid.UUID,
    framework: Framework,
    control_id: str,
) -> bool:
    """Remove a mapping. Returns False, writing nothing, when it did not exist."""
    mapping = session.scalars(_mapping_query(item_kind, item_id, framework, control_id)).first()
    if mapping is None:
        return False
    session.delete(mapping)
    session.flush()
    append_event(
        session,
        org_id=org_id,
        actor=actor,
        event_type="control_mapping.removed",
        subject_kind=ItemKind(item_kind).value,
        subject_id=item_id,
        payload=_payload(item_kind, item_id, framework, control_id),
    )
    return True


def controls_for_item(
    session: Session, item_kind: ItemKind | str, item_id: uuid.UUID
) -> list[ControlMapping]:
    return list(
        session.scalars(
            select(ControlMapping)
            .where(
                ControlMapping.item_kind == ItemKind(item_kind).value,
                ControlMapping.item_id == item_id,
            )
            .order_by(ControlMapping.framework, ControlMapping.control_id)
        )
    )


def items_for_framework(session: Session, framework: Framework) -> list[tuple[str, uuid.UUID]]:
    """Distinct (item_kind, item_id) pairs mapped to any control of the framework."""
    rows = session.execute(
        select(ControlMapping.item_kind, ControlMapping.item_id)
        .where(ControlMapping.framework == framework.value)
        .distinct()
        .order_by(ControlMapping.item_kind, ControlMapping.item_id)
    )
    return [(kind, item_id) for kind, item_id in rows]
