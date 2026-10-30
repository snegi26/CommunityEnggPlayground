"""Control catalogs and item-to-control mappings (U4: R4)."""

import uuid
from collections.abc import Iterator

import psycopg
import pytest
from sqlalchemy import select

from passport.controls.models import Control, Framework
from passport.controls.service import (
    UnknownControlError,
    catalog_rows,
    controls_for_item,
    items_for_framework,
    list_controls,
    load_catalog,
    map_item,
    unmap_item,
)
from passport.db.engine import get_sessionmaker
from passport.db.models import Event
from passport.db.rls import set_org_context
from passport.provenance.actor import Human
from passport.settings import libpq_url
from tests.helpers import create_org, sign_up


@pytest.mark.parametrize("framework", list(Framework))
def test_catalog_file_has_unique_ids_and_no_empty_titles(framework: Framework) -> None:
    controls = load_catalog(framework)
    ids = [c.control_id for c in controls]
    assert len(ids) == len(set(ids))
    assert all(c.title.strip() for c in controls)


def test_catalogs_cover_the_required_ranges() -> None:
    soc2 = [c.control_id for c in load_catalog(Framework.SOC2)]
    iso = [c.control_id for c in load_catalog(Framework.ISO27001)]
    assert soc2[0] == "CC1.1" and soc2[-1] == "CC9.2" and "CC6.1" in soc2
    assert iso[0] == "5.1" and iso[-1] == "8.34" and len(iso) == 93


@pytest.fixture
def catalog(database_urls: dict[str, str]) -> Iterator[None]:
    """Reference rows are loaded by the migration; the suite's truncation clears them."""
    with psycopg.connect(libpq_url(database_urls["owner"]), autocommit=True) as conn:
        if conn.execute("SELECT count(*) FROM controls").fetchone() == (0,):
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO controls (framework, control_id, title, position) "
                    "VALUES (%(framework)s, %(control_id)s, %(title)s, %(position)s)",
                    catalog_rows(),
                )
    yield


def test_reference_tables_hold_both_catalogs(catalog: None) -> None:
    with get_sessionmaker()() as db:
        soc2 = list_controls(db, Framework.SOC2)
        iso = list_controls(db, Framework.ISO27001)
    assert [c.control_id for c in soc2] == [c.control_id for c in load_catalog(Framework.SOC2)]
    assert len(iso) == 93


def test_app_role_cannot_change_the_reference_catalog(catalog: None) -> None:
    with get_sessionmaker()() as db:
        control = db.scalars(select(Control).limit(1)).one()
        control.title = "changed"
        with pytest.raises(Exception, match="permission denied"):
            db.flush()


def test_mapping_one_policy_to_soc2_and_iso_shows_it_in_both_views(catalog: None) -> None:
    owner = sign_up()
    org = create_org(owner)
    actor = Human(owner.user_id)
    policy = uuid.uuid4()

    with get_sessionmaker()() as db:
        set_org_context(db, org)
        map_item(db, org, actor, "document", policy, Framework.SOC2, "CC6.1")
        map_item(db, org, actor, "document", policy, Framework.ISO27001, "5.15")
        db.commit()

        set_org_context(db, org)
        assert ("document", policy) in items_for_framework(db, Framework.SOC2)
        assert ("document", policy) in items_for_framework(db, Framework.ISO27001)
        mapped = {(m.framework, m.control_id) for m in controls_for_item(db, "document", policy)}
        assert mapped == {("soc2", "CC6.1"), ("iso27001", "5.15")}
        types = db.scalars(select(Event.event_type).order_by(Event.seq)).all()
        assert types == ["control_mapping.added", "control_mapping.added"]


def test_unmapping_removes_the_item_from_the_view_and_writes_an_event(catalog: None) -> None:
    owner = sign_up()
    org = create_org(owner)
    actor = Human(owner.user_id)
    evidence = uuid.uuid4()

    with get_sessionmaker()() as db:
        set_org_context(db, org)
        map_item(db, org, actor, "evidence", evidence, Framework.SOC2, "CC6.2")
        unmap_item(db, org, actor, "evidence", evidence, Framework.SOC2, "CC6.2")
        db.commit()

        set_org_context(db, org)
        assert items_for_framework(db, Framework.SOC2) == []
        last = db.scalars(select(Event).order_by(Event.seq.desc()).limit(1)).one()
        assert last.event_type == "control_mapping.removed"
        assert last.payload["control_id"] == "CC6.2"


def test_mapping_to_an_unknown_control_is_rejected(catalog: None) -> None:
    owner = sign_up()
    org = create_org(owner)
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        with pytest.raises(UnknownControlError):
            map_item(db, org, Human(owner.user_id), "document", uuid.uuid4(), Framework.SOC2, "5.1")
