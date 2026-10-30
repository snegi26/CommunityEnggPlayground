"""Per-org, per-framework audit windows and cadences, and the scope inventory (U4: R19, R18)."""

import uuid
from datetime import date

import pytest
from sqlalchemy import select

from passport.controls.models import AuditType, Framework, ScopeKind
from passport.controls.settings import (
    SettingsValidationError,
    add_scope_entry,
    ensure_defaults,
    get_framework_settings,
    list_scope_entries,
    remove_scope_entry,
    update_framework_settings,
)
from passport.db.engine import get_sessionmaker
from passport.db.models import Event
from passport.db.rls import set_org_context
from passport.provenance.actor import Human
from tests.helpers import create_org, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")


def _org() -> tuple[uuid.UUID, Human]:
    owner = sign_up()
    return create_org(owner), Human(owner.user_id)


def test_a_new_org_gets_default_cadences_for_both_frameworks() -> None:
    org, actor = _org()
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        ensure_defaults(db, org, actor)
        ensure_defaults(db, org, actor)  # idempotent
        db.commit()

        set_org_context(db, org)
        for framework in Framework:
            s = get_framework_settings(db, framework)
            assert (s.policy_review_days, s.access_review_days, s.expiring_soon_days) == (
                365,
                90,
                30,
            )
        events = db.scalars(select(Event.event_type)).all()
        assert events == ["framework_settings.created", "framework_settings.created"]


def test_soc2_type2_window_round_trips_and_is_visible_in_events() -> None:
    org, actor = _org()
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        ensure_defaults(db, org, actor)
        update_framework_settings(
            db,
            org,
            actor,
            Framework.SOC2,
            audit_type=AuditType.SOC2_TYPE2,
            window_start=date(2026, 1, 1),
            window_end=date(2026, 12, 31),
            access_review_days=60,
        )
        db.commit()

        set_org_context(db, org)
        s = get_framework_settings(db, Framework.SOC2)
        assert (s.window_start, s.window_end, s.as_of_date) == (
            date(2026, 1, 1),
            date(2026, 12, 31),
            None,
        )
        assert (s.access_review_days, s.policy_review_days) == (60, 365)
        last = db.scalars(select(Event).order_by(Event.seq.desc()).limit(1)).one()
        assert last.event_type == "framework_settings.updated"
        assert last.payload["after"]["window_start"] == "2026-01-01"
        assert last.payload["after"]["access_review_days"] == 60


def test_a_soc2_type2_window_ending_before_it_starts_is_rejected() -> None:
    org, actor = _org()
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        ensure_defaults(db, org, actor)
        with pytest.raises(SettingsValidationError, match="end"):
            update_framework_settings(
                db,
                org,
                actor,
                Framework.SOC2,
                audit_type=AuditType.SOC2_TYPE2,
                window_start=date(2026, 6, 1),
                window_end=date(2026, 5, 31),
            )


def test_a_soc2_type1_setting_stores_a_single_as_of_date() -> None:
    org, actor = _org()
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        ensure_defaults(db, org, actor)
        update_framework_settings(
            db,
            org,
            actor,
            Framework.SOC2,
            audit_type=AuditType.SOC2_TYPE1,
            as_of_date=date(2026, 9, 30),
        )
        db.commit()
        set_org_context(db, org)
        s = get_framework_settings(db, Framework.SOC2)
        assert s.audit_type == AuditType.SOC2_TYPE1
        assert (s.as_of_date, s.window_start, s.window_end) == (date(2026, 9, 30), None, None)

        with pytest.raises(SettingsValidationError):
            update_framework_settings(
                db,
                org,
                actor,
                Framework.SOC2,
                audit_type=AuditType.SOC2_TYPE1,
                window_start=date(2026, 1, 1),
                window_end=date(2026, 12, 31),
            )


def test_an_audit_type_from_the_other_framework_is_rejected() -> None:
    org, actor = _org()
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        ensure_defaults(db, org, actor)
        with pytest.raises(SettingsValidationError):
            update_framework_settings(
                db,
                org,
                actor,
                Framework.ISO27001,
                audit_type=AuditType.SOC2_TYPE1,
                as_of_date=date(2026, 1, 1),
            )


def test_declaring_two_production_aws_accounts_stores_both_and_removal_writes_an_event() -> None:
    org, actor = _org()
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        prod = add_scope_entry(
            db, org, actor, ScopeKind.AWS_ACCOUNT, "111111111111", label="prod", production=True
        )
        add_scope_entry(
            db, org, actor, ScopeKind.AWS_ACCOUNT, "222222222222", label="prod-eu", production=True
        )
        db.commit()

        set_org_context(db, org)
        stored = {e.identifier for e in list_scope_entries(db, ScopeKind.AWS_ACCOUNT)}
        assert stored == {"111111111111", "222222222222"}

        remove_scope_entry(db, org, actor, prod.id)
        db.commit()

        set_org_context(db, org)
        assert [e.identifier for e in list_scope_entries(db)] == ["222222222222"]
        types = db.scalars(select(Event.event_type).order_by(Event.seq)).all()
        assert types == ["scope_entry.added", "scope_entry.added", "scope_entry.removed"]
        last = db.scalars(select(Event).order_by(Event.seq.desc()).limit(1)).one()
        assert last.payload["identifier"] == "111111111111"
