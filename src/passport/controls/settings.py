"""Per-org, per-framework audit windows and cadences (R19), and the scope inventory (R18).

Every change is written to the event log with its before and after values.
"""

import uuid
from dataclasses import asdict, dataclass
from datetime import date
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.controls.models import (
    AUDIT_TYPES,
    AuditType,
    Framework,
    OrgFrameworkSettings,
    ScopeEntry,
    ScopeKind,
)
from passport.db.base import utcnow
from passport.provenance.actor import Actor
from passport.provenance.service import append_event

DEFAULT_POLICY_REVIEW_DAYS = 365
DEFAULT_ACCESS_REVIEW_DAYS = 90
DEFAULT_EXPIRING_SOON_DAYS = 30
DEFAULT_AUDIT_TYPE: dict[Framework, AuditType] = {
    Framework.SOC2: AuditType.SOC2_TYPE2,
    Framework.ISO27001: AuditType.ISO27001_CERTIFICATION,
}


class SettingsValidationError(ValueError):
    """Framework settings that would be inconsistent are rejected before storing."""


class ScopeEntryNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class _Snapshot:
    audit_type: str
    as_of_date: str | None
    window_start: str | None
    window_end: str | None
    policy_review_days: int
    access_review_days: int
    expiring_soon_days: int


def _snapshot(s: OrgFrameworkSettings) -> dict[str, Any]:
    return asdict(
        _Snapshot(
            audit_type=s.audit_type,
            as_of_date=s.as_of_date.isoformat() if s.as_of_date else None,
            window_start=s.window_start.isoformat() if s.window_start else None,
            window_end=s.window_end.isoformat() if s.window_end else None,
            policy_review_days=s.policy_review_days,
            access_review_days=s.access_review_days,
            expiring_soon_days=s.expiring_soon_days,
        )
    )


def get_framework_settings(session: Session, framework: Framework) -> OrgFrameworkSettings:
    """The active org's settings for one framework (RLS scopes the lookup)."""
    return session.scalars(
        select(OrgFrameworkSettings).where(OrgFrameworkSettings.framework == framework.value)
    ).one()


def ensure_defaults(
    session: Session, org_id: uuid.UUID, actor: Actor
) -> list[OrgFrameworkSettings]:
    """Create default settings for every framework the org lacks; existing rows are kept."""
    existing = {
        s.framework: s
        for s in session.scalars(
            select(OrgFrameworkSettings).where(OrgFrameworkSettings.org_id == org_id)
        )
    }
    result: list[OrgFrameworkSettings] = []
    for framework in Framework:
        row = existing.get(framework.value)
        if row is None:
            row = OrgFrameworkSettings(
                org_id=org_id,
                framework=framework.value,
                audit_type=DEFAULT_AUDIT_TYPE[framework].value,
                policy_review_days=DEFAULT_POLICY_REVIEW_DAYS,
                access_review_days=DEFAULT_ACCESS_REVIEW_DAYS,
                expiring_soon_days=DEFAULT_EXPIRING_SOON_DAYS,
            )
            session.add(row)
            session.flush()
            append_event(
                session,
                org_id=org_id,
                actor=actor,
                event_type="framework_settings.created",
                subject_kind="framework_settings",
                subject_id=row.id,
                payload={"framework": framework.value, "after": _snapshot(row)},
            )
        result.append(row)
    return result


def _validate(
    framework: Framework,
    audit_type: AuditType,
    as_of_date: date | None,
    window_start: date | None,
    window_end: date | None,
    cadences: dict[str, int],
) -> None:
    if audit_type not in AUDIT_TYPES[framework]:
        raise SettingsValidationError(f"{audit_type.value} is not a {framework.value} audit type")
    if audit_type is AuditType.SOC2_TYPE1:
        if as_of_date is None or window_start is not None or window_end is not None:
            raise SettingsValidationError("a SOC 2 Type I audit takes a single as-of date")
    else:
        if as_of_date is not None:
            raise SettingsValidationError(f"{audit_type.value} takes a window, not an as-of date")
        if window_start is None or window_end is None:
            raise SettingsValidationError(f"{audit_type.value} needs a window start and end")
        if window_end <= window_start:
            raise SettingsValidationError("the window end must be after the window start")
    for name, days in cadences.items():
        minimum = 0 if name == "expiring_soon_days" else 1
        if days < minimum:
            raise SettingsValidationError(f"{name} must be at least {minimum}")


def update_framework_settings(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    framework: Framework,
    *,
    audit_type: AuditType,
    as_of_date: date | None = None,
    window_start: date | None = None,
    window_end: date | None = None,
    policy_review_days: int | None = None,
    access_review_days: int | None = None,
    expiring_soon_days: int | None = None,
) -> OrgFrameworkSettings:
    """Set the audit type and its dates; cadences left as None keep their current value."""
    row = get_framework_settings(session, framework)
    cadences = {
        "policy_review_days": row.policy_review_days
        if policy_review_days is None
        else policy_review_days,
        "access_review_days": row.access_review_days
        if access_review_days is None
        else access_review_days,
        "expiring_soon_days": row.expiring_soon_days
        if expiring_soon_days is None
        else expiring_soon_days,
    }
    _validate(framework, audit_type, as_of_date, window_start, window_end, cadences)
    before = _snapshot(row)
    row.audit_type = audit_type.value
    row.as_of_date = as_of_date
    row.window_start = window_start
    row.window_end = window_end
    row.policy_review_days = cadences["policy_review_days"]
    row.access_review_days = cadences["access_review_days"]
    row.expiring_soon_days = cadences["expiring_soon_days"]
    row.updated_at = utcnow()
    session.flush()
    append_event(
        session,
        org_id=org_id,
        actor=actor,
        event_type="framework_settings.updated",
        subject_kind="framework_settings",
        subject_id=row.id,
        payload={"framework": framework.value, "before": before, "after": _snapshot(row)},
    )
    return row


def _scope_payload(entry: ScopeEntry) -> dict[str, Any]:
    return {
        "kind": entry.kind,
        "identifier": entry.identifier,
        "label": entry.label,
        "production": entry.production,
    }


def add_scope_entry(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    kind: ScopeKind,
    identifier: str,
    *,
    label: str = "",
    production: bool = False,
) -> ScopeEntry:
    """Declare an in-scope system (also used by setup pre-fill, e.g. AWS ListAccounts)."""
    entry = ScopeEntry(
        org_id=org_id,
        kind=ScopeKind(kind).value,
        identifier=identifier.strip(),
        label=label,
        production=production,
    )
    session.add(entry)
    session.flush()
    append_event(
        session,
        org_id=org_id,
        actor=actor,
        event_type="scope_entry.added",
        subject_kind="scope_entry",
        subject_id=entry.id,
        payload=_scope_payload(entry),
    )
    return entry


def remove_scope_entry(
    session: Session, org_id: uuid.UUID, actor: Actor, entry_id: uuid.UUID
) -> None:
    entry = session.get(ScopeEntry, entry_id)
    if entry is None:
        raise ScopeEntryNotFoundError(str(entry_id))
    payload = _scope_payload(entry)
    session.delete(entry)
    session.flush()
    append_event(
        session,
        org_id=org_id,
        actor=actor,
        event_type="scope_entry.removed",
        subject_kind="scope_entry",
        subject_id=entry_id,
        payload=payload,
    )


def list_scope_entries(session: Session, kind: ScopeKind | None = None) -> list[ScopeEntry]:
    query = select(ScopeEntry).order_by(ScopeEntry.kind, ScopeEntry.identifier)
    if kind is not None:
        query = query.where(ScopeEntry.kind == ScopeKind(kind).value)
    return list(session.scalars(query))
