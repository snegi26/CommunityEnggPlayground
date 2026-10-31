"""Build the auditor export for one org and framework (R13, R14, KTD8, KTD13).

The export is a ZIP of four files:

- ``snapshot.json``: the org, framework, audit window, chain verification result, and
  every item the status engine placed under this framework (including unmapped items
  it assigned here, labelled), each with its status, causes, last approval, and claims.
  Each claim carries its state (unconfirmed and needs-review claims are labelled
  ``unconfirmed``), who confirmed it, and its latest check with the IPE fields of every
  observation that check read (KTD7).
- ``items.csv`` and ``claims.csv``: one row per item and per claim, the same facts flat.
- ``events.json``: every event of the org inside the framework's audit window, with the
  actor (person and on-behalf flag, or the agent with run, model, and prompt version)
  and the hash chain fields, so an auditor can re-link them.

Source of truth: current-state tables, read as stored. Statuses come from
``item_statuses`` (nothing is recomputed, so the export matches the passport page);
claims are chosen the way the status service chooses them; events come from ``events``.

Audit window: a SOC 2 Type II or ISO 27001 window includes events created from the
window's start date through the end of its end date (UTC). When no window is set (a
SOC 2 Type I audit has only an as-of date, and a fresh org may not have set its window
yet) every event is included: a Type I opinion covers the design as of a date, and the
full history behind the current statuses is what substantiates it.

The chain is verified over the whole org log, not only the window. Generating an export
appends an ``export.generated`` event (human actor) after the files are built, naming
the export id and the ZIP's SHA-256. The format is provisional until auditors review a
sample (Dependencies / Assumptions).
"""

import csv
import hashlib
import io
import json
import uuid
import zipfile
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, time, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.auth.models import User
from passport.checks.models import CheckOutcome
from passport.claims.service import CHECKED_STATES, checkable_claims, current_claims_for_versions
from passport.controls.models import ControlMapping, Framework, ItemKind, OrgFrameworkSettings
from passport.db.base import utcnow
from passport.db.models import (
    Claim,
    ClaimState,
    Document,
    DocumentVersion,
    Event,
    EvidenceItem,
    ItemStatus,
    Observation,
)
from passport.provenance.actor import Actor, require_human
from passport.provenance.service import append_event, verify_chain
from passport.tenancy.models import Org

EXPORT_FORMAT = "passport-export/1"

ITEM_COLUMNS = [
    "item_kind",
    "item_id",
    "title",
    "framework",
    "status",
    "trusted",
    "unmapped",
    "controls",
    "causes",
    "last_approved_by_id",
    "last_approved_by_name",
    "approved_on_behalf_of_org",
    "approved_at",
    "review_due_on",
    "claims_total",
    "claims_unconfirmed",
]

CLAIM_COLUMNS = [
    "item_kind",
    "item_id",
    "item_title",
    "claim_id",
    "quote",
    "predicate_id",
    "predicate_version",
    "check_description",
    "state",
    "label",
    "confirmed_by_id",
    "confirmed_by_name",
    "confirmed_on_behalf_of_org",
    "confirmed_at",
    "last_outcome",
    "last_checked_at",
    "observation_endpoints",
    "observation_row_counts",
    "observation_complete",
    "observation_sha256s",
]


@dataclass(frozen=True)
class ExportFile:
    export_id: uuid.UUID
    filename: str
    data: bytes
    sha256: str


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _claim_label(state: ClaimState) -> str:
    """Confirmed, or unconfirmed for every state that still awaits a person (R8)."""
    if state is ClaimState.CONFIRMED:
        return "confirmed"
    if state in (ClaimState.UNCONFIRMED, ClaimState.NEEDS_REVIEW):
        return "unconfirmed"
    return str(state.value)


class _People:
    """User names by id, read through the org's RLS view of its members."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.names: dict[uuid.UUID, str | None] = {}

    def name(self, user_id: uuid.UUID | None) -> str | None:
        if user_id is None:
            return None
        if user_id not in self.names:
            user = self.session.get(User, user_id)
            self.names[user_id] = user.name if user is not None else None
        return self.names[user_id]

    def person(self, user_id: uuid.UUID | None, on_behalf: bool) -> dict[str, Any] | None:
        if user_id is None:
            return None
        return {"user_id": str(user_id), "name": self.name(user_id), "on_behalf_of_org": on_behalf}


def _observation_json(row: Observation) -> dict[str, Any]:
    return {
        "observation_id": str(row.id),
        "connection_id": str(row.connection_id) if row.connection_id else None,
        "capability": row.capability,
        "outcome": row.outcome,
        "endpoint": row.endpoint,
        "parameters": row.parameters,
        "row_count": row.row_count,
        "total_count": row.total_count,
        "complete": row.complete,
        "response_sha256": row.response_sha256,
        "collector_version": row.collector_version,
        "collected_at": _iso(row.collected_at),
        "scope": row.scope,
    }


def _latest_checks(
    session: Session, org_id: uuid.UUID, claim_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, dict[str, Any]]:
    """Each claim's latest check outcome with the observations it read."""
    if not claim_ids:
        return {}
    latest: dict[uuid.UUID, CheckOutcome] = {}
    for row in session.scalars(
        select(CheckOutcome)
        .where(CheckOutcome.org_id == org_id, CheckOutcome.claim_id.in_(claim_ids))
        .order_by(CheckOutcome.checked_at.desc(), CheckOutcome.created_at.desc())
    ):
        latest.setdefault(row.claim_id, row)
    wanted = {uuid.UUID(i) for row in latest.values() for i in row.observation_ids}
    observations = (
        {
            o.id: o
            for o in session.scalars(
                select(Observation).where(Observation.org_id == org_id, Observation.id.in_(wanted))
            )
        }
        if wanted
        else {}
    )
    return {
        claim_id: {
            "check_run_id": str(row.check_run_id),
            "outcome": row.outcome,
            "checked_at": _iso(row.checked_at),
            "detail": row.detail,
            "observations": [
                _observation_json(observations[uuid.UUID(i)])
                for i in row.observation_ids
                if uuid.UUID(i) in observations
            ],
        }
        for claim_id, row in latest.items()
    }


def _version_claims(current: list[Claim], checked_ids: set[uuid.UUID]) -> list[Claim]:
    """The claims the status service counts for a version: checkable plus open unbound."""
    return [
        c
        for c in current
        if c.id in checked_ids or (c.predicate_id is None and c.state in CHECKED_STATES)
    ]


def _latest_versions(session: Session, org_id: uuid.UUID) -> dict[uuid.UUID, DocumentVersion]:
    latest: dict[uuid.UUID, DocumentVersion] = {}
    for version in session.scalars(
        select(DocumentVersion)
        .where(DocumentVersion.org_id == org_id)
        .order_by(DocumentVersion.document_id, DocumentVersion.version_number)
    ):
        latest[version.document_id] = version
    return latest


def _controls(
    session: Session, org_id: uuid.UUID, framework: Framework
) -> dict[tuple[str, uuid.UUID], list[str]]:
    found: dict[tuple[str, uuid.UUID], list[str]] = {}
    for kind, item_id, control_id in session.execute(
        select(ControlMapping.item_kind, ControlMapping.item_id, ControlMapping.control_id)
        .where(ControlMapping.org_id == org_id, ControlMapping.framework == framework.value)
        .order_by(ControlMapping.control_id)
    ):
        found.setdefault((kind, item_id), []).append(control_id)
    return found


def _claim_json(
    claim: Claim, checks: dict[uuid.UUID, dict[str, Any]], people: _People
) -> dict[str, Any]:
    return {
        "claim_id": str(claim.id),
        "quote": claim.quote,
        "predicate_id": claim.predicate_id,
        "predicate_version": claim.predicate_version,
        "parameters": claim.parameters,
        "check_description": claim.check_description,
        "state": claim.state.value,
        "label": _claim_label(claim.state),
        "needs_review_reason": claim.needs_review_reason,
        "confirmed_by": people.person(claim.confirmed_by, claim.confirmed_on_behalf),
        "confirmed_at": _iso(claim.confirmed_at),
        "latest_check": checks.get(claim.id),
    }


def _items(
    session: Session, org_id: uuid.UUID, framework: Framework, people: _People
) -> list[dict[str, Any]]:
    statuses = list(
        session.scalars(
            select(ItemStatus)
            .where(ItemStatus.org_id == org_id, ItemStatus.framework == framework.value)
            .order_by(ItemStatus.item_kind, ItemStatus.item_id)
        )
    )
    documents = {
        d.id: d for d in session.scalars(select(Document).where(Document.org_id == org_id))
    }
    evidence = {
        e.id: e for e in session.scalars(select(EvidenceItem).where(EvidenceItem.org_id == org_id))
    }
    versions = _latest_versions(session, org_id)
    controls = _controls(session, org_id, framework)
    checked_ids = {c.id for c in checkable_claims(session, org_id)}

    document_rows = [
        row
        for row in statuses
        if row.item_kind == ItemKind.DOCUMENT.value and row.item_id in versions
    ]
    current = current_claims_for_versions(
        session, org_id, (versions[row.item_id].id for row in document_rows)
    )
    claims_by_doc: dict[uuid.UUID, list[Claim]] = {}
    for row in document_rows:
        claims_by_doc[row.item_id] = _version_claims(current[versions[row.item_id].id], checked_ids)
    checks = _latest_checks(
        session, org_id, [c.id for claims in claims_by_doc.values() for c in claims]
    )

    items: list[dict[str, Any]] = []
    for row in statuses:
        approval: DocumentVersion | EvidenceItem | None
        detail: dict[str, Any]
        if row.item_kind == ItemKind.DOCUMENT.value:
            document = documents.get(row.item_id)
            approval = versions.get(row.item_id)
            title = document.title if document else None
            detail = {
                "document_version_id": str(approval.id) if approval else None,
                "version_number": approval.version_number if approval else None,
                "filename": approval.filename if approval else None,
                "content_sha256": approval.content_hash if approval else None,
            }
        else:
            approval = evidence.get(row.item_id)
            title = approval.title if approval else None
            detail = {
                "filename": approval.filename if approval else None,
                "content_sha256": approval.content_hash if approval else None,
                "source": approval.source if approval else None,
                "collected_at": _iso(approval.collected_at) if approval else None,
                "user_asserted": approval.user_asserted if approval else None,
            }
        claims = claims_by_doc.get(row.item_id, [])
        items.append(
            {
                "item_kind": row.item_kind,
                "item_id": str(row.item_id),
                "title": title,
                "framework": row.framework,
                "status": row.status,
                "trusted": row.trusted,
                "unmapped": any(c.get("kind") == "unmapped" for c in row.causes),
                "controls": controls.get((row.item_kind, row.item_id), []),
                "causes": row.causes,
                "status_computed_at": _iso(row.computed_at),
                **detail,
                "last_approved_by": people.person(
                    approval.last_approved_by, approval.approved_on_behalf
                )
                if approval
                else None,
                "approved_at": _iso(approval.approved_at) if approval else None,
                "review_due_on": _iso(approval.review_due_on) if approval else None,
                "claims": [_claim_json(c, checks, people) for c in claims],
            }
        )
    return items


def _window(settings: OrgFrameworkSettings | None) -> tuple[datetime, datetime] | None:
    if settings is None or settings.window_start is None or settings.window_end is None:
        return None
    start = datetime.combine(settings.window_start, time.min, tzinfo=UTC)
    end = datetime.combine(settings.window_end + timedelta(days=1), time.min, tzinfo=UTC)
    return start, end


def _events(
    session: Session,
    org_id: uuid.UUID,
    window: tuple[datetime, datetime] | None,
    people: _People,
) -> list[dict[str, Any]]:
    query = select(Event).where(Event.org_id == org_id)
    if window is not None:
        query = query.where(Event.created_at >= window[0], Event.created_at < window[1])
    return [
        {
            "seq": e.seq,
            "created_at": _iso(e.created_at),
            "event_type": e.event_type,
            "subject_kind": e.subject_kind,
            "subject_id": e.subject_id,
            "actor_kind": e.actor_kind,
            "actor_user_id": str(e.actor_user_id) if e.actor_user_id else None,
            "actor_name": people.name(e.actor_user_id),
            "on_behalf_of_org": e.on_behalf_of_org,
            "agent_run_id": str(e.agent_run_id) if e.agent_run_id else None,
            "model_id": e.model_id,
            "prompt_version": e.prompt_version,
            "payload": e.payload,
            "payload_hash": e.payload_hash,
            "prev_hash": e.prev_hash,
            "hash": e.hash,
        }
        for e in session.scalars(query.order_by(Event.seq))
    ]


def _csv(columns: list[str], rows: Iterable[dict[str, Any]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: _cell(row.get(k)) for k in columns})
    return buffer.getvalue().encode()


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _item_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        approver = item["last_approved_by"] or {}
        rows.append(
            {
                **item,
                "controls": ";".join(item["controls"]),
                "causes": " | ".join(c.get("text", "") for c in item["causes"]),
                "last_approved_by_id": approver.get("user_id"),
                "last_approved_by_name": approver.get("name"),
                "approved_on_behalf_of_org": approver.get("on_behalf_of_org"),
                "claims_total": len(item["claims"]),
                "claims_unconfirmed": sum(c["label"] == "unconfirmed" for c in item["claims"]),
            }
        )
    return rows


def _claim_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        for claim in item["claims"]:
            confirmer = claim["confirmed_by"] or {}
            check = claim["latest_check"] or {}
            observations = check.get("observations", [])
            rows.append(
                {
                    **claim,
                    "item_kind": item["item_kind"],
                    "item_id": item["item_id"],
                    "item_title": item["title"],
                    "confirmed_by_id": confirmer.get("user_id"),
                    "confirmed_by_name": confirmer.get("name"),
                    "confirmed_on_behalf_of_org": confirmer.get("on_behalf_of_org"),
                    "last_outcome": check.get("outcome"),
                    "last_checked_at": check.get("checked_at"),
                    "observation_endpoints": ";".join(o["endpoint"] for o in observations),
                    "observation_row_counts": ";".join(str(o["row_count"]) for o in observations),
                    "observation_complete": ";".join(_cell(o["complete"]) for o in observations),
                    "observation_sha256s": ";".join(o["response_sha256"] for o in observations),
                }
            )
    return rows


def _zip(files: dict[str, bytes], when: datetime) -> bytes:
    buffer = io.BytesIO()
    stamp = when.astimezone(UTC).timetuple()[:6]
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(zipfile.ZipInfo(name, date_time=stamp), data, zipfile.ZIP_DEFLATED)
    return buffer.getvalue()


def _json(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=False, default=str).encode()


def build_export(
    session: Session,
    org_id: uuid.UUID,
    framework: Framework,
    *,
    export_id: uuid.UUID,
    generated_at: datetime,
) -> dict[str, bytes]:
    """The export's files, read from the org's current state; writes nothing."""
    people = _People(session)
    org = session.get(Org, org_id)
    settings = session.scalars(
        select(OrgFrameworkSettings).where(
            OrgFrameworkSettings.org_id == org_id,
            OrgFrameworkSettings.framework == framework.value,
        )
    ).one_or_none()
    window = _window(settings)
    chain = verify_chain(session, org_id)
    items = _items(session, org_id, framework, people)
    events = _events(session, org_id, window, people)

    status_counts: dict[str, int] = {}
    for item in items:
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1
    snapshot = {
        "format": EXPORT_FORMAT,
        "format_note": "Provisional until reviewed by auditors.",
        "export_id": str(export_id),
        "generated_at": generated_at.isoformat(),
        "org": {"org_id": str(org_id), "name": org.name if org else None},
        "framework": framework.value,
        "audit": {
            "audit_type": settings.audit_type if settings else None,
            "as_of_date": _iso(settings.as_of_date) if settings else None,
            "window_start": _iso(settings.window_start) if settings else None,
            "window_end": _iso(settings.window_end) if settings else None,
            "events_scope": "window" if window else "all",
        },
        "chain_verification": asdict(chain),
        "summary": {
            "chain_verified": chain.ok,
            "items": len(items),
            "status_counts": status_counts,
            "untrusted_items": sum(not i["trusted"] for i in items),
            "claims": sum(len(i["claims"]) for i in items),
            "unconfirmed_claims": sum(
                c["label"] == "unconfirmed" for i in items for c in i["claims"]
            ),
            "events": len(events),
        },
        "items": items,
    }
    return {
        "snapshot.json": _json(snapshot),
        "items.csv": _csv(ITEM_COLUMNS, _item_rows(items)),
        "claims.csv": _csv(CLAIM_COLUMNS, _claim_rows(items)),
        "events.json": _json(events),
    }


def generate_export(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    framework: Framework,
    *,
    now: datetime | None = None,
) -> ExportFile:
    """Build the export and record that a person generated it (human-only)."""
    human = require_human(actor)
    generated_at = now or utcnow()
    export_id = uuid.uuid4()
    files = build_export(session, org_id, framework, export_id=export_id, generated_at=generated_at)
    data = _zip(files, generated_at)
    digest = hashlib.sha256(data).hexdigest()
    append_event(
        session,
        org_id=org_id,
        actor=human,
        event_type="export.generated",
        subject_kind="export",
        subject_id=export_id,
        payload={
            "export_id": str(export_id),
            "framework": framework.value,
            "format": EXPORT_FORMAT,
            "generated_at": generated_at.isoformat(),
            "zip_sha256": digest,
            "files": {name: hashlib.sha256(body).hexdigest() for name, body in files.items()},
        },
    )
    stamp = generated_at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return ExportFile(export_id, f"passport-{framework.value}-{stamp}.zip", data, digest)
