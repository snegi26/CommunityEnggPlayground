"""Build the weekly report from a check run's statuses and coverage (R11, R12).

The diff baseline is the snapshot stored on the org's last *sent* report, never the
last run: a week whose report was not sent (a mail failure, a missed run) folds into
the next report. With no sent report the report is a full baseline listing every item.

Sections, per item and framework (an ItemStatus row):

- newly bad: now in a bad status (anything but current) and the baseline had it in a
  different status, or did not have it;
- resolved: the baseline had it in a bad status and it is now current (AE8);
- still bad: in the same bad status as in the baseline.

Coverage comes from ``run_coverage`` (claims checked, failed, not checkable, and which
connected systems answered). A week with no changes is called quiet only when every
system read was reachable (AE4); an unreachable system makes the report say not
everything was checked, even when no status changed (AE6).
"""

import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.checks.runner import run_coverage
from passport.db.base import utcnow
from passport.db.models import CheckRun, Document, EvidenceItem, ItemStatus
from passport.provenance.actor import Agent
from passport.provenance.service import append_event
from passport.reports.models import WeeklyReport
from passport.status.engine import SEVERITY_RANK, Status

REPORT_VERSION = "weekly-report/1"
CURRENT = Status.CURRENT.value

STATUS_LABELS: Mapping[str, str] = {
    "contradicted": "Contradicted",
    "expired": "Expired",
    "check_failed": "Check failed",
    "expiring_soon": "Expiring soon",
    "unconfirmed": "Unconfirmed",
    "not_checkable": "Not checkable",
    "current": "Current",
}

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "web" / "templates"
_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

Clock = Callable[[], datetime]


def report_actor(run_id: uuid.UUID) -> Agent:
    """The freshness agent reporting on one run; deterministic code, no model."""
    return Agent(run_id=run_id, model_id="none", prompt_version=REPORT_VERSION)


@dataclass(frozen=True)
class CurrentItem:
    item_kind: str
    item_id: uuid.UUID
    framework: str
    title: str
    status: str
    trusted: bool
    causes: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.item_kind}:{self.item_id}:{self.framework}"


def snapshot_of(items: Sequence[CurrentItem]) -> dict[str, Any]:
    return {i.key: {"status": i.status, "title": i.title} for i in items}


def _entry(item: CurrentItem, before: str | None) -> dict[str, Any]:
    return {
        "item_kind": item.item_kind,
        "item_id": str(item.item_id),
        "framework": item.framework,
        "title": item.title,
        "status": item.status,
        "status_label": STATUS_LABELS.get(item.status, item.status),
        "before": before,
        "before_label": STATUS_LABELS.get(before, before) if before else None,
        "trusted": item.trusted,
        "causes": list(item.causes),
    }


def _ordered(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        entries,
        key=lambda e: (
            SEVERITY_RANK.get(e["status"], len(SEVERITY_RANK)),
            e["title"],
            e["item_kind"],
            e["item_id"],
        ),
    )


def coverage_summary(coverage: Mapping[str, Any], *, run_status: str) -> dict[str, Any]:
    """The run's coverage JSON plus which systems were unreachable."""
    systems = list(coverage.get("systems", ()))
    unreachable = [s["name"] for s in systems if not s["reachable"]]
    return {
        **coverage,
        "run_status": run_status,
        "unreachable": unreachable,
        "all_reachable": not unreachable and run_status == "succeeded",
    }


def diff_sections(
    previous: Mapping[str, Mapping[str, Any]] | None,
    items: Sequence[CurrentItem],
    coverage: Mapping[str, Any],
) -> dict[str, Any]:
    """Sections of a report against the last sent snapshot (None: a baseline report)."""
    baseline = previous is None
    before_of = previous or {}
    newly_bad: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    still_bad: list[dict[str, Any]] = []
    for item in items:
        prior = before_of.get(item.key)
        before = str(prior["status"]) if prior else None
        if item.status != CURRENT:
            target = still_bad if before == item.status else newly_bad
            target.append(_entry(item, before))
        elif before is not None and before != CURRENT:
            resolved.append(_entry(item, before))
    nothing_changed = not baseline and not newly_bad and not resolved
    return {
        "baseline": baseline,
        "newly_bad": _ordered(newly_bad),
        "resolved": _ordered(resolved),
        "still_bad": _ordered(still_bad),
        "all_items": _ordered([_entry(i, None) for i in items]) if baseline else [],
        "nothing_changed": nothing_changed,
        "quiet_week": nothing_changed and bool(coverage.get("all_reachable")),
    }


def render_report_html(
    *,
    org_name: str,
    sections: Mapping[str, Any],
    coverage: Mapping[str, Any],
    generated_at: datetime,
) -> str:
    """The in-product report page (``web/templates/report.html``)."""
    return _env.get_template("report.html").render(
        org_name=org_name,
        sections=sections,
        coverage=coverage,
        generated_at=generated_at,
    )


def _titles(session: Session, org_id: uuid.UUID) -> dict[tuple[str, uuid.UUID], str]:
    titles: dict[tuple[str, uuid.UUID], str] = {}
    for doc_id, title in session.execute(
        select(Document.id, Document.title).where(Document.org_id == org_id)
    ):
        titles[("document", doc_id)] = title
    for ev_id, title in session.execute(
        select(EvidenceItem.id, EvidenceItem.title).where(EvidenceItem.org_id == org_id)
    ):
        titles[("evidence", ev_id)] = title
    return titles


def current_items(session: Session, org_id: uuid.UUID) -> list[CurrentItem]:
    titles = _titles(session, org_id)
    rows = session.scalars(
        select(ItemStatus)
        .where(ItemStatus.org_id == org_id)
        .order_by(ItemStatus.item_kind, ItemStatus.item_id, ItemStatus.framework)
    )
    return [
        CurrentItem(
            item_kind=row.item_kind,
            item_id=row.item_id,
            framework=row.framework,
            title=titles.get((row.item_kind, row.item_id), "(untitled)"),
            status=row.status,
            trusted=row.trusted,
            causes=tuple(str(c.get("text", "")) for c in row.causes if c.get("text")),
        )
        for row in rows
    ]


def last_sent_report(session: Session, org_id: uuid.UUID) -> WeeklyReport | None:
    return session.scalars(
        select(WeeklyReport)
        .where(WeeklyReport.org_id == org_id, WeeklyReport.sent_at.is_not(None))
        .order_by(WeeklyReport.sent_at.desc(), WeeklyReport.created_at.desc())
    ).first()


def report_for_run(session: Session, org_id: uuid.UUID, run_id: uuid.UUID) -> WeeklyReport | None:
    return session.scalars(
        select(WeeklyReport).where(
            WeeklyReport.org_id == org_id, WeeklyReport.check_run_id == run_id
        )
    ).one_or_none()


def build_report(
    session: Session, org_id: uuid.UUID, run_id: uuid.UUID, *, clock: Clock = utcnow
) -> WeeklyReport:
    """Build and store the report for a finished run; an existing one is returned as is."""
    existing = report_for_run(session, org_id, run_id)
    if existing is not None:
        return existing
    run = session.scalars(
        select(CheckRun).where(CheckRun.id == run_id, CheckRun.org_id == org_id)
    ).one()
    coverage = coverage_summary(
        run_coverage(session, org_id, run_id).to_json(), run_status=run.status.value
    )
    items = current_items(session, org_id)
    baseline = last_sent_report(session, org_id)
    sections = diff_sections(baseline.snapshot if baseline else None, items, coverage)
    report = WeeklyReport(
        org_id=org_id,
        check_run_id=run_id,
        snapshot=snapshot_of(items),
        sections=sections,
        coverage=coverage,
        created_at=clock(),
    )
    session.add(report)
    session.flush()
    append_event(
        session,
        org_id=org_id,
        actor=report_actor(run_id),
        event_type="weekly_report.built",
        subject_kind="weekly_report",
        subject_id=report.id,
        payload={
            "check_run_id": str(run_id),
            "baseline_report_id": str(baseline.id) if baseline else None,
            "newly_bad": len(sections["newly_bad"]),
            "resolved": len(sections["resolved"]),
            "still_bad": len(sections["still_bad"]),
            "nothing_changed": sections["nothing_changed"],
            "unreachable": len(coverage["unreachable"]),
        },
    )
    return report
