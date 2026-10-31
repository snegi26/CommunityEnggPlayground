"""Weekly report (U13): pure diff, headline, rendering, and email body (R11, R12, KTD12)."""

import uuid
from datetime import UTC, datetime
from typing import Any

from passport.reports.builder import (
    CurrentItem,
    coverage_summary,
    diff_sections,
    render_report_html,
    snapshot_of,
)
from passport.reports.email import email_body

GENERATED = datetime(2026, 10, 26, 9, tzinfo=UTC)
ACCESS = uuid.UUID("00000000-0000-0000-0000-000000000001")
BACKUP = uuid.UUID("00000000-0000-0000-0000-000000000002")
REVIEW = uuid.UUID("00000000-0000-0000-0000-000000000003")
OFFENDER_CAUSE = 'Contradicted on AWS prod (111111111111): "MFA is required" does not hold for bob.'


def item(
    item_id: uuid.UUID,
    status: str,
    *,
    title: str = "Access policy",
    kind: str = "document",
    causes: tuple[str, ...] = (),
) -> CurrentItem:
    return CurrentItem(
        item_kind=kind,
        item_id=item_id,
        framework="soc2",
        title=title,
        status=status,
        trusted=True,
        causes=causes,
    )


def coverage(*, reachable: dict[str, bool] | None = None, **counts: int) -> dict[str, Any]:
    reachable = {"AWS prod": True} if reachable is None else reachable
    base = {
        "claims": 3,
        "checked": 2,
        "current": 2,
        "contradicted": 0,
        "check_failed": 0,
        "not_checkable": 1,
        "deadline_exceeded": 0,
        "systems": [
            {"connection_id": name, "name": name, "kind": "aws", "reachable": ok, "outcomes": []}
            for name, ok in reachable.items()
        ],
    }
    base.update(counts)
    return coverage_summary(base, run_status="succeeded")


def titles(entries: list[dict[str, Any]]) -> list[str]:
    return [e["title"] for e in entries]


def test_the_first_report_is_a_baseline_listing_every_item() -> None:
    items = [
        item(ACCESS, "contradicted", causes=(OFFENDER_CAUSE,)),
        item(BACKUP, "current", title="Backup policy"),
        item(REVIEW, "expired", title="Access review", kind="evidence"),
    ]

    sections = diff_sections(None, items, coverage())

    assert sections["baseline"] is True
    assert sorted(titles(sections["all_items"])) == [
        "Access policy",
        "Access review",
        "Backup policy",
    ]
    assert titles(sections["newly_bad"]) == ["Access policy", "Access review"]
    assert sections["resolved"] == [] and sections["still_bad"] == []
    assert sections["nothing_changed"] is False


def test_ae8_an_item_going_from_contradicted_to_current_is_listed_as_resolved() -> None:
    backup = item(BACKUP, "expiring_soon", title="Backup policy")
    before = snapshot_of([item(ACCESS, "contradicted"), backup])

    sections = diff_sections(before, [item(ACCESS, "current"), backup], coverage())

    assert sections["baseline"] is False
    assert [(e["title"], e["before"], e["status"]) for e in sections["resolved"]] == [
        ("Access policy", "contradicted", "current")
    ]
    assert titles(sections["still_bad"]) == ["Backup policy"]
    assert sections["newly_bad"] == []
    assert sections["all_items"] == []


def test_changes_to_a_bad_status_are_newly_bad_and_unchanged_bad_items_are_still_bad() -> None:
    before = snapshot_of(
        [
            item(ACCESS, "current"),
            item(BACKUP, "expiring_soon", title="Backup policy"),
            item(REVIEW, "not_checkable", title="Access review"),
        ]
    )
    now = [
        item(ACCESS, "check_failed"),
        item(BACKUP, "expired", title="Backup policy"),
        item(REVIEW, "not_checkable", title="Access review"),
    ]

    sections = diff_sections(before, now, coverage())

    assert [(e["title"], e["before"], e["status"]) for e in sections["newly_bad"]] == [
        ("Backup policy", "expiring_soon", "expired"),
        ("Access policy", "current", "check_failed"),
    ]
    assert titles(sections["still_bad"]) == ["Access review"]
    assert sections["resolved"] == []


def test_ae4_no_change_with_every_system_reachable_is_a_quiet_week_with_full_counts() -> None:
    items = [item(ACCESS, "current"), item(BACKUP, "not_checkable", title="Backup policy")]
    cov = coverage()

    sections = diff_sections(snapshot_of(items), items, cov)
    html = render_report_html(
        org_name="Acme", sections=sections, coverage=cov, generated_at=GENERATED
    )

    assert sections["nothing_changed"] is True and sections["quiet_week"] is True
    assert "Nothing changed since the last report" in html
    for label, value in [("Claims checked", 2), ("Check failed", 0), ("Not checkable", 1)]:
        assert f"{label}: {value}" in html
    assert "AWS prod: reachable" in html


def test_ae6_an_unreachable_system_shows_in_coverage_and_is_not_a_quiet_week() -> None:
    items = [item(ACCESS, "check_failed")]
    cov = coverage(reachable={"AWS prod": True, "Workspace": False}, check_failed=1)

    # The item was already failing last week: no status changed, but the week was not quiet.
    sections = diff_sections(snapshot_of(items), items, cov)
    html = render_report_html(
        org_name="Acme", sections=sections, coverage=cov, generated_at=GENERATED
    )

    assert cov["unreachable"] == ["Workspace"] and cov["all_reachable"] is False
    assert sections["nothing_changed"] is True and sections["quiet_week"] is False
    assert "Nothing changed since the last report" not in html
    assert "Not everything was checked" in html
    assert "Workspace: unreachable" in html


def test_report_html_renders_every_section_with_causes() -> None:
    before = snapshot_of([item(ACCESS, "current"), item(BACKUP, "contradicted", title="Backup")])
    now = [
        item(ACCESS, "contradicted", causes=(OFFENDER_CAUSE,)),
        item(BACKUP, "current", title="Backup"),
        item(REVIEW, "expired", title="Access review", kind="evidence"),
    ]
    cov = coverage()
    sections = diff_sections(before, now, cov)

    html = render_report_html(
        org_name="Acme <Ltd>", sections=sections, coverage=cov, generated_at=GENERATED
    )

    for heading in ["Newly bad", "Resolved", "Still bad", "Coverage"]:
        assert heading in html
    assert "does not hold for bob" in html
    assert "Acme &lt;Ltd&gt;" in html
    baseline = render_report_html(
        org_name="Acme",
        sections=diff_sections(None, now, cov),
        coverage=cov,
        generated_at=GENERATED,
    )
    assert "Baseline" in baseline and "Backup" in baseline


def test_the_email_body_has_counts_titles_and_a_link_but_no_causes() -> None:
    now = [item(ACCESS, "contradicted", causes=(OFFENDER_CAUSE,))]
    cov = coverage(reachable={"AWS prod": True, "Workspace": False}, contradicted=1)
    sections = diff_sections(snapshot_of([item(ACCESS, "current")]), now, cov)

    body = email_body(
        org_name="Acme", sections=sections, coverage=cov, link="https://p.example/r/1"
    )

    assert "Access policy" in body
    assert "Newly bad: 1" in body and "Resolved: 0" in body
    assert "Claims checked: 2" in body
    assert "https://p.example/r/1" in body
    assert "unreachable" in body.lower()
    for leaked in ["bob", "111111111111", "does not hold", "Workspace", "AWS prod"]:
        assert leaked not in body
