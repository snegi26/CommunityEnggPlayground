"""Plain-language cause text, rendered from structured fields by templates (R3, KTD9).

The engine stores every cause as structured fields (claim, offenders, systems, scope,
dates) and renders the text here with fixed templates, so no model runs at check time
and the same inputs always produce the same text. Dates are absolute (never "in 20
days"), so a recompute on another day with unchanged inputs yields identical causes.
"""

from collections.abc import Mapping, Sequence
from typing import Any

# Failure kinds in words (connectors' FailureKind values, plus a connector error).
_FAILURES = {
    "unauthorized": "access was denied (credentials revoked or expired)",
    "rate_limited": "the provider rate-limited the read",
    "timeout": "the read timed out",
    "incomplete_pagination": "the provider stopped returning pages",
    "error": "the connector raised an error",
}

_NOT_CHECKABLE = {
    "no_predicate": 'No supported check covers "{quote}".',
    "unknown_predicate": 'The check bound to "{quote}" is no longer available.',
    "no_connection": 'No connected system can check "{quote}".',
    "not_checked_yet": '"{quote}" has not been checked yet.',
    "empty": '{systems} returned no records for "{quote}", so it was not checked.',
    "incomplete": '{systems} returned incomplete records for "{quote}", so it was not checked.',
}

TEMPLATES: Mapping[str, str] = {
    "contradicted": 'Contradicted on {systems}: "{quote}" does not hold for {offenders}.',
    "check_failed": 'Check failed for "{quote}": {failures}. {last_verified_text}',
    "partially_checked": ('Partially checked: "{quote}" holds on {checked}, but {gap}.'),
    "unconfirmed": '"{quote}" is awaiting confirmation by an approver.',
    "review_overdue": "Review was due on {due_on} and has not been done.",
    "review_due_soon": "Review is due on {due_on}, within the {lead_days}-day lead time.",
    "outside_window": (
        "Collected on {collected_on}, outside the audit window {window_start} to {window_end}."
    ),
    "window_ending": (
        "The audit window {window_start} to {window_end} ends within the {lead_days}-day lead time."
    ),
    "nothing_to_check": "This {item_kind} has no checkable claims or dates to check.",
    "all_passed": "{count} {claims} checked against {systems}, all holding.",
    "unmapped": "Not mapped to any control; shown under {framework}.",
}


def join(values: Sequence[str]) -> str:
    items = [v for v in values if v]
    if not items:
        return "none"
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} and {items[-1]}"


def system_label(name: str, scope: Sequence[str]) -> str:
    return f"{name} ({', '.join(scope)})" if scope else name


def failure_label(label: str, outcome: str, detail: str = "") -> str:
    reason = _FAILURES.get(outcome, outcome.replace("_", " "))
    return f"{label}: {reason}"


def _short(quote: str, limit: int = 160) -> str:
    quote = " ".join(quote.split())
    return quote if len(quote) <= limit else quote[: limit - 1].rstrip() + "…"


def render(kind: str, fields: Mapping[str, Any]) -> str:
    """Render one cause's text from its structured fields."""
    values: dict[str, Any] = dict(fields)
    if "quote" in values:
        values["quote"] = _short(str(values["quote"]))
    for key in ("systems", "offenders", "checked", "failures"):
        if isinstance(values.get(key), list | tuple):
            values[key] = join(values[key])
    if kind == "not_checkable":
        return _NOT_CHECKABLE[values["reason"]].format(**values)
    if kind == "check_failed":
        verified = values.get("last_verified_on")
        values["last_verified_text"] = (
            f"Last verified on {verified}." if verified else "Never verified successfully."
        )
        if values.get("reason") == "deadline_exceeded":
            values["failures"] = "the run reached its deadline before this check"
    if kind == "partially_checked":
        unchecked = list(fields.get("unchecked", ()))
        undeclared = list(fields.get("undeclared", ()))
        gaps = []
        if unchecked:
            verb = "was" if len(unchecked) == 1 else "were"
            gaps.append(f"{join(unchecked)} {verb} not checked")
        if undeclared or not unchecked:
            named = f" ({join(undeclared)})" if undeclared else ""
            gaps.append(f"its scope{named} is not declared in the scope inventory")
        values["gap"] = "; ".join(gaps)
    if kind == "all_passed":
        values["claims"] = "claim" if values["count"] == 1 else "claims"
    return TEMPLATES[kind].format(**values)
