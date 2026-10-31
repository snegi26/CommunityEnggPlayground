"""The passport per framework, item approval, claim review, re-runs, and reports (U14).

Claim and approval actions go through the U10 services with
``ActingMember.from_context``; their refusals become responses: ``ForbiddenError`` is
403, ``ClaimActionError`` (including ``NeedsAcknowledgementError``) is 409, each with
the service's message. Only people reach these routes (the actor is always the
signed-in user), so the agent never acts here.

"Last checked" (R1) is the latest ``CheckOutcome.checked_at`` among the claims of the
item's latest version; an item whose claims were never checked (or evidence, which has
no claims) shows "never".
"""

import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from passport.agent.models import AgentRun
from passport.auth.deps import DbSession, OrgContext
from passport.auth.models import User
from passport.checks.jobs import enqueue_run
from passport.checks.models import CheckOutcome
from passport.checks.runner import active_run, request_rerun
from passport.claims.approval import ApprovalItemNotFoundError, approve_item
from passport.claims.service import (
    ActingMember,
    ClaimActionError,
    ClaimNotFoundError,
    ForbiddenError,
    confirm_claim,
    current_claims,
    dismiss_claim,
    edit_claim,
    preview_check,
    reject_claim,
)
from passport.controls.models import Framework, ItemKind
from passport.db.models import (
    CheckRun,
    Claim,
    ClaimState,
    Document,
    DocumentVersion,
    EvidenceItem,
    ItemStatus,
    RunStatus,
)
from passport.documents.service import spans_for_version
from passport.predicates.registry import Predicate, PredicateError
from passport.predicates.registry import registry as predicates
from passport.reports.builder import render_report_html
from passport.reports.models import WeeklyReport
from passport.status.engine import SEVERITY
from passport.tenancy.models import Org
from passport.web.csrf import require_csrf
from passport.web.routes.common import (
    WebOrg,
    commit,
    rebind,
    refresh_statuses,
    render,
    see_other,
)
from passport.web.routes.setup import FRAMEWORK_LABELS, latest_versions

router = APIRouter(dependencies=[Depends(require_csrf)], default_response_class=HTMLResponse)

_RANK = {s.value: i for i, s in enumerate(SEVERITY)}
CLAIM_STATE_LABELS = {
    ClaimState.UNCONFIRMED.value: "Unconfirmed",
    ClaimState.NEEDS_REVIEW.value: "Needs review",
    ClaimState.CONFIRMED.value: "Confirmed",
    ClaimState.REJECTED.value: "Rejected",
    ClaimState.DISMISSED.value: "Dismissed",
}


def _names(db: Session, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    return {u.id: u.name for u in db.scalars(select(User).where(User.id.in_(ids)))}


# --- the passport ----------------------------------------------------------------------


@dataclass(frozen=True)
class PassportRow:
    item_kind: str
    item_id: uuid.UUID
    title: str
    status: str
    trusted: bool
    last_checked: datetime | None
    approved_by: str | None
    approved_on_behalf: bool
    approved_at: datetime | None
    causes: list[str]
    review_link: str | None


def _last_checked(
    db: Session, org_id: uuid.UUID, version_ids: list[uuid.UUID]
) -> dict[uuid.UUID, datetime]:
    if not version_ids:
        return {}
    rows = db.execute(
        select(Claim.document_version_id, func.max(CheckOutcome.checked_at))
        .join(CheckOutcome, CheckOutcome.claim_id == Claim.id)
        .where(Claim.org_id == org_id, Claim.document_version_id.in_(version_ids))
        .group_by(Claim.document_version_id)
    )
    return {version_id: checked for version_id, checked in rows}


def passport_rows(db: Session, org_id: uuid.UUID, framework: Framework) -> list[PassportRow]:
    statuses = list(
        db.scalars(
            select(ItemStatus).where(
                ItemStatus.org_id == org_id, ItemStatus.framework == framework.value
            )
        )
    )
    documents = {r.document.id: r for r in latest_versions(db, org_id)}
    evidence = {
        e.id: e for e in db.scalars(select(EvidenceItem).where(EvidenceItem.org_id == org_id))
    }
    checked = _last_checked(db, org_id, [r.version.id for r in documents.values()])
    approvers = {r.version.last_approved_by for r in documents.values()} | {
        e.last_approved_by for e in evidence.values()
    }
    names = _names(db, {a for a in approvers if a is not None})

    rows: list[PassportRow] = []
    for status_row in statuses:
        approvable: DocumentVersion | EvidenceItem
        if status_row.item_kind == ItemKind.DOCUMENT.value:
            doc = documents.get(status_row.item_id)
            if doc is None:
                continue
            approvable, title = doc.version, doc.document.title
            last = checked.get(doc.version.id)
            link: str | None = f"/orgs/{org_id}/versions/{doc.version.id}/claims"
        else:
            item = evidence.get(status_row.item_id)
            if item is None:
                continue
            approvable, title, last, link = item, item.title, None, None
        approver = approvable.last_approved_by
        rows.append(
            PassportRow(
                item_kind=status_row.item_kind,
                item_id=status_row.item_id,
                title=title,
                status=status_row.status,
                trusted=status_row.trusted,
                last_checked=last,
                approved_by=(names.get(approver, "a former member") if approver else None),
                approved_on_behalf=approvable.approved_on_behalf,
                approved_at=approvable.approved_at,
                causes=[str(c["text"]) for c in status_row.causes if c.get("text")],
                review_link=link,
            )
        )
    rows.sort(key=lambda r: (_RANK.get(r.status, len(_RANK)), r.title.lower()))
    return rows


@dataclass(frozen=True)
class RunState:
    """What the re-run control shows: idle, queued, running, or failed."""

    state: str
    run: CheckRun | None
    last_completed: datetime | None
    reason: str | None


def run_state(db: Session, org_id: uuid.UUID) -> RunState:
    last_ok = db.scalar(
        select(func.max(CheckRun.finished_at)).where(
            CheckRun.org_id == org_id, CheckRun.status == RunStatus.SUCCEEDED
        )
    )
    running = active_run(db, org_id)
    if running is not None:
        return RunState(running.status.value, running, last_ok, None)
    latest = db.scalars(
        select(CheckRun).where(CheckRun.org_id == org_id).order_by(CheckRun.created_at.desc())
    ).first()
    if latest is not None and latest.status is RunStatus.FAILED:
        return RunState("failed", latest, last_ok, latest.failure_reason)
    return RunState("idle", latest, last_ok, None)


def _latest_report(db: Session, org_id: uuid.UUID) -> WeeklyReport | None:
    return db.scalars(
        select(WeeklyReport)
        .where(WeeklyReport.org_id == org_id)
        .order_by(WeeklyReport.created_at.desc())
    ).first()


@router.get("/orgs/{org_id}/passport")
def passport_page(
    request: Request, ctx: WebOrg, db: DbSession, framework: Framework = Framework.SOC2
) -> Response:
    return render(
        request,
        "passport.html",
        {
            "framework": framework.value,
            "frameworks": [(f.value, FRAMEWORK_LABELS[f]) for f in Framework],
            "framework_label": FRAMEWORK_LABELS[framework],
            "rows": passport_rows(db, ctx.org_id, framework),
            "run": run_state(db, ctx.org_id),
            "report": _latest_report(db, ctx.org_id),
        },
        ctx=ctx,
        db=db,
    )


@router.get("/orgs/{org_id}/checks/status")
def run_status_fragment(request: Request, ctx: WebOrg, db: DbSession) -> Response:
    return render(request, "run_status.html", {"run": run_state(db, ctx.org_id)}, ctx=ctx)


@router.post("/orgs/{org_id}/checks/rerun")
def rerun(
    request: Request,
    ctx: WebOrg,
    db: DbSession,
    framework: Annotated[str, Form()] = Framework.SOC2.value,
) -> Response:
    try:
        run, created = request_rerun(db, ActingMember.from_context(ctx))
    except ForbiddenError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from None
    run_id = run.id
    commit(db, ctx)
    if created:
        enqueue_run(ctx.org_id, run_id)
    fw = framework if framework in {f.value for f in Framework} else Framework.SOC2.value
    return see_other(f"/orgs/{ctx.org_id}/passport?framework={fw}")


@router.post("/orgs/{org_id}/items/{item_kind}/{item_id}/approve")
def approve(
    request: Request,
    item_kind: ItemKind,
    item_id: uuid.UUID,
    ctx: WebOrg,
    db: DbSession,
    framework: Annotated[Framework, Form()] = Framework.SOC2,
) -> Response:
    """Mark the item reviewed; a policy's approval applies to its latest version."""
    target_id = item_id
    if item_kind is ItemKind.DOCUMENT:
        latest = next(
            (r for r in latest_versions(db, ctx.org_id) if r.document.id == item_id), None
        )
        if latest is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
        target_id = latest.version.id
    try:
        approve_item(
            db,
            ActingMember.from_context(ctx),
            item_kind="document_version" if item_kind is ItemKind.DOCUMENT else "evidence",
            item_id=target_id,
            framework=framework,
        )
    except ForbiddenError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from None
    except ApprovalItemNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found") from None
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/passport?framework={framework.value}")


# --- claim review ----------------------------------------------------------------------


@dataclass(frozen=True)
class ParamField:
    name: str
    kind: str  # "scope", "number", "checkbox", or "text"
    value: Any
    options: list[str]


def param_fields(predicate: Predicate[Any], values: Mapping[str, Any]) -> list[ParamField]:
    """Typed inputs for a predicate's parameters, filled from ``values`` or defaults."""
    fields: list[ParamField] = []
    for name, info in predicate.params_model.model_fields.items():
        default = None if info.is_required() else info.get_default(call_default_factory=True)
        value = values.get(name, default)
        if name == "scope":
            fields.append(ParamField(name, "scope", value, sorted(predicate.scope_rule.keywords)))
        elif info.annotation is bool:
            fields.append(ParamField(name, "checkbox", bool(value), []))
        elif info.annotation is int:
            fields.append(ParamField(name, "number", value, []))
        else:
            fields.append(ParamField(name, "text", value, []))
    return fields


def params_from_form(predicate: Predicate[Any], form: Mapping[str, Any]) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for f in param_fields(predicate, {}):
        raw = form.get(f"param_{f.name}")
        if f.kind == "scope":
            if raw == "named":
                names = str(form.get("param_scope_names", ""))
                params["scope"] = [n.strip() for n in names.split(",") if n.strip()]
            else:
                params["scope"] = raw or ""
        elif f.kind == "checkbox":
            params[f.name] = raw is not None
        elif raw not in (None, ""):
            params[f.name] = raw
    return params


@dataclass(frozen=True)
class ClaimView:
    claim: Claim
    state_label: str
    checkable: bool
    open: bool
    confirmed_by: str | None
    fields: list[ParamField]


def _version(db: Session, ctx: OrgContext, version_id: uuid.UUID) -> DocumentVersion:
    version = db.get(DocumentVersion, version_id)
    if version is None or version.org_id != ctx.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return version


def _claims_page(
    request: Request,
    ctx: OrgContext,
    db: Session,
    version: DocumentVersion,
    *,
    status_code: int = 200,
    **context: Any,
) -> Response:
    document = db.get(Document, version.document_id)
    assert document is not None
    claims = current_claims(db, ctx.org_id, version.id)
    names = _names(db, {c.confirmed_by for c in claims if c.confirmed_by})
    views = []
    for c in claims:
        fields: list[ParamField] = []
        if c.predicate_id is not None:
            try:
                fields = param_fields(predicates.latest(c.predicate_id), c.parameters)
            except PredicateError:
                fields = []
        views.append(
            ClaimView(
                claim=c,
                state_label=CLAIM_STATE_LABELS[c.state.value],
                checkable=c.predicate_id is not None,
                open=c.state not in (ClaimState.REJECTED, ClaimState.DISMISSED),
                confirmed_by=names.get(c.confirmed_by) if c.confirmed_by else None,
                fields=fields,
            )
        )
    drafting = db.scalars(
        select(AgentRun)
        .where(AgentRun.org_id == ctx.org_id, AgentRun.document_version_id == version.id)
        .order_by(AgentRun.created_at.desc())
    ).first()
    return render(
        request,
        "claims.html",
        {
            "document": document,
            "version": version,
            "claims": views,
            "drafting": drafting,
            "no_text": not spans_for_version(db, version.id),
            "predicates": [(p.id, p.title) for p in _latest_predicates()],
            **context,
        },
        ctx=ctx,
        db=db,
        status_code=status_code,
    )


def _latest_predicates() -> list[Predicate[Any]]:
    latest: dict[str, Predicate[Any]] = {}
    for p in predicates.all():
        if p.id not in latest or p.version > latest[p.id].version:
            latest[p.id] = p
    return sorted(latest.values(), key=lambda p: p.title)


@router.get("/orgs/{org_id}/versions/{version_id}/claims")
def claims_page(
    request: Request, version_id: uuid.UUID, ctx: WebOrg, db: DbSession, uploaded: int = 0
) -> Response:
    return _claims_page(request, ctx, db, _version(db, ctx, version_id), uploaded=bool(uploaded))


def _claim(db: Session, ctx: OrgContext, claim_id: uuid.UUID) -> Claim:
    claim = db.get(Claim, claim_id)
    if claim is None or claim.org_id != ctx.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    return claim


def _claim_action(
    request: Request,
    ctx: OrgContext,
    db: Session,
    claim_id: uuid.UUID,
    action: Callable[[ActingMember], object],
) -> Response:
    claim = _claim(db, ctx, claim_id)
    version_id = claim.document_version_id
    try:
        action(ActingMember.from_context(ctx))
    except ForbiddenError as exc:
        rebind(db, ctx)
        return _claims_page(
            request, ctx, db, _version(db, ctx, version_id), status_code=403, error=str(exc)
        )
    except ClaimActionError as exc:
        rebind(db, ctx)
        return _claims_page(
            request, ctx, db, _version(db, ctx, version_id), status_code=409, error=str(exc)
        )
    except ClaimNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found") from None
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/versions/{version_id}/claims")


@router.post("/orgs/{org_id}/claims/{claim_id}/confirm")
def confirm(
    request: Request,
    claim_id: uuid.UUID,
    ctx: WebOrg,
    db: DbSession,
    acknowledge: Annotated[bool, Form()] = False,
) -> Response:
    return _claim_action(
        request,
        ctx,
        db,
        claim_id,
        lambda acting: confirm_claim(db, acting, claim_id, acknowledge_reason=acknowledge),
    )


@router.post("/orgs/{org_id}/claims/{claim_id}/reject")
def reject(
    request: Request,
    claim_id: uuid.UUID,
    ctx: WebOrg,
    db: DbSession,
    reason: Annotated[str, Form()] = "",
) -> Response:
    return _claim_action(
        request,
        ctx,
        db,
        claim_id,
        lambda acting: reject_claim(db, acting, claim_id, reason=reason.strip() or None),
    )


@router.post("/orgs/{org_id}/claims/{claim_id}/dismiss")
def dismiss(
    request: Request,
    claim_id: uuid.UUID,
    ctx: WebOrg,
    db: DbSession,
    reason: Annotated[str, Form()] = "",
) -> Response:
    return _claim_action(
        request,
        ctx,
        db,
        claim_id,
        lambda acting: dismiss_claim(db, acting, claim_id, reason=reason.strip() or None),
    )


async def _form(request: Request) -> dict[str, Any]:
    form = await request.form()
    return {k: v for k, v in form.items() if isinstance(v, str)}


Submitted = Annotated[dict[str, Any], Depends(_form)]


def _edit_inputs(form: Mapping[str, Any]) -> tuple[Predicate[Any], dict[str, Any]]:
    predicate = predicates.latest(str(form.get("predicate_id", "")))
    return predicate, params_from_form(predicate, form)


@router.post("/orgs/{org_id}/claims/{claim_id}/preview")
def preview(
    request: Request, claim_id: uuid.UUID, ctx: WebOrg, db: DbSession, form: Submitted
) -> Response:
    """Show the check an edit would make, in plain language, without saving (R7)."""
    claim = _claim(db, ctx, claim_id)
    version = _version(db, ctx, claim.document_version_id)
    editing: dict[str, Any] = {"claim_id": claim_id}
    try:
        predicate, params = _edit_inputs(form)
        editing["predicate_id"] = predicate.id
        editing["fields"] = param_fields(predicate, params)
        editing["description"] = preview_check(predicate.id, params).check_description
    except PredicateError as exc:
        editing["error"] = str(exc)
        return _claims_page(request, ctx, db, version, status_code=422, editing=editing)
    return _claims_page(request, ctx, db, version, editing=editing)


@router.post("/orgs/{org_id}/claims/{claim_id}/edit")
def edit(
    request: Request, claim_id: uuid.UUID, ctx: WebOrg, db: DbSession, form: Submitted
) -> Response:
    claim = _claim(db, ctx, claim_id)
    try:
        predicate, params = _edit_inputs(form)
    except PredicateError as exc:
        version = _version(db, ctx, claim.document_version_id)
        editing = {"claim_id": claim_id, "error": str(exc)}
        return _claims_page(request, ctx, db, version, status_code=422, editing=editing)
    try:
        return _claim_action(
            request,
            ctx,
            db,
            claim_id,
            lambda acting: edit_claim(
                db, acting, claim_id, predicate_id=predicate.id, parameters=params
            ),
        )
    except PredicateError as exc:
        rebind(db, ctx)
        version = _version(db, ctx, claim.document_version_id)
        editing = {
            "claim_id": claim_id,
            "predicate_id": predicate.id,
            "fields": param_fields(predicate, params),
            "error": str(exc),
        }
        return _claims_page(request, ctx, db, version, status_code=422, editing=editing)


# --- reports ---------------------------------------------------------------------------


@router.get("/orgs/{org_id}/reports/{report_id}")
def report_page(report_id: uuid.UUID, ctx: WebOrg, db: DbSession) -> HTMLResponse:
    """The stored weekly report; the report email links here (KTD12)."""
    report = db.scalars(
        select(WeeklyReport).where(WeeklyReport.id == report_id, WeeklyReport.org_id == ctx.org_id)
    ).one_or_none()
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    org = db.get(Org, ctx.org_id)
    html = render_report_html(
        org_name=org.name if org else "",
        sections=report.sections,
        coverage=report.coverage,
        generated_at=report.created_at,
    )
    return HTMLResponse(html)
