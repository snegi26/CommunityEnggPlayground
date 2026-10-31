"""The setup wizard, in F1 order.

Steps and when each counts as complete (derived from stored data, never a flag):

1. ``connect``: the org has at least one active connection.
2. ``settings``: every framework has saved settings with its audit date(s) set (an
   as-of date for SOC 2 Type I, a window otherwise); the defaults carry no dates.
3. ``upload``: at least one policy document or evidence item.
4. ``map``: at least one item is mapped to a control.
5. ``invite``: an approver was invited or is a member.

``GET /orgs/{org_id}/setup`` resumes at the first incomplete step. Connecting, settings,
scope, and invitations are owner actions; uploads and mappings are open to owners and
approvers. Viewers see the pages read-only.
"""

import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy import exists, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from passport.agent.jobs import draft_claims
from passport.auth.deps import SESSION_COOKIE, DbSession, OrgContext
from passport.auth.models import User
from passport.auth.service import hash_token
from passport.claims.matching import carry_over_confirmations
from passport.connectors.aws import ClientFactory
from passport.connectors.models import Connection, ConnectionKind, ConnectionStatus
from passport.connectors.setup import (
    AWS_TEMPLATE_PATH,
    ConnectionSetup,
    PlatformSettings,
    SetupError,
    begin_aws_setup,
    begin_github_setup,
    begin_google_setup,
    complete_aws_setup,
    complete_github_setup,
    complete_google_setup,
    org_id_from_state,
)
from passport.connectors.vault import Vault, get_vault
from passport.controls.models import (
    AuditType,
    ControlMapping,
    Framework,
    ItemKind,
    OrgFrameworkSettings,
    ScopeEntry,
    ScopeKind,
)
from passport.controls.service import UnknownControlError, list_controls, map_item, unmap_item
from passport.controls.settings import (
    DEFAULT_ACCESS_REVIEW_DAYS,
    DEFAULT_AUDIT_TYPE,
    DEFAULT_EXPIRING_SOON_DAYS,
    DEFAULT_POLICY_REVIEW_DAYS,
    ScopeEntryNotFoundError,
    SettingsValidationError,
    add_scope_entry,
    ensure_defaults,
    list_scope_entries,
    remove_scope_entry,
    update_framework_settings,
)
from passport.db.models import Document, DocumentVersion, EvidenceItem
from passport.documents.parsing import DocumentRejectedError
from passport.documents.service import upload_evidence, upload_policy
from passport.documents.storage import ObjectStorage, get_storage
from passport.tenancy.models import Invitation, Membership, Role
from passport.tenancy.service import create_invitation
from passport.web.csrf import require_csrf
from passport.web.routes.common import (
    WebOrg,
    WebSignedIn,
    commit,
    rebind,
    refresh_statuses,
    render,
    require_approving,
    require_owner,
    see_other,
    web_org,
)

router = APIRouter(dependencies=[Depends(require_csrf)], default_response_class=HTMLResponse)

STEPS: tuple[tuple[str, str], ...] = (
    ("connect", "Connect systems"),
    ("settings", "Audit settings and scope"),
    ("upload", "Upload policies and evidence"),
    ("map", "Map items to controls"),
    ("invite", "Invite the approver"),
)
FRAMEWORK_LABELS = {Framework.SOC2: "SOC 2", Framework.ISO27001: "ISO 27001"}
AUDIT_TYPE_LABELS = {
    AuditType.SOC2_TYPE1: "SOC 2 Type I (single as-of date)",
    AuditType.SOC2_TYPE2: "SOC 2 Type II (observation window)",
    AuditType.ISO27001_CERTIFICATION: "ISO 27001 certification cycle (window)",
}
SCOPE_KIND_LABELS = {
    ScopeKind.AWS_ACCOUNT: "AWS account",
    ScopeKind.GITHUB_ORG: "GitHub organization",
    ScopeKind.WORKSPACE_DOMAIN: "Google Workspace domain",
}
KIND_LABELS = {
    ConnectionKind.AWS.value: "AWS",
    ConnectionKind.GOOGLE_WORKSPACE.value: "Google Workspace",
    ConnectionKind.GITHUB.value: "GitHub",
}


# Provider dependencies, overridden in tests with fakes.
def _boto_sts() -> Any:
    import boto3

    return boto3.client("sts")


def _http_client() -> AbstractContextManager[httpx.Client]:
    return httpx.Client(timeout=30.0)


@dataclass
class SetupProviders:
    """Everything a setup flow reaches outside the database."""

    platform: PlatformSettings = field(default_factory=PlatformSettings)
    sts: Callable[[], Any] = _boto_sts
    # None: assume the verified role for the AWS account inventory read.
    aws_clients: ClientFactory | None = None
    http: Callable[[], AbstractContextManager[httpx.Client]] = _http_client
    vault: Callable[[], Vault] = get_vault


def get_setup_providers() -> SetupProviders:
    return SetupProviders()


def get_upload_storage() -> ObjectStorage:
    return get_storage()


Providers = Annotated[SetupProviders, Depends(get_setup_providers)]
Storage = Annotated[ObjectStorage, Depends(get_upload_storage)]


def session_key(request: Request) -> str:
    """Setups are bound to the browser session: the hash of its session cookie."""
    return hash_token(request.cookies.get(SESSION_COOKIE, ""))


def enqueue_drafting(org_id: uuid.UUID, version_id: uuid.UUID) -> int:
    """Defer drafting for a version whose upload transaction has committed."""
    job_id: int = draft_claims.defer(org_id=str(org_id), document_version_id=str(version_id))
    return job_id


def _dates_set(row: OrgFrameworkSettings) -> bool:
    if row.audit_type == AuditType.SOC2_TYPE1.value:
        return row.as_of_date is not None
    return row.window_start is not None and row.window_end is not None


def step_completion(db: Session, org_id: uuid.UUID) -> dict[str, bool]:
    settings = list(
        db.scalars(select(OrgFrameworkSettings).where(OrgFrameworkSettings.org_id == org_id))
    )
    saved = {s.framework for s in settings if _dates_set(s)}
    return {
        "connect": bool(
            db.scalar(
                select(
                    exists().where(
                        Connection.org_id == org_id,
                        Connection.status == ConnectionStatus.ACTIVE.value,
                    )
                )
            )
        ),
        "settings": saved >= {f.value for f in Framework},
        "upload": bool(
            db.scalar(select(exists().where(Document.org_id == org_id)))
            or db.scalar(select(exists().where(EvidenceItem.org_id == org_id)))
        ),
        "map": bool(db.scalar(select(exists().where(ControlMapping.org_id == org_id)))),
        "invite": bool(
            db.scalar(
                select(
                    exists().where(Invitation.org_id == org_id, Invitation.role == Role.APPROVER)
                )
            )
            or db.scalar(
                select(
                    exists().where(Membership.org_id == org_id, Membership.role == Role.APPROVER)
                )
            )
        ),
    }


def first_incomplete(done: dict[str, bool]) -> str | None:
    return next((key for key, _ in STEPS if not done[key]), None)


def _page(
    request: Request,
    ctx: OrgContext,
    db: Session,
    step: str,
    context: dict[str, Any],
    status_code: int = 200,
) -> Response:
    done = step_completion(db, ctx.org_id)
    return render(
        request,
        f"setup_{step}.html",
        {"steps": STEPS, "step": step, "done": done, **context},
        ctx=ctx,
        db=db,
        status_code=status_code,
    )


@router.get("/orgs/{org_id}/setup")
def resume(ctx: WebOrg, db: DbSession) -> Response:
    step = first_incomplete(step_completion(db, ctx.org_id))
    return see_other(f"/orgs/{ctx.org_id}/setup/{step or 'done'}")


@router.get("/orgs/{org_id}/setup/done")
def done_page(request: Request, ctx: WebOrg, db: DbSession) -> Response:
    versions = latest_versions(db, ctx.org_id)
    return _page(request, ctx, db, "done", {"documents": versions})


def _connections(db: Session, org_id: uuid.UUID) -> list[Connection]:
    return list(
        db.scalars(
            select(Connection)
            .where(Connection.org_id == org_id, Connection.status == ConnectionStatus.ACTIVE.value)
            .order_by(Connection.created_at)
        )
    )


def _connect_page(
    request: Request,
    ctx: OrgContext,
    db: Session,
    status_code: int = 200,
    **context: Any,
) -> Response:
    return _page(
        request,
        ctx,
        db,
        "connect",
        {"connections": _connections(db, ctx.org_id), "kind_labels": KIND_LABELS, **context},
        status_code,
    )


@router.get("/orgs/{org_id}/setup/connect")
def connect_page(
    request: Request, ctx: WebOrg, db: DbSession, connected: uuid.UUID | None = None
) -> Response:
    success = None
    if connected is not None:
        connection = db.get(Connection, connected)
        if connection is not None and connection.org_id == ctx.org_id:
            success = f"Connected {connection.display_name}."
    return _connect_page(request, ctx, db, success=success)


@router.get("/orgs/{org_id}/setup/aws/template")
def aws_template(ctx: WebOrg) -> PlainTextResponse:
    return PlainTextResponse(
        AWS_TEMPLATE_PATH.read_text(),
        media_type="application/x-yaml",
        headers={"Content-Disposition": 'attachment; filename="aws-readonly-role.yaml"'},
    )


@router.post("/orgs/{org_id}/setup/aws/start")
def aws_start(request: Request, ctx: WebOrg, db: DbSession, providers: Providers) -> Response:
    require_owner(ctx)
    try:
        start = begin_aws_setup(
            db,
            ctx.org_id,
            ctx.actor,
            session_key=session_key(request),
            platform=providers.platform,
        )
    except SetupError as exc:
        rebind(db, ctx)
        return _connect_page(request, ctx, db, 422, aws_error=str(exc), aws_restart=True)
    aws = {
        "token": start.token,
        "external_id": start.external_id,
        "instructions": start.instructions,
    }
    return _connect_page(request, ctx, db, aws=aws)


def _pending_aws(db: Session, token: str, providers: SetupProviders) -> dict[str, str] | None:
    """The still-pending setup behind ``token`` (RLS-scoped), for the retry form."""
    setup = db.scalars(
        select(ConnectionSetup).where(
            ConnectionSetup.token_hash == hash_token(token),
            ConnectionSetup.kind == ConnectionKind.AWS.value,
        )
    ).one_or_none()
    if setup is None:
        return None
    external_id = str(setup.payload.get("external_id", ""))
    principal = providers.platform.aws_platform_principal_arn or ""
    return {
        "token": token,
        "external_id": external_id,
        "instructions": (
            f"Deploy the role with PlatformPrincipalArn={principal} and "
            f"ExternalId={external_id}, then verify again."
        ),
    }


@router.post("/orgs/{org_id}/setup/aws/verify")
def aws_verify(
    request: Request,
    ctx: WebOrg,
    db: DbSession,
    providers: Providers,
    token: Annotated[str, Form()],
    role_arn: Annotated[str, Form()],
) -> Response:
    require_owner(ctx)
    try:
        connection = complete_aws_setup(
            db,
            ctx.org_id,
            ctx.actor,
            session_key=session_key(request),
            token=token,
            role_arn=role_arn,
            sts=providers.sts(),
            clients=providers.aws_clients,
        )
    except SetupError as exc:
        # Rolling back keeps the pending setup (and its external id) for the retry.
        rebind(db, ctx)
        pending = _pending_aws(db, token, providers)
        return _connect_page(
            request,
            ctx,
            db,
            422,
            aws_error=str(exc),
            aws=pending,
            aws_restart=pending is None,
            role_arn=role_arn,
        )
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/setup/connect?connected={connection.id}")


@router.post("/orgs/{org_id}/setup/google/start")
def google_start(
    request: Request,
    ctx: WebOrg,
    db: DbSession,
    providers: Providers,
    domain: Annotated[str, Form()],
) -> Response:
    require_owner(ctx)
    try:
        start = begin_google_setup(
            db,
            ctx.org_id,
            ctx.actor,
            session_key=session_key(request),
            domain=domain,
            redirect_uri=str(request.url_for("google_callback")),
            platform=providers.platform,
        )
    except SetupError as exc:
        rebind(db, ctx)
        return _connect_page(request, ctx, db, 422, google_error=str(exc), domain=domain)
    return see_other(start.authorization_url)


@router.post("/orgs/{org_id}/setup/github/start")
def github_start(request: Request, ctx: WebOrg, db: DbSession, providers: Providers) -> Response:
    require_owner(ctx)
    try:
        start = begin_github_setup(
            db,
            ctx.org_id,
            ctx.actor,
            session_key=session_key(request),
            platform=providers.platform,
        )
    except SetupError as exc:
        rebind(db, ctx)
        return _connect_page(request, ctx, db, 422, github_error=str(exc))
    return see_other(start.install_url)


def _callback_org(request: Request, db: Session, state: str) -> OrgContext:
    """Route a provider callback to the org its state names, as a verified owner there."""
    try:
        org_id = org_id_from_state(state)
    except SetupError as exc:
        raise HTTPException(400, str(exc)) from None
    ctx = web_org(org_id, request, db)
    require_owner(ctx)
    return ctx


@router.get("/setup/google/callback", name="google_callback")
def google_callback(
    request: Request,
    db: DbSession,
    signed_in: WebSignedIn,
    providers: Providers,
    state: str = "",
    code: str = "",
    error: str = "",
) -> Response:
    ctx = _callback_org(request, db, state)
    if error:
        return _connect_page(
            request,
            ctx,
            db,
            422,
            google_error=f"Google did not grant access ({error}); start again.",
        )
    try:
        with providers.http() as http:
            connection = complete_google_setup(
                db,
                ctx.org_id,
                ctx.actor,
                session_key=session_key(request),
                state=state,
                code=code,
                vault=providers.vault(),
                platform=providers.platform,
                http=http,
            )
    except SetupError as exc:
        rebind(db, ctx)
        return _connect_page(request, ctx, db, 422, google_error=str(exc))
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/setup/connect?connected={connection.id}")


@router.get("/setup/github/callback", name="github_callback")
def github_callback(
    request: Request,
    db: DbSession,
    signed_in: WebSignedIn,
    providers: Providers,
    state: str = "",
    installation_id: str = "",
    code: str = "",
) -> Response:
    ctx = _callback_org(request, db, state)
    try:
        with providers.http() as http:
            connection = complete_github_setup(
                db,
                ctx.org_id,
                ctx.actor,
                session_key=session_key(request),
                state=state,
                installation_id=installation_id,
                code=code,
                platform=providers.platform,
                http=http,
            )
    except SetupError as exc:
        rebind(db, ctx)
        return _connect_page(request, ctx, db, 422, github_error=str(exc))
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/setup/connect?connected={connection.id}")


@dataclass(frozen=True)
class SettingsView:
    framework: Framework
    label: str
    audit_types: list[tuple[str, str]]
    audit_type: str
    as_of_date: date | None
    window_start: date | None
    window_end: date | None
    policy_review_days: int
    access_review_days: int
    expiring_soon_days: int
    saved: bool


def _settings_views(db: Session, org_id: uuid.UUID) -> list[SettingsView]:
    stored = {
        s.framework: s
        for s in db.scalars(
            select(OrgFrameworkSettings).where(OrgFrameworkSettings.org_id == org_id)
        )
    }
    views = []
    for framework in Framework:
        row = stored.get(framework.value)
        types = [
            (t.value, AUDIT_TYPE_LABELS[t])
            for t in AuditType
            if t.value.startswith("soc2" if framework is Framework.SOC2 else "iso27001")
        ]
        views.append(
            SettingsView(
                framework=framework,
                label=FRAMEWORK_LABELS[framework],
                audit_types=types,
                audit_type=row.audit_type if row else DEFAULT_AUDIT_TYPE[framework].value,
                as_of_date=row.as_of_date if row else None,
                window_start=row.window_start if row else None,
                window_end=row.window_end if row else None,
                policy_review_days=row.policy_review_days if row else DEFAULT_POLICY_REVIEW_DAYS,
                access_review_days=row.access_review_days if row else DEFAULT_ACCESS_REVIEW_DAYS,
                expiring_soon_days=row.expiring_soon_days if row else DEFAULT_EXPIRING_SOON_DAYS,
                saved=row is not None and _dates_set(row),
            )
        )
    return views


def _settings_page(
    request: Request, ctx: OrgContext, db: Session, status_code: int = 200, **context: Any
) -> Response:
    return _page(
        request,
        ctx,
        db,
        "settings",
        {
            "frameworks": _settings_views(db, ctx.org_id),
            "scope_entries": list_scope_entries(db),
            "scope_kinds": [(k.value, SCOPE_KIND_LABELS[k]) for k in ScopeKind],
            "scope_kind_labels": {k.value: v for k, v in SCOPE_KIND_LABELS.items()},
            **context,
        },
        status_code,
    )


@router.get("/orgs/{org_id}/setup/settings")
def settings_page(
    request: Request, ctx: WebOrg, db: DbSession, saved: str | None = None
) -> Response:
    return _settings_page(request, ctx, db, saved=saved)


class FormValueError(ValueError):
    pass


def _date(value: str, label: str) -> date | None:
    value = value.strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise FormValueError(f"{label} must be a date (YYYY-MM-DD)") from None


def _int(value: str, label: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        raise FormValueError(f"{label} must be a whole number of days") from None


@router.post("/orgs/{org_id}/setup/settings/{framework}")
def settings_save(
    request: Request,
    framework: Framework,
    ctx: WebOrg,
    db: DbSession,
    audit_type: Annotated[str, Form()],
    as_of_date: Annotated[str, Form()] = "",
    window_start: Annotated[str, Form()] = "",
    window_end: Annotated[str, Form()] = "",
    policy_review_days: Annotated[str, Form()] = "",
    access_review_days: Annotated[str, Form()] = "",
    expiring_soon_days: Annotated[str, Form()] = "",
) -> Response:
    require_owner(ctx)
    try:
        try:
            chosen = AuditType(audit_type)
        except ValueError:
            raise FormValueError("choose an audit type") from None
        ensure_defaults(db, ctx.org_id, ctx.actor)
        update_framework_settings(
            db,
            ctx.org_id,
            ctx.actor,
            framework,
            audit_type=chosen,
            as_of_date=_date(as_of_date, "The as-of date"),
            window_start=_date(window_start, "The window start"),
            window_end=_date(window_end, "The window end"),
            policy_review_days=_int(policy_review_days, "The policy review cadence"),
            access_review_days=_int(access_review_days, "The access review cadence"),
            expiring_soon_days=_int(expiring_soon_days, "The expiring-soon lead time"),
        )
    except (FormValueError, SettingsValidationError) as exc:
        rebind(db, ctx)
        return _settings_page(
            request, ctx, db, 422, settings_error={"framework": framework.value, "text": str(exc)}
        )
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/setup/settings?saved={framework.value}")


@router.post("/orgs/{org_id}/setup/scope")
def scope_add(
    request: Request,
    ctx: WebOrg,
    db: DbSession,
    kind: Annotated[str, Form()],
    identifier: Annotated[str, Form()],
    label: Annotated[str, Form()] = "",
    production: Annotated[bool, Form()] = False,
) -> Response:
    require_owner(ctx)
    try:
        scope_kind = ScopeKind(kind)
        if not identifier.strip():
            raise FormValueError("enter the system's identifier")
        with db.begin_nested():
            add_scope_entry(
                db,
                ctx.org_id,
                ctx.actor,
                scope_kind,
                identifier,
                label=label,
                production=production,
            )
    except (ValueError, IntegrityError) as exc:
        message = (
            f"{identifier.strip()} is already in the inventory"
            if isinstance(exc, IntegrityError)
            else str(exc)
        )
        rebind(db, ctx)
        return _settings_page(request, ctx, db, 422, scope_error=message)
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/setup/settings")


def _scope_entry(db: Session, ctx: OrgContext, entry_id: uuid.UUID) -> ScopeEntry:
    entry = db.get(ScopeEntry, entry_id)
    if entry is None or entry.org_id != ctx.org_id:
        raise HTTPException(404, "not_found")
    return entry


@router.post("/orgs/{org_id}/setup/scope/{entry_id}/remove")
def scope_remove(entry_id: uuid.UUID, ctx: WebOrg, db: DbSession) -> Response:
    require_owner(ctx)
    try:
        remove_scope_entry(db, ctx.org_id, ctx.actor, entry_id)
    except ScopeEntryNotFoundError:
        raise HTTPException(404, "not_found") from None
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/setup/settings")


@router.post("/orgs/{org_id}/setup/scope/{entry_id}/production")
def scope_production(
    entry_id: uuid.UUID,
    ctx: WebOrg,
    db: DbSession,
    production: Annotated[bool, Form()] = False,
) -> Response:
    """Mark an entry (for example a pre-filled AWS account) production or not.

    The inventory service has add and remove only, so the entry is replaced; both
    changes are in the event log.
    """
    require_owner(ctx)
    entry = _scope_entry(db, ctx, entry_id)
    if entry.production != production:
        kind, identifier, label = ScopeKind(entry.kind), entry.identifier, entry.label
        remove_scope_entry(db, ctx.org_id, ctx.actor, entry_id)
        add_scope_entry(
            db, ctx.org_id, ctx.actor, kind, identifier, label=label, production=production
        )
        refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/setup/settings")


@dataclass(frozen=True)
class DocumentRow:
    document: Document
    version: DocumentVersion


def latest_versions(db: Session, org_id: uuid.UUID) -> list[DocumentRow]:
    latest = (
        select(
            DocumentVersion.document_id,
            func.max(DocumentVersion.version_number).label("number"),
        )
        .where(DocumentVersion.org_id == org_id)
        .group_by(DocumentVersion.document_id)
        .subquery()
    )
    rows = db.execute(
        select(Document, DocumentVersion)
        .join(DocumentVersion, DocumentVersion.document_id == Document.id)
        .join(
            latest,
            (latest.c.document_id == DocumentVersion.document_id)
            & (latest.c.number == DocumentVersion.version_number),
        )
        .where(Document.org_id == org_id)
        .order_by(Document.title, Document.id)
    ).all()
    return [DocumentRow(d, v) for d, v in rows]


def latest_version_for(
    db: Session, org_id: uuid.UUID, document_id: uuid.UUID
) -> DocumentRow | None:
    """One document's row from :func:`latest_versions`, or None when it has none."""
    latest = (
        select(
            DocumentVersion.document_id,
            func.max(DocumentVersion.version_number).label("number"),
        )
        .where(DocumentVersion.org_id == org_id, DocumentVersion.document_id == document_id)
        .group_by(DocumentVersion.document_id)
        .subquery()
    )
    row = db.execute(
        select(Document, DocumentVersion)
        .join(DocumentVersion, DocumentVersion.document_id == Document.id)
        .join(
            latest,
            (latest.c.document_id == DocumentVersion.document_id)
            & (latest.c.number == DocumentVersion.version_number),
        )
        .where(Document.org_id == org_id, Document.id == document_id)
    ).first()
    return DocumentRow(row[0], row[1]) if row is not None else None


def _evidence(db: Session, org_id: uuid.UUID) -> list[EvidenceItem]:
    return list(
        db.scalars(
            select(EvidenceItem)
            .where(EvidenceItem.org_id == org_id)
            .order_by(EvidenceItem.title, EvidenceItem.id)
        )
    )


def _upload_page(
    request: Request, ctx: OrgContext, db: Session, status_code: int = 200, **context: Any
) -> Response:
    return _page(
        request,
        ctx,
        db,
        "upload",
        {
            "documents": latest_versions(db, ctx.org_id),
            "evidence": _evidence(db, ctx.org_id),
            **context,
        },
        status_code,
    )


@router.get("/orgs/{org_id}/setup/upload")
def upload_page(request: Request, ctx: WebOrg, db: DbSession) -> Response:
    return _upload_page(request, ctx, db)


def _uuid_or_none(value: str) -> uuid.UUID | None:
    value = value.strip()
    if not value:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        raise FormValueError("choose a document from the list") from None


@router.post("/orgs/{org_id}/setup/upload/policy")
def upload_policy_submit(
    request: Request,
    ctx: WebOrg,
    db: DbSession,
    storage: Storage,
    file: Annotated[UploadFile, File()],
    title: Annotated[str, Form()] = "",
    document_id: Annotated[str, Form()] = "",
    review_due_on: Annotated[str, Form()] = "",
) -> Response:
    """Store the version and carry confirmations over in one transaction, then draft.

    Drafting is enqueued only after the commit, so the job always finds the version and
    the carried-over claims (F3, R20).
    """
    require_approving(ctx)
    try:
        upload = upload_policy(
            db,
            org_id=ctx.org_id,
            actor=ctx.actor,
            filename=file.filename or "policy",
            data=file.file.read(),
            title=title.strip() or None,
            document_id=_uuid_or_none(document_id),
            review_due_on=_date(review_due_on, "The review date"),
            storage=storage,
        )
    except (DocumentRejectedError, FormValueError, LookupError) as exc:
        rebind(db, ctx)
        return _upload_page(request, ctx, db, 422, policy_error=str(exc))
    carry_over_confirmations(db, version=upload.version, actor=ctx.actor)
    refresh_statuses(db, ctx)
    version_id = upload.version.id
    commit(db, ctx)
    enqueue_drafting(ctx.org_id, version_id)
    return see_other(f"/orgs/{ctx.org_id}/versions/{version_id}/claims?uploaded=1")


@router.post("/orgs/{org_id}/setup/upload/evidence")
def upload_evidence_submit(
    request: Request,
    ctx: WebOrg,
    db: DbSession,
    storage: Storage,
    file: Annotated[UploadFile, File()],
    title: Annotated[str, Form()],
    source: Annotated[str, Form()],
    collected_at: Annotated[str, Form()],
) -> Response:
    require_approving(ctx)
    try:
        collected = _date(collected_at, "The collection date")
        if collected is None:
            raise FormValueError("enter the date the evidence was collected")
        if not title.strip() or not source.strip():
            raise FormValueError("enter the evidence title and where it came from")
        upload_evidence(
            db,
            org_id=ctx.org_id,
            actor=ctx.actor,
            title=title.strip(),
            filename=file.filename or "evidence",
            data=file.file.read(),
            source=source.strip(),
            collected_at=datetime(collected.year, collected.month, collected.day, tzinfo=UTC),
            storage=storage,
        )
    except (DocumentRejectedError, FormValueError) as exc:
        rebind(db, ctx)
        return _upload_page(request, ctx, db, 422, evidence_error=str(exc))
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/setup/upload")


@dataclass(frozen=True)
class MapRow:
    key: str
    kind_label: str
    title: str
    mappings: list[ControlMapping]


def _map_page(
    request: Request, ctx: OrgContext, db: Session, status_code: int = 200, **context: Any
) -> Response:
    mappings: dict[tuple[str, uuid.UUID], list[ControlMapping]] = {}
    for m in db.scalars(
        select(ControlMapping)
        .where(ControlMapping.org_id == ctx.org_id)
        .order_by(ControlMapping.framework, ControlMapping.control_id)
    ):
        mappings.setdefault((m.item_kind, m.item_id), []).append(m)
    rows = [
        MapRow(
            f"document:{r.document.id}",
            "Policy",
            r.document.title,
            mappings.get((ItemKind.DOCUMENT.value, r.document.id), []),
        )
        for r in latest_versions(db, ctx.org_id)
    ] + [
        MapRow(
            f"evidence:{e.id}",
            "Evidence",
            e.title,
            mappings.get((ItemKind.EVIDENCE.value, e.id), []),
        )
        for e in _evidence(db, ctx.org_id)
    ]
    catalogs = [(FRAMEWORK_LABELS[f], f.value, list_controls(db, f)) for f in Framework]
    return _page(
        request,
        ctx,
        db,
        "map",
        {"rows": rows, "catalogs": catalogs, "framework_labels": FRAMEWORK_LABELS, **context},
        status_code,
    )


@router.get("/orgs/{org_id}/setup/map")
def map_page(request: Request, ctx: WebOrg, db: DbSession) -> Response:
    return _map_page(request, ctx, db)


def _item(db: Session, ctx: OrgContext, key: str) -> tuple[ItemKind, uuid.UUID]:
    kind, _, raw = key.partition(":")
    try:
        item_kind, item_id = ItemKind(kind), uuid.UUID(raw)
    except ValueError:
        raise FormValueError("choose an item from the list") from None
    found: Document | EvidenceItem | None = (
        db.get(Document, item_id)
        if item_kind is ItemKind.DOCUMENT
        else db.get(EvidenceItem, item_id)
    )
    if found is None or found.org_id != ctx.org_id:
        raise FormValueError("choose an item from the list")
    return item_kind, item_id


def _control(value: str) -> tuple[Framework, str]:
    framework, _, control_id = value.partition(":")
    try:
        return Framework(framework), control_id
    except ValueError:
        raise FormValueError("choose a control from the list") from None


@router.post("/orgs/{org_id}/setup/map")
def map_add(
    request: Request,
    ctx: WebOrg,
    db: DbSession,
    item: Annotated[str, Form()],
    control: Annotated[str, Form()],
) -> Response:
    require_approving(ctx)
    try:
        item_kind, item_id = _item(db, ctx, item)
        framework, control_id = _control(control)
        map_item(db, ctx.org_id, ctx.actor, item_kind, item_id, framework, control_id)
    except (FormValueError, UnknownControlError) as exc:
        rebind(db, ctx)
        return _map_page(request, ctx, db, 422, map_error=str(exc))
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/setup/map")


@router.post("/orgs/{org_id}/setup/map/remove")
def map_remove(
    request: Request,
    ctx: WebOrg,
    db: DbSession,
    item: Annotated[str, Form()],
    control: Annotated[str, Form()],
) -> Response:
    require_approving(ctx)
    try:
        item_kind, item_id = _item(db, ctx, item)
        framework, control_id = _control(control)
    except FormValueError as exc:
        return _map_page(request, ctx, db, 422, map_error=str(exc))
    unmap_item(db, ctx.org_id, ctx.actor, item_kind, item_id, framework, control_id)
    refresh_statuses(db, ctx)
    return see_other(f"/orgs/{ctx.org_id}/setup/map")


def _invite_page(
    request: Request, ctx: OrgContext, db: Session, status_code: int = 200, **context: Any
) -> Response:
    members = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.org_id == ctx.org_id)
        .order_by(User.name)
    ).all()
    invitations = list(
        db.scalars(
            select(Invitation)
            .where(Invitation.org_id == ctx.org_id, Invitation.accepted_at.is_(None))
            .order_by(Invitation.created_at)
        )
    )
    return _page(
        request,
        ctx,
        db,
        "invite",
        {
            "members": members,
            "invitations": invitations,
            "roles": [r.value for r in Role],
            **context,
        },
        status_code,
    )


@router.get("/orgs/{org_id}/setup/invite")
def invite_page(request: Request, ctx: WebOrg, db: DbSession) -> Response:
    return _invite_page(request, ctx, db)


@router.post("/orgs/{org_id}/setup/invite")
def invite_submit(
    request: Request,
    ctx: WebOrg,
    db: DbSession,
    email: Annotated[str, Form()],
    role: Annotated[str, Form()] = Role.APPROVER.value,
    external: Annotated[bool, Form()] = False,
) -> Response:
    require_owner(ctx)
    try:
        chosen = Role(role)
    except ValueError:
        return _invite_page(request, ctx, db, 422, invite_error="choose a role")
    if "@" not in email:
        return _invite_page(request, ctx, db, 422, invite_error="enter the person's email")
    token = create_invitation(
        db, org_id=ctx.org_id, invited_by=ctx.user, email=email, role=chosen, external=external
    )
    # The link is shown once; only its hash is stored.
    link = str(request.url_for("invitation_page", token=token))
    return _invite_page(request, ctx, db, invite_link=link, invited=email.strip().lower())
