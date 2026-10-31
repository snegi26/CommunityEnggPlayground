"""Shared pieces of the HTML pages: templates, sign-in redirects, and org context (U14).

Pages reuse the JSON API's services and dependencies (``passport.auth.deps``): the org
context check is the same ``org_context`` (membership, RLS binding, MFA for approving
roles); only its refusals are turned into redirects to the login and MFA pages.
"""

import uuid
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from passport.auth.deps import SESSION_COOKIE, DbSession, OrgContext, org_context
from passport.auth.service import CurrentSession, resolve_session
from passport.db.rls import set_org_context, set_user_context
from passport.reports.builder import STATUS_LABELS
from passport.status.service import recompute_statuses
from passport.tenancy.models import APPROVING_ROLES, Role
from passport.tenancy.service import orgs_for_user
from passport.web import csrf

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=TEMPLATES_DIR)
templates.env.globals["status_label"] = lambda s: STATUS_LABELS.get(s, s)
templates.env.trim_blocks = True
templates.env.lstrip_blocks = True


class LoginRedirect(Exception):
    """Send the browser to a sign-in step (login, MFA enrollment, MFA verification)."""

    def __init__(self, location: str) -> None:
        super().__init__(location)
        self.location = location


def safe_next(value: str | None, default: str = "/") -> str:
    """Only same-site paths are accepted as a post-login destination."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return default


def _here(request: Request) -> str:
    path = request.url.path
    if request.method == "GET" and request.url.query:
        path = f"{path}?{request.url.query}"
    return quote(path, safe="")


def web_signed_in(request: Request, db: DbSession) -> CurrentSession:
    token = request.cookies.get(SESSION_COOKIE)
    resolved = resolve_session(db, token) if token else None
    if resolved is None:
        raise LoginRedirect(f"/login?next={_here(request)}")
    return resolved


WebSignedIn = Annotated[CurrentSession, Depends(web_signed_in)]


def web_org(org_id: uuid.UUID, request: Request, db: DbSession) -> OrgContext:
    signed_in = web_signed_in(request, db)
    try:
        return org_context(org_id, db, signed_in)
    except HTTPException as exc:
        if exc.detail == "mfa_enrollment_required":
            raise LoginRedirect(f"/mfa/enroll?next={_here(request)}") from None
        if exc.detail == "mfa_verification_required":
            raise LoginRedirect(f"/login/mfa?next={_here(request)}") from None
        raise


WebOrg = Annotated[OrgContext, Depends(web_org)]


def can_approve(ctx: OrgContext) -> bool:
    return ctx.membership.role in APPROVING_ROLES


def is_owner(ctx: OrgContext) -> bool:
    return ctx.membership.role is Role.OWNER


def require_owner(ctx: OrgContext) -> None:
    if not is_owner(ctx):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owners only")


def require_approving(ctx: OrgContext) -> None:
    if not can_approve(ctx):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owners and approvers only")


def _ids(ctx: OrgContext) -> tuple[uuid.UUID, uuid.UUID]:
    # Read before the transaction ends: reloading expired rows needs the context first.
    return ctx.user.id, ctx.membership.org_id


def rebind(db: Session, ctx: OrgContext) -> None:
    """Roll back a failed action and restore the transaction-local tenant context."""
    user_id, org_id = _ids(ctx)
    db.rollback()
    set_user_context(db, user_id)
    set_org_context(db, org_id)


def commit(db: Session, ctx: OrgContext) -> None:
    """Commit, then bind the next transaction to the same user and org again."""
    user_id, org_id = _ids(ctx)
    db.commit()
    set_user_context(db, user_id)
    set_org_context(db, org_id)


def refresh_statuses(db: Session, ctx: OrgContext) -> None:
    """Recompute statuses after a person changes what they depend on (R1: always shown)."""
    recompute_statuses(db, ctx.org_id)


def render(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    ctx: OrgContext | None = None,
    db: Session | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    values: dict[str, Any] = {"csrf_token": csrf.token_for(request), **(context or {})}
    if ctx is not None:
        values.setdefault("ctx", ctx)
        values.setdefault("org_id", ctx.org_id)
        values.setdefault("role", ctx.membership.role.value)
        values.setdefault("can_approve", can_approve(ctx))
        values.setdefault("is_owner", is_owner(ctx))
        values.setdefault("user", ctx.user)
        if db is not None:
            choices = orgs_for_user(db, user_id=ctx.user.id)
            values.setdefault("orgs", choices)
            values.setdefault(
                "org_name", next((c.name for c in choices if c.org_id == ctx.org_id), "")
            )
    response = templates.TemplateResponse(request, name, values, status_code=status_code)
    csrf.set_pre_session_cookie(request, response)
    return response


def see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)
