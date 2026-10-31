"""Login, MFA verification and enrollment, the org switcher, and invitation pages (U14).

These call the same services as the JSON endpoints in ``passport.auth.routes``.
"""

import uuid
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

from passport.auth import service
from passport.auth.deps import SESSION_COOKIE, DbSession
from passport.auth.routes import _client_ip, _set_session_cookie
from passport.tenancy import service as tenancy
from passport.web.csrf import require_csrf
from passport.web.routes.common import WebSignedIn, render, safe_next, see_other

router = APIRouter(dependencies=[Depends(require_csrf)], default_response_class=HTMLResponse)

Next = Annotated[str | None, Form()]


@router.get("/login")
def login_page(request: Request, next: str | None = None) -> Response:
    return render(request, "login.html", {"next": safe_next(next)})


@router.post("/login")
def login_submit(
    request: Request,
    db: DbSession,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Next = None,
) -> Response:
    destination = safe_next(next)
    try:
        result = service.authenticate(db, email=email, password=password, ip=_client_ip(request))
    except service.ThrottledError:
        return render(
            request,
            "login.html",
            {"next": destination, "error": "Too many attempts. Wait a few minutes and retry."},
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )
    except service.AuthError:
        db.commit()  # keep the recorded failure for throttling
        return render(
            request,
            "login.html",
            {"next": destination, "error": "The email or password is not correct."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    target = (
        f"/login/mfa?next={quote(destination, safe='')}" if result.mfa_required else destination
    )
    response = see_other(target)
    _set_session_cookie(response, result.session_token)
    return response


@router.get("/login/mfa")
def mfa_verify_page(request: Request, signed_in: WebSignedIn, next: str | None = None) -> Response:
    return render(request, "mfa_verify.html", {"next": safe_next(next), "user": signed_in.user})


@router.post("/login/mfa")
def mfa_verify_submit(
    request: Request,
    db: DbSession,
    signed_in: WebSignedIn,
    code: Annotated[str, Form()],
    next: Next = None,
) -> Response:
    destination = safe_next(next)
    token = request.cookies[SESSION_COOKIE]
    try:
        service.verify_mfa(db, session_token=token, code=code.strip(), ip=_client_ip(request))
    except service.ThrottledError:
        error, code_status = "Too many attempts. Wait a few minutes and retry.", 429
    except service.AuthError:
        db.commit()  # keep the recorded failure for throttling
        error, code_status = "That code is not valid. Try a current code or a recovery code.", 401
    else:
        return see_other(destination)
    return render(
        request,
        "mfa_verify.html",
        {"next": destination, "error": error, "user": signed_in.user},
        status_code=code_status,
    )


@router.get("/mfa/enroll")
def mfa_enroll_page(request: Request, signed_in: WebSignedIn, next: str | None = None) -> Response:
    return render(request, "mfa_enroll.html", {"next": safe_next(next), "user": signed_in.user})


@router.post("/mfa/enroll")
def mfa_enroll_start(
    request: Request, db: DbSession, signed_in: WebSignedIn, next: Next = None
) -> Response:
    uri = service.begin_totp_enrollment(db, signed_in.user)
    return render(
        request,
        "mfa_enroll.html",
        {"next": safe_next(next), "user": signed_in.user, "provisioning_uri": uri},
    )


@router.post("/mfa/enroll/confirm")
def mfa_enroll_confirm(
    request: Request,
    db: DbSession,
    signed_in: WebSignedIn,
    code: Annotated[str, Form()],
    next: Next = None,
) -> Response:
    destination = safe_next(next)
    try:
        codes = service.confirm_totp_enrollment(
            db,
            user=signed_in.user,
            code=code.strip(),
            session_token=request.cookies[SESSION_COOKIE],
        )
    except service.AuthError:
        return render(
            request,
            "mfa_enroll.html",
            {
                "next": destination,
                "user": signed_in.user,
                "error": "That code is not valid. Start enrollment again and enter a "
                "current code from the authenticator.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    # Recovery codes are shown once, here, and stored only as hashes.
    return render(
        request,
        "mfa_enroll.html",
        {"next": destination, "user": signed_in.user, "recovery_codes": codes},
    )


@router.post("/logout")
def logout(request: Request, db: DbSession) -> Response:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        service.logout(db, token)
    response = see_other("/login")
    response.delete_cookie(SESSION_COOKIE)
    return response


# --- org switcher ----------------------------------------------------------------------


@router.get("/")
def org_switcher(request: Request, db: DbSession, signed_in: WebSignedIn) -> Response:
    orgs = tenancy.orgs_for_user(db, user_id=signed_in.user.id)
    return render(request, "orgs.html", {"orgs": orgs, "user": signed_in.user})


@router.get("/switch")
def switch(org_id: uuid.UUID, signed_in: WebSignedIn) -> RedirectResponse:
    return see_other(f"/orgs/{org_id}/passport")


@router.post("/orgs/create")
def create_org(
    db: DbSession, signed_in: WebSignedIn, name: Annotated[str, Form()]
) -> RedirectResponse:
    name = name.strip()
    if not name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "name_required")
    org = tenancy.create_org(db, name=name, owner=signed_in.user)
    return see_other(f"/orgs/{org.id}/setup")


# --- invitations -----------------------------------------------------------------------


@router.get("/invitations/{token}")
def invitation_page(request: Request, token: str, signed_in: WebSignedIn) -> Response:
    return render(request, "invitation.html", {"token": token, "user": signed_in.user})


@router.post("/invitations/{token}")
def invitation_accept(
    request: Request, token: str, db: DbSession, signed_in: WebSignedIn
) -> Response:
    try:
        membership = tenancy.accept_invitation(db, token=token, user=signed_in.user)
    except tenancy.InvitationError:
        return render(
            request,
            "invitation.html",
            {
                "token": token,
                "user": signed_in.user,
                "error": "This invitation is not valid, has expired, or was already used.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return see_other(f"/orgs/{membership.org_id}/passport")
