"""Login, MFA, password reset, invitations, and org selection endpoints."""

import uuid

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr

from passport.auth import service
from passport.auth.deps import SESSION_COOKIE, DbSession, InOrg, SignedIn, require_roles
from passport.auth.models import User
from passport.tenancy import service as tenancy
from passport.tenancy.models import Role

router = APIRouter()


class Credentials(BaseModel):
    email: EmailStr
    password: str


class Registration(Credentials):
    name: str


class Code(BaseModel):
    code: str


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, secure=True, samesite="lax", max_age=12 * 3600
    )


@router.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(body: Registration, db: DbSession) -> dict[str, str]:
    user = service.register_user(db, email=body.email, name=body.name, password=body.password)
    return {"user_id": str(user.id)}


@router.post("/auth/login")
def login(
    body: Credentials, request: Request, response: Response, db: DbSession
) -> dict[str, bool]:
    try:
        result = service.authenticate(
            db, email=body.email, password=body.password, ip=_client_ip(request)
        )
    except service.ThrottledError:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too_many_attempts") from None
    except service.AuthError:
        db.commit()  # keep the recorded failure for throttling despite the error response
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_credentials") from None
    _set_session_cookie(response, result.session_token)
    return {"mfa_required": result.mfa_required}


@router.post("/auth/mfa/verify")
def mfa_verify(body: Code, request: Request, db: DbSession) -> dict[str, bool]:
    token = request.cookies.get(SESSION_COOKIE)
    try:
        if token is None:
            raise service.AuthError
        service.verify_mfa(db, session_token=token, code=body.code, ip=_client_ip(request))
    except service.ThrottledError:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too_many_attempts") from None
    except service.AuthError:
        db.commit()  # keep the recorded failure for throttling despite the error response
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_code") from None
    return {"mfa_verified": True}


@router.post("/auth/mfa/enroll")
def mfa_enroll(signed_in: SignedIn, db: DbSession) -> dict[str, str]:
    return {"provisioning_uri": service.begin_totp_enrollment(db, signed_in.user)}


@router.post("/auth/mfa/confirm")
def mfa_confirm(
    body: Code, request: Request, signed_in: SignedIn, db: DbSession
) -> dict[str, list[str]]:
    try:
        codes = service.confirm_totp_enrollment(
            db,
            user=signed_in.user,
            code=body.code,
            session_token=request.cookies[SESSION_COOKIE],
        )
    except service.AuthError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid_code") from None
    return {"recovery_codes": codes}


@router.post("/auth/logout")
def logout(request: Request, response: Response, db: DbSession) -> dict[str, bool]:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        service.logout(db, token)
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


class ResetRequest(BaseModel):
    email: EmailStr


class ResetCompletion(BaseModel):
    token: str
    new_password: str
    second_factor: str | None = None


@router.post("/auth/password-reset", status_code=status.HTTP_202_ACCEPTED)
def password_reset(body: ResetRequest, db: DbSession) -> dict[str, bool]:
    # Delivery of the token by email is wired with report email (U13); the response never
    # reveals whether the account exists.
    service.request_password_reset(db, email=body.email)
    return {"ok": True}


@router.post("/auth/password-reset/complete")
def password_reset_complete(body: ResetCompletion, db: DbSession) -> dict[str, bool]:
    try:
        service.complete_password_reset(
            db, token=body.token, new_password=body.new_password, second_factor=body.second_factor
        )
    except service.AuthError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid_reset") from None
    return {"ok": True}


class NewOrg(BaseModel):
    name: str


@router.post("/orgs", status_code=status.HTTP_201_CREATED)
def create_org(body: NewOrg, signed_in: SignedIn, db: DbSession) -> dict[str, str]:
    org = tenancy.create_org(db, name=body.name, owner=signed_in.user)
    return {"org_id": str(org.id)}


@router.get("/orgs")
def list_orgs(signed_in: SignedIn, db: DbSession) -> list[dict[str, str]]:
    return [
        {"org_id": str(c.org_id), "name": c.name, "role": c.role.value}
        for c in tenancy.orgs_for_user(db, user_id=signed_in.user.id)
    ]


@router.get("/orgs/{org_id}")
def show_org(ctx: InOrg) -> dict[str, str]:
    return {"org_id": str(ctx.org_id), "role": ctx.membership.role.value}


class NewInvitation(BaseModel):
    email: EmailStr
    role: Role
    external: bool = False


@router.post("/orgs/{org_id}/invitations", status_code=status.HTTP_201_CREATED)
def invite(body: NewInvitation, ctx: InOrg, db: DbSession) -> dict[str, str]:
    require_roles(ctx, Role.OWNER)
    token = tenancy.create_invitation(
        db,
        org_id=ctx.org_id,
        invited_by=ctx.user,
        email=body.email,
        role=body.role,
        external=body.external,
    )
    return {"token": token}


@router.post("/invitations/{token}/accept")
def accept(token: str, signed_in: SignedIn, db: DbSession) -> dict[str, str]:
    try:
        membership = tenancy.accept_invitation(db, token=token, user=signed_in.user)
    except tenancy.InvitationError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid_invitation") from None
    return {"org_id": str(membership.org_id), "role": membership.role.value}


@router.post("/orgs/{org_id}/members/{user_id}/reset-mfa")
def reset_member_mfa(user_id: uuid.UUID, ctx: InOrg, db: DbSession) -> dict[str, bool]:
    require_roles(ctx, Role.OWNER)
    target = db.get(User, user_id)
    if target is None or tenancy.membership_of(db, user_id=user_id, org_id=ctx.org_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not_found")
    service.reset_member_mfa(db, actor=ctx.actor, org_id=ctx.org_id, target=target)
    return {"ok": True}
