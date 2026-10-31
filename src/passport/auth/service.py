"""Login, sessions, TOTP MFA, recovery codes, password reset, and throttling (KTD15)."""

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from passport.auth.models import (
    AuthSession,
    LoginAttempt,
    PasswordResetToken,
    RecoveryCode,
    User,
)
from passport.db.base import utcnow
from passport.db.rls import set_user_context
from passport.provenance.actor import Actor, require_human
from passport.provenance.service import append_event

SESSION_TTL = timedelta(hours=12)
RESET_TTL = timedelta(hours=1)
THROTTLE_WINDOW = timedelta(minutes=15)
MAX_FAILURES_PER_ACCOUNT = 5
MAX_FAILURES_PER_IP = 20
RECOVERY_CODE_COUNT = 10

_hasher = PasswordHasher()


class AuthError(Exception):
    """Credentials or second factor rejected. Deliberately carries no detail."""


class ThrottledError(AuthError):
    """Too many recent failures for this account or address."""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def register_user(session: Session, *, email: str, name: str, password: str) -> User:
    user = User(email=email.strip().lower(), name=name, password_hash=hash_password(password))
    session.add(user)
    session.flush()
    set_user_context(session, user.id)
    return user


@dataclass(frozen=True)
class LoginResult:
    session_token: str
    user_id: uuid.UUID
    mfa_required: bool


def _recent_failures(session: Session, key: str) -> int:
    since = utcnow() - THROTTLE_WINDOW
    count = session.scalar(
        select(func.count())
        .select_from(LoginAttempt)
        .where(LoginAttempt.key == key, LoginAttempt.created_at >= since)
    )
    return count or 0


def _check_throttle(session: Session, account_key: str, ip_key: str) -> None:
    if (
        _recent_failures(session, account_key) >= MAX_FAILURES_PER_ACCOUNT
        or _recent_failures(session, ip_key) >= MAX_FAILURES_PER_IP
    ):
        raise ThrottledError


def _record_failure(session: Session, *keys: str) -> None:
    for key in keys:
        session.add(LoginAttempt(key=key))
    session.flush()


def authenticate(session: Session, *, email: str, password: str, ip: str) -> LoginResult:
    """Check a password and open a session; MFA users must still verify a second factor."""
    account_key = f"account:{email.strip().lower()}"
    ip_key = f"ip:{ip}"
    _check_throttle(session, account_key, ip_key)

    row = session.execute(
        text("SELECT id, password_hash, totp_enabled FROM passport_login_lookup(:email)"),
        {"email": email},
    ).one_or_none()
    try:
        if row is None:
            raise VerificationError
        _hasher.verify(row.password_hash, password)
    except VerificationError:
        _record_failure(session, account_key, ip_key)
        raise AuthError from None

    token = new_token()
    session.add(
        AuthSession(
            token_hash=hash_token(token),
            user_id=row.id,
            mfa_verified=False,
            expires_at=utcnow() + SESSION_TTL,
        )
    )
    session.flush()
    return LoginResult(session_token=token, user_id=row.id, mfa_required=row.totp_enabled)


@dataclass(frozen=True)
class CurrentSession:
    user: User
    mfa_verified: bool


def resolve_session(session: Session, token: str) -> CurrentSession | None:
    auth = session.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token)))
    if auth is None or auth.expires_at <= utcnow():
        return None
    set_user_context(session, auth.user_id)
    user = session.get(User, auth.user_id)
    if user is None:
        return None
    return CurrentSession(user=user, mfa_verified=auth.mfa_verified)


def logout(session: Session, token: str) -> None:
    auth = session.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token)))
    if auth is not None:
        session.delete(auth)
        session.flush()


def _check_second_factor(session: Session, user: User, code: str) -> bool:
    """Accept a current TOTP code or an unused recovery code (consuming it)."""
    if user.totp_secret and pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        return True
    recovery = session.scalar(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.code_hash == hash_token(code),
            RecoveryCode.used_at.is_(None),
        )
    )
    if recovery is None:
        return False
    recovery.used_at = utcnow()
    session.flush()
    return True


def verify_mfa(session: Session, *, session_token: str, code: str, ip: str) -> None:
    auth = session.scalar(
        select(AuthSession).where(AuthSession.token_hash == hash_token(session_token))
    )
    if auth is None or auth.expires_at <= utcnow():
        raise AuthError
    set_user_context(session, auth.user_id)
    user = session.get(User, auth.user_id)
    if user is None:
        raise AuthError
    account_key, ip_key = f"account:{user.email}", f"ip:{ip}"
    _check_throttle(session, account_key, ip_key)
    if not _check_second_factor(session, user, code):
        _record_failure(session, account_key, ip_key)
        raise AuthError
    auth.mfa_verified = True
    session.flush()


def begin_totp_enrollment(session: Session, user: User) -> str:
    """Store a fresh, not-yet-enabled secret and return its provisioning URI."""
    user.totp_secret = pyotp.random_base32()
    user.totp_enabled = False
    session.flush()
    return pyotp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email, issuer_name="Freshness Passport"
    )


def confirm_totp_enrollment(
    session: Session, *, user: User, code: str, session_token: str
) -> list[str]:
    """Enable TOTP once the user proves the authenticator works; return recovery codes."""
    if not user.totp_secret or not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        raise AuthError
    user.totp_enabled = True
    for old in session.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user.id)):
        session.delete(old)
    codes = [secrets.token_hex(5) for _ in range(RECOVERY_CODE_COUNT)]
    session.add_all(RecoveryCode(user_id=user.id, code_hash=hash_token(c)) for c in codes)
    auth = session.scalar(
        select(AuthSession).where(AuthSession.token_hash == hash_token(session_token))
    )
    if auth is not None:
        auth.mfa_verified = True
    session.flush()
    return codes


def reset_member_mfa(session: Session, *, actor: Actor, org_id: uuid.UUID, target: User) -> None:
    """Owner-initiated MFA reset for a member who lost their authenticator (human-only)."""
    require_human(actor)
    target.totp_secret = None
    target.totp_enabled = False
    for code in session.scalars(select(RecoveryCode).where(RecoveryCode.user_id == target.id)):
        session.delete(code)
    session.execute(delete(AuthSession).where(AuthSession.user_id == target.id))
    append_event(
        session,
        org_id=org_id,
        actor=actor,
        event_type="member.mfa_reset",
        subject_kind="user",
        subject_id=target.id,
    )


def request_password_reset(session: Session, *, email: str) -> str | None:
    """Create a single-use reset token; None when no such account (caller stays silent)."""
    row = session.execute(
        text("SELECT id FROM passport_login_lookup(:email)"), {"email": email}
    ).one_or_none()
    if row is None:
        return None
    token = new_token()
    session.add(
        PasswordResetToken(
            user_id=row.id, token_hash=hash_token(token), expires_at=utcnow() + RESET_TTL
        )
    )
    session.flush()
    return token


def complete_password_reset(
    session: Session, *, token: str, new_password: str, second_factor: str | None
) -> None:
    """Set a new password. Users with MFA must also present TOTP or a recovery code."""
    reset = session.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(token))
    )
    if reset is None or reset.used_at is not None or reset.expires_at <= utcnow():
        raise AuthError
    set_user_context(session, reset.user_id)
    user = session.get(User, reset.user_id)
    if user is None:
        raise AuthError
    if user.totp_enabled and (
        second_factor is None or not _check_second_factor(session, user, second_factor)
    ):
        raise AuthError
    user.password_hash = hash_password(new_password)
    reset.used_at = utcnow()
    session.execute(delete(AuthSession).where(AuthSession.user_id == user.id))
    session.flush()
