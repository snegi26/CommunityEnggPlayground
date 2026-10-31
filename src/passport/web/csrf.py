"""CSRF protection for every state-changing HTML form (U14).

The token is bound to the browser's session: it is a hash of the session cookie, which
is HttpOnly, so another site can neither read nor compute it. Before login (the login
form) there is no session yet, so the token is bound the same way to a random
pre-session cookie instead. A POST whose ``csrf_token`` field (or ``X-CSRF-Token``
header, for HTMX requests) does not match is refused with 403 before the route runs.
"""

import hashlib
import hmac
import secrets

from fastapi import HTTPException, Request, Response, status

from passport.auth.deps import SESSION_COOKIE

PRE_SESSION_COOKIE = "passport_csrf"
FIELD = "csrf_token"
HEADER = "x-csrf-token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _derive(secret: str) -> str:
    return hashlib.sha256(f"passport-csrf:{secret}".encode()).hexdigest()


def _binding(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE) or request.cookies.get(PRE_SESSION_COOKIE)


def token_for(request: Request) -> str:
    """The token to embed in this page's forms; creates a pre-session binding if needed."""
    binding = _binding(request)
    if binding is None:
        binding = getattr(request.state, "csrf_pre_session", None)
        if binding is None:
            binding = secrets.token_urlsafe(32)
            request.state.csrf_pre_session = binding
    return _derive(binding)


def set_pre_session_cookie(request: Request, response: Response) -> None:
    """Persist a pre-session binding created while rendering this response."""
    binding = getattr(request.state, "csrf_pre_session", None)
    if binding is not None:
        response.set_cookie(PRE_SESSION_COOKIE, binding, httponly=True, secure=True, samesite="lax")


async def require_csrf(request: Request) -> None:
    """Router dependency: refuse an unsafe request without the matching token."""
    if request.method in SAFE_METHODS:
        return
    sent = request.headers.get(HEADER)
    if sent is None:
        form = await request.form()
        value = form.get(FIELD)
        sent = value if isinstance(value, str) else None
    binding = _binding(request)
    if not sent or binding is None or not hmac.compare_digest(sent, _derive(binding)):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "csrf_token_invalid")
