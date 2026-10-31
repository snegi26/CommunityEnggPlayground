"""Server-rendered pages: sign-in, setup wizard, passport, claim review, reports."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from passport.web.routes import auth_pages, passport, setup
from passport.web.routes.common import LoginRedirect

STATIC_DIR = Path(__file__).resolve().parent / "static"


async def _login_redirect(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, LoginRedirect)
    if request.headers.get("hx-request"):
        return Response(status_code=200, headers={"HX-Redirect": exc.location})
    return RedirectResponse(exc.location, status_code=303)


def install(app: FastAPI) -> None:
    """Mount the HTML routers, static files, and the sign-in redirect handler."""
    app.add_exception_handler(LoginRedirect, _login_redirect)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(auth_pages.router)
    app.include_router(setup.router)
    app.include_router(passport.router)
