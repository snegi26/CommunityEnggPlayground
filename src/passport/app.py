"""FastAPI application factory."""

from typing import Annotated

from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from passport.db.engine import get_session


def create_app() -> FastAPI:
    app = FastAPI(title="Compliance Freshness Passport")

    @app.get("/healthz")
    def healthz(session: Annotated[Session, Depends(get_session)]) -> dict[str, str]:
        session.execute(text("SELECT 1"))
        return {"status": "ok", "database": "ok"}

    return app
