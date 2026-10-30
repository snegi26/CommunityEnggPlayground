"""Google Workspace connector and setup, replayed through httpx.MockTransport."""

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import select

from passport.connectors.base import Capability
from passport.connectors.google_workspace import (
    SCOPES,
    TOKEN_URL,
    USERS_URL,
    GoogleWorkspaceConnector,
)
from passport.connectors.models import Connection, ConnectionKind
from passport.connectors.observation import Failure, FailureKind, Observed
from passport.connectors.registry import registry
from passport.connectors.setup import (
    GoogleSetupError,
    PlatformSettings,
    begin_google_setup,
    complete_google_setup,
    connector_for,
)
from passport.connectors.vault import LocalKeyProvider, Vault, load_secret
from passport.controls.models import ScopeEntry
from passport.db.engine import get_sessionmaker
from passport.db.rls import set_org_context
from passport.provenance.actor import Human
from tests.helpers import create_org, sign_up

FIXTURES = Path(__file__).parents[1] / "fixtures" / "provider_responses" / "google"
DOMAIN = "example.com"
CLOCK = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PLATFORM = PlatformSettings(
    google_oauth_client_id="client-id.apps.googleusercontent.com",
    google_oauth_client_secret="client-secret-value",  # type: ignore[arg-type]
)
VAULT = Vault(LocalKeyProvider(os.urandom(32)))
REDIRECT = "https://passport.example/setup/google/callback"
SESSION_KEY = "browser-session-key"

Handler = Callable[[httpx.Request], httpx.Response]


def _fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def _refresh_ok(request: httpx.Request) -> httpx.Response | None:
    if str(request.url) == TOKEN_URL:
        form = parse_qs(request.content.decode())
        assert form["grant_type"] == ["refresh_token"]
        assert form["refresh_token"] == ["1//test-refresh-token"]
        return httpx.Response(200, json={"access_token": "ya29.access", "expires_in": 3599})
    return None


def _users(pages: dict[str | None, Any]) -> Handler:
    """Serve the directory: the page for each pageToken (None for the first)."""

    def handler(request: httpx.Request) -> httpx.Response:
        refreshed = _refresh_ok(request)
        if refreshed is not None:
            return refreshed
        assert str(request.url).startswith(USERS_URL)
        assert request.headers["Authorization"] == "Bearer ya29.access"
        assert request.url.params["domain"] == DOMAIN
        return httpx.Response(200, json=pages[request.url.params.get("pageToken")])

    return handler


def _connector(handler: Handler) -> GoogleWorkspaceConnector:
    return GoogleWorkspaceConnector(
        domain=DOMAIN,
        refresh_token="1//test-refresh-token",
        client_id="client-id",
        client_secret="client-secret-value",
        http=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=lambda: CLOCK,
    )


def test_every_page_of_users_is_read_and_the_observation_is_complete() -> None:
    connector = _connector(
        _users({None: _fixture("users_page1.json"), "CAIQ-page-2": _fixture("users_page2.json")})
    )
    result = connector.list_users_mfa()

    assert isinstance(result, Observed)
    assert result.capability is Capability.LIST_USERS_MFA
    assert result.rows == [
        {"user": "ana@example.com", "mfa": True},
        {"user": "ben@example.com", "mfa": False},
        {"user": "cy@example.com", "mfa": True},
    ]
    assert result.scope == (DOMAIN,)
    assert result.parameters["pages"] == 2
    assert result.pagination_complete and result.complete and result.checkable
    assert "admin_consent_suspected" not in result.parameters


def test_an_empty_user_list_is_an_empty_observation_flagged_for_admin_consent() -> None:
    result = _connector(_users({None: _fixture("users_empty.json")})).list_users_mfa()

    assert isinstance(result, Observed)
    assert result.rows == []
    assert result.is_empty and not result.checkable
    assert result.parameters["admin_consent_suspected"] is True
    assert "administrator" in result.parameters["note"]


def test_a_revoked_refresh_token_is_unauthorized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant"})

    result = _connector(handler).list_users_mfa()
    assert isinstance(result, Failure)
    assert result.kind is FailureKind.UNAUTHORIZED
    assert "client-secret-value" not in result.detail


def test_the_google_connector_is_registered_for_its_kind() -> None:
    assert registry.connector_class(ConnectionKind.GOOGLE_WORKSPACE) is GoogleWorkspaceConnector


def _token_exchange(body: dict[str, Any]) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode())
        if form.get("grant_type") == ["authorization_code"]:
            assert form["code"] == ["auth-code"]
            assert form["redirect_uri"] == [REDIRECT]
            return httpx.Response(200, json=body)
        return _users({None: _fixture("users_page2.json")})(request)

    return handler


@pytest.mark.usefixtures("database_urls")
def test_setup_asks_for_admin_consent_and_keeps_the_refresh_token_in_the_vault() -> None:
    owner = sign_up()
    org = create_org(owner)
    actor = Human(owner.user_id)
    http = httpx.Client(
        transport=httpx.MockTransport(_token_exchange(_fixture("token_exchange.json")))
    )
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        start = begin_google_setup(
            db,
            org,
            actor,
            session_key=SESSION_KEY,
            domain="Example.com ",
            redirect_uri=REDIRECT,
            platform=PLATFORM,
        )
        assert "administrator must" in start.admin_consent_notice
        query = parse_qs(urlparse(start.authorization_url).query)
        assert query["scope"] == [" ".join(SCOPES)]
        assert query["access_type"] == ["offline"]
        assert query["state"] == [start.token]

        conn = complete_google_setup(
            db,
            org,
            actor,
            session_key=SESSION_KEY,
            state=start.token,
            code="auth-code",
            vault=VAULT,
            platform=PLATFORM,
            http=http,
        )
        db.commit()

        set_org_context(db, org)
        assert conn.config == {"domain": DOMAIN}
        secret = load_secret(db, VAULT, conn)
        assert secret is not None
        assert json.loads(secret) == {"refresh_token": "1//test-refresh-token"}
        assert "1//test-refresh-token" not in json.dumps(conn.config)
        assert [e.identifier for e in db.scalars(select(ScopeEntry))] == [DOMAIN]

        connector = connector_for(db, conn, platform=PLATFORM, vault=VAULT, http=http)
        result = connector.list_users_mfa()
        assert isinstance(result, Observed)
        assert result.rows == [{"user": "cy@example.com", "mfa": True}]


@pytest.mark.usefixtures("database_urls")
@pytest.mark.parametrize(
    ("session_key", "token_body"),
    [
        ("another-browser", None),
        (SESSION_KEY, {"access_token": "a", "refresh_token": "r", "scope": "openid email"}),
        (SESSION_KEY, {"access_token": "a", "scope": SCOPES[0]}),
    ],
    ids=["other-session", "scope-not-granted", "no-refresh-token"],
)
def test_setup_is_refused_without_a_matching_state_scope_or_refresh_token(
    session_key: str, token_body: dict[str, Any] | None
) -> None:
    owner = sign_up()
    org = create_org(owner)
    actor = Human(owner.user_id)
    http = httpx.Client(
        transport=httpx.MockTransport(
            _token_exchange(token_body or _fixture("token_exchange.json"))
        )
    )
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        start = begin_google_setup(
            db,
            org,
            actor,
            session_key=SESSION_KEY,
            domain=DOMAIN,
            redirect_uri=REDIRECT,
            platform=PLATFORM,
        )
        with pytest.raises(GoogleSetupError):
            complete_google_setup(
                db,
                org,
                actor,
                session_key=session_key,
                state=start.token,
                code="auth-code",
                vault=VAULT,
                platform=PLATFORM,
                http=http,
            )
        assert db.scalars(select(Connection)).all() == []
