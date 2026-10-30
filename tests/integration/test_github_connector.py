"""GitHub App connector and installation binding, replayed through httpx.MockTransport."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from passport.connectors.base import Capability
from passport.connectors.github import GitHubAppCredentials, GitHubConnector
from passport.connectors.models import Connection, ConnectionKind
from passport.connectors.observation import Failure, FailureKind, Observed
from passport.connectors.registry import disconnect_connection, registry
from passport.connectors.setup import (
    GitHubSetupError,
    PlatformSettings,
    begin_github_setup,
    complete_github_setup,
)
from passport.controls.models import ScopeEntry
from passport.db.engine import get_sessionmaker
from passport.db.rls import set_org_context
from passport.provenance.actor import Human
from tests.helpers import create_org, sign_up

FIXTURES = Path(__file__).parents[1] / "fixtures" / "provider_responses" / "github"
API = "https://api.github.com"
ORG = "example-co"
INSTALLATION = 42424242
APP_ID = "123456"
CLOCK = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
SESSION_KEY = "browser-session-key"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = _KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode()
CREDENTIALS = GitHubAppCredentials(app_id=APP_ID, private_key=PRIVATE_PEM)
PLATFORM = PlatformSettings(
    github_app_id=APP_ID,
    github_app_private_key=PRIVATE_PEM,  # type: ignore[arg-type]
    github_app_slug="passport-checks",
    github_app_client_id="Iv1.clientid",
    github_app_client_secret="client-secret-value",  # type: ignore[arg-type]
)


def _fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def _next(url: str) -> dict[str, str]:
    return {"Link": f'<{url}>; rel="next", <{url}>; rel="last"'}


class FakeGitHub:
    """Routes recorded responses by method and path; records the paths requested."""

    def __init__(self, *, token_status: int = 201, org_body: Any = None) -> None:
        self.token_status = token_status
        self.org_body = org_body if org_body is not None else _fixture("org_2fa_off.json")
        self.requested: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, params = request.url.path, request.url.params
        self.requested.append(f"{request.method} {request.url}")
        auth = request.headers.get("Authorization", "")
        if request.url.host == "github.com" and path == "/login/oauth/access_token":
            code = dict(x.split("=") for x in request.content.decode().split("&"))["code"]
            return httpx.Response(200, json={"access_token": f"ghu_{code}", "token_type": "bearer"})
        if path == "/user/installations":
            if auth == "Bearer ghu_installer":
                return httpx.Response(200, json=_fixture("user_installations.json"))
            return httpx.Response(200, json={"total_count": 0, "installations": []})
        if path == f"/app/installations/{INSTALLATION}/access_tokens":
            claims = jwt.decode(
                auth.removeprefix("Bearer "),
                _KEY.public_key(),
                algorithms=["RS256"],
                options={"verify_exp": False, "verify_iat": False},
            )
            assert claims["iss"] == APP_ID
            if self.token_status != 201:
                return httpx.Response(self.token_status, json={"message": "Not Found"})
            return httpx.Response(201, json={"token": "ghs_installation", "expires_at": "x"})
        assert auth == "Bearer ghs_installation", path
        if path == f"/orgs/{ORG}":
            return httpx.Response(200, json=self.org_body)
        if path == f"/orgs/{ORG}/members":
            if params.get("filter") == "2fa_disabled":
                return httpx.Response(200, json=_fixture("members_2fa_disabled.json"))
            if params.get("page") == "2":
                return httpx.Response(200, json=_fixture("members_page2.json"))
            return httpx.Response(
                200,
                json=_fixture("members_page1.json"),
                headers=_next(f"{API}/orgs/{ORG}/members?per_page=100&page=2"),
            )
        if path == "/installation/repositories":
            if params.get("page") == "2":
                return httpx.Response(200, json=_fixture("installation_repositories_page2.json"))
            return httpx.Response(
                200,
                json=_fixture("installation_repositories_page1.json"),
                headers=_next(f"{API}/installation/repositories?per_page=100&page=2"),
            )
        if path == f"/repos/{ORG}/api/branches/main/protection":
            return httpx.Response(200, json=_fixture("branch_protection_api_main.json"))
        if path == f"/repos/{ORG}/web/branches/trunk/protection":
            return httpx.Response(404, json=_fixture("branch_not_protected.json"))
        raise AssertionError(f"unexpected request {request.method} {request.url}")


def _connector(fake: FakeGitHub) -> GitHubConnector:
    return GitHubConnector(
        org=ORG,
        installation_id=INSTALLATION,
        credentials=CREDENTIALS,
        http=httpx.Client(transport=httpx.MockTransport(fake)),
        clock=lambda: CLOCK,
    )


def test_an_org_without_the_two_factor_requirement_is_observed_with_it_off() -> None:
    result = _connector(FakeGitHub()).get_org_two_factor_requirement()
    assert isinstance(result, Observed)
    assert result.capability is Capability.GET_ORG_TWO_FACTOR_REQUIREMENT
    assert result.rows == [{"org": ORG, "required": False}]
    assert result.scope == (ORG,)
    assert result.checkable


def test_a_hidden_two_factor_setting_is_not_reported_as_off() -> None:
    body = {k: v for k, v in _fixture("org_2fa_off.json").items() if "two_factor" not in k}
    result = _connector(FakeGitHub(org_body=body)).get_org_two_factor_requirement()
    assert isinstance(result, Failure)
    assert result.kind is FailureKind.UNAUTHORIZED


def test_members_are_read_across_link_header_pages_with_their_2fa_status() -> None:
    fake = FakeGitHub()
    result = _connector(fake).list_org_members()
    assert isinstance(result, Observed)
    assert result.rows == [
        {"login": "octo-ana", "two_factor_enabled": True},
        {"login": "octo-ben", "two_factor_enabled": False},
        {"login": "octo-cy", "two_factor_enabled": True},
    ]
    assert result.parameters["pages"] == 2
    assert result.complete
    # One installation token serves every page.
    assert sum("access_tokens" in r for r in fake.requested) == 1


def test_default_branch_protection_is_read_for_every_repository_page() -> None:
    result = _connector(FakeGitHub()).get_branch_protection()
    assert isinstance(result, Observed)
    assert result.rows == [
        {"repo": "api", "branch": "main", "protected": True, "required_reviews": 2},
        {"repo": "web", "branch": "trunk", "protected": False, "required_reviews": 0},
    ]
    assert result.total_count == 2
    assert result.pagination_complete and result.complete
    assert result.parameters["pages"] == 2


@pytest.mark.parametrize("status", [401, 404])
def test_a_revoked_installation_is_unauthorized(status: int) -> None:
    connector = _connector(FakeGitHub(token_status=status))
    for read in (connector.get_org_two_factor_requirement, connector.list_org_members):
        result = read()
        assert isinstance(result, Failure)
        assert result.kind is FailureKind.UNAUTHORIZED
        assert str(INSTALLATION) in result.detail


def test_the_private_key_never_appears_in_reprs() -> None:
    assert "PRIVATE KEY" not in repr(CREDENTIALS)
    assert "PRIVATE KEY" not in repr(PLATFORM)
    assert "client-secret-value" not in repr(PLATFORM)


def test_the_github_connector_is_registered_for_its_kind() -> None:
    assert registry.connector_class(ConnectionKind.GITHUB) is GitHubConnector


# --- installation binding --------------------------------------------------------------


def _http() -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(FakeGitHub()))


def _setup(
    db: Any,
    org: Any,
    user: Any,
    *,
    code: str = "installer",
    installation: int | str = INSTALLATION,
    session_key: str = SESSION_KEY,
    state: str | None = None,
) -> Connection:
    actor = Human(user)
    if state is None:
        state = begin_github_setup(db, org, actor, session_key=SESSION_KEY, platform=PLATFORM).token
    return complete_github_setup(
        db,
        org,
        actor,
        session_key=session_key,
        state=state,
        installation_id=installation,
        code=code,
        platform=PLATFORM,
        http=_http(),
    )


@pytest.mark.usefixtures("database_urls")
def test_an_accessible_installation_is_bound_to_the_org() -> None:
    owner = sign_up()
    org = create_org(owner)
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        start = begin_github_setup(
            db, org, Human(owner.user_id), session_key=SESSION_KEY, platform=PLATFORM
        )
        assert start.install_url.startswith(
            "https://github.com/apps/passport-checks/installations/new?state="
        )
        conn = _setup(db, org, owner.user_id, state=start.token, installation=str(INSTALLATION))
        db.commit()

        set_org_context(db, org)
        assert conn.kind == ConnectionKind.GITHUB.value
        assert conn.config == {"installation_id": str(INSTALLATION), "org": ORG}
        assert [e.identifier for e in db.scalars(select(ScopeEntry))] == [ORG]


@pytest.mark.usefixtures("database_urls")
@pytest.mark.parametrize(
    ("code", "installation"),
    [("someone-else", INSTALLATION), ("installer", 99999999)],
    ids=["user-cannot-access-installation", "installation-not-in-users-list"],
)
def test_an_installation_the_user_cannot_access_is_rejected(code: str, installation: int) -> None:
    owner = sign_up()
    org = create_org(owner)
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        with pytest.raises(GitHubSetupError, match="cannot access"):
            _setup(db, org, owner.user_id, code=code, installation=installation)
        assert db.scalars(select(Connection)).all() == []


@pytest.mark.usefixtures("database_urls")
def test_a_state_from_another_session_or_org_is_rejected() -> None:
    owner_x, owner_y = sign_up(), sign_up()
    org_x, org_y = create_org(owner_x, "X"), create_org(owner_y, "Y")
    with get_sessionmaker()() as db:
        set_org_context(db, org_x)
        state = begin_github_setup(
            db, org_x, Human(owner_x.user_id), session_key=SESSION_KEY, platform=PLATFORM
        ).token
        db.commit()

        set_org_context(db, org_x)
        with pytest.raises(GitHubSetupError):
            _setup(db, org_x, owner_x.user_id, state=state, session_key="another-browser")
        db.rollback()

        set_org_context(db, org_y)
        with pytest.raises(GitHubSetupError):
            _setup(db, org_y, owner_y.user_id, state=state)
        assert db.scalars(select(Connection)).all() == []


@pytest.mark.usefixtures("database_urls")
def test_an_installation_bound_to_another_org_is_rejected_until_disconnected() -> None:
    owner_x, owner_y = sign_up(), sign_up()
    org_x, org_y = create_org(owner_x, "X"), create_org(owner_y, "Y")
    with get_sessionmaker()() as db:
        set_org_context(db, org_x)
        conn_x = _setup(db, org_x, owner_x.user_id)
        db.commit()

        # Org Y's installer can also access the installation, yet it belongs to X.
        set_org_context(db, org_y)
        with pytest.raises(GitHubSetupError, match="another Passport organization"):
            _setup(db, org_y, owner_y.user_id)
        assert db.scalars(select(Connection)).all() == []
        db.rollback()

        set_org_context(db, org_x)
        assert db.scalars(select(Connection)).all() == [conn_x]
        # Connecting it again in the same org is refused too.
        with pytest.raises(GitHubSetupError, match="already connected"):
            _setup(db, org_x, owner_x.user_id)
        db.rollback()

        set_org_context(db, org_x)
        disconnect_connection(
            db, actor=Human(owner_x.user_id), connection=db.get(Connection, conn_x.id)
        )  # type: ignore[arg-type]
        db.commit()

        set_org_context(db, org_y)
        conn_y = _setup(db, org_y, owner_y.user_id)
        db.commit()
        assert conn_y.org_id == org_y
