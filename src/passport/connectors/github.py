"""GitHub connector: one organization through our GitHub App installation (R5, KTD6, KTD7).

We store no customer secret: each read signs a short-lived app JWT (RS256) with the
platform's app private key, exchanges it for an installation token, and calls one
read endpoint. Paginated lists follow the ``Link: rel="next"`` header to the end.

Read-only App permissions this connector relies on (TO VERIFY against GitHub's REST
"Permissions required for GitHub Apps" reference before registering the app):

- Organization permissions: ``Administration: Read-only`` (``GET /orgs/{org}`` returns
  ``two_factor_requirement_enabled``; ``GET /orgs/{org}/members?filter=2fa_disabled``)
  and ``Members: Read-only`` (``GET /orgs/{org}/members``).
- Repository permissions: ``Administration: Read-only`` (``GET /repos/{owner}/{repo}/
  branches/{branch}/protection``) and ``Metadata: Read-only`` (mandatory; repository
  listing via ``GET /installation/repositories``).
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx
import jwt

from passport.connectors.base import Capability, Connector
from passport.connectors.models import ConnectionKind
from passport.connectors.observation import (
    CollectionResult,
    ConnectorReadError,
    FailureKind,
    Observed,
)
from passport.connectors.registry import registry
from passport.db.base import utcnow

COLLECTOR_VERSION = "github-1"
API_URL = "https://api.github.com"
OAUTH_TOKEN_URL = "https://github.com/login/oauth/access_token"  # noqa: S105 - an endpoint
API_VERSION = "2022-11-28"
PAGE_SIZE = 100
HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION}


@dataclass(frozen=True)
class GitHubAppCredentials:
    """The platform's app id and private key (PEM). The key never appears in a repr."""

    app_id: str
    private_key: str = field(repr=False)


def app_jwt(credentials: GitHubAppCredentials, now: datetime) -> str:
    """A GitHub App JWT: issued a minute early for clock drift, valid under 10 minutes."""
    payload = {
        "iat": int((now - timedelta(seconds=60)).timestamp()),
        "exp": int((now + timedelta(minutes=9)).timestamp()),
        "iss": credentials.app_id,
    }
    return jwt.encode(payload, credentials.private_key, algorithm="RS256")


class GitHubError(ConnectorReadError):
    """A GitHub call failed in a way the caller must handle (setup) or report (reads)."""


def _check(response: httpx.Response, what: str) -> None:
    """Map an error response to a typed failure; unexpected server errors propagate."""
    status = response.status_code
    if status < 400:
        return
    if status == 429 or (status == 403 and response.headers.get("x-ratelimit-remaining") == "0"):
        raise GitHubError(FailureKind.RATE_LIMITED, f"{what}: rate limited")
    if status in (401, 403, 404):
        raise GitHubError(FailureKind.UNAUTHORIZED, f"{what}: HTTP {status}")
    response.raise_for_status()


def get_all(
    http: httpx.Client, url: str, *, token: str, params: dict[str, Any] | None = None
) -> tuple[list[Any], list[Any]]:
    """GET every page of ``url``; returns (pages' bodies, the pages' items in order).

    A page body that is a list contributes its items; an object contributes the first
    list-valued field (``repositories``, ``installations``).
    """
    headers = {**HEADERS, "Authorization": f"Bearer {token}"}
    pages: list[Any] = []
    items: list[Any] = []
    next_url: str | None = url
    next_params: dict[str, Any] | None = {"per_page": PAGE_SIZE, **(params or {})}
    while next_url:
        response = http.get(next_url, params=next_params, headers=headers)
        _check(response, f"GET {url}")
        body = response.json()
        pages.append(body)
        if isinstance(body, list):
            items.extend(body)
        else:
            items.extend(next((v for v in body.values() if isinstance(v, list)), []))
        next_url = response.links.get("next", {}).get("url")
        next_params = None  # the next link already carries the query
    return pages, items


def exchange_oauth_code(
    http: httpx.Client, *, client_id: str, client_secret: str, code: str
) -> str:
    """Exchange a user-to-server OAuth code for the installing user's access token."""
    response = http.post(
        OAUTH_TOKEN_URL,
        data={"client_id": client_id, "client_secret": client_secret, "code": code},
        headers={"Accept": "application/json"},
    )
    _check(response, "POST /login/oauth/access_token")
    token = response.json().get("access_token")
    if not isinstance(token, str):
        raise GitHubError(FailureKind.UNAUTHORIZED, "GitHub did not accept the OAuth code")
    return token


def list_user_installations(http: httpx.Client, *, user_token: str) -> list[dict[str, Any]]:
    """Installations of our app that the user behind ``user_token`` can access."""
    _, items = get_all(http, f"{API_URL}/user/installations", token=user_token)
    return [i for i in items if isinstance(i, dict)]


@dataclass(frozen=True)
class _Read:
    rows: list[dict[str, Any]]
    raw: Any
    extra: dict[str, Any] = field(default_factory=dict)
    total: int | None = None


class GitHubConnector(Connector):
    """Reads one organization through its installation of our GitHub App."""

    kind = ConnectionKind.GITHUB
    collector_version = COLLECTOR_VERSION

    def __init__(
        self,
        *,
        org: str,
        installation_id: int,
        credentials: GitHubAppCredentials,
        http: httpx.Client,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.org = org
        self.installation_id = installation_id
        self.scope = (org,)
        self._credentials = credentials
        self._http = http
        self._clock = clock
        self._token: str | None = None

    def __repr__(self) -> str:
        return f"GitHubConnector(org={self.org!r}, installation_id={self.installation_id})"

    def _installation_token(self) -> str:
        if self._token is None:
            response = self._http.post(
                f"{API_URL}/app/installations/{self.installation_id}/access_tokens",
                headers={
                    **HEADERS,
                    "Authorization": f"Bearer {app_jwt(self._credentials, self._clock())}",
                },
            )
            if response.status_code in (401, 403, 404):
                raise GitHubError(
                    FailureKind.UNAUTHORIZED,
                    f"installation {self.installation_id} is revoked, suspended, or removed "
                    f"(HTTP {response.status_code})",
                )
            _check(response, "POST /app/installations/{id}/access_tokens")
            self._token = str(response.json()["token"])
        return self._token

    def _run(
        self, capability: Capability, endpoint: str, read: Callable[[str], _Read]
    ) -> CollectionResult:
        parameters: dict[str, Any] = {"org": self.org}
        try:
            result = read(self._installation_token())
        except GitHubError as exc:
            return self._failure(capability, endpoint, parameters, exc.kind, exc.detail)
        except httpx.TimeoutException as exc:
            return self._failure(
                capability, endpoint, parameters, FailureKind.TIMEOUT, f"{endpoint}: {exc}"
            )
        parameters.update(result.extra)
        return Observed(
            capability=capability,
            endpoint=endpoint,
            parameters=parameters,
            rows=result.rows,
            raw_response=result.raw,
            collector_version=self.collector_version,
            collected_at=self._clock(),
            scope=self.scope,
            total_count=result.total,
            pagination_complete=True,
        )

    def _org_path(self) -> str:
        return f"{API_URL}/orgs/{quote(self.org, safe='')}"

    def get_org_two_factor_requirement(self) -> CollectionResult:
        def read(token: str) -> _Read:
            response = self._http.get(
                self._org_path(), headers={**HEADERS, "Authorization": f"Bearer {token}"}
            )
            _check(response, "GET /orgs/{org}")
            body = response.json()
            required = body.get("two_factor_requirement_enabled")
            if not isinstance(required, bool):
                # GitHub omits the field without organization administration access;
                # treating that as "off" would report a contradiction we never saw.
                raise GitHubError(
                    FailureKind.UNAUTHORIZED,
                    "two_factor_requirement_enabled was not returned; the app needs "
                    "organization Administration read access",
                )
            return _Read(rows=[{"org": self.org, "required": required}], raw=body)

        return self._run(Capability.GET_ORG_TWO_FACTOR_REQUIREMENT, "GET /orgs/{org}", read)

    def list_org_members(self) -> CollectionResult:
        def read(token: str) -> _Read:
            members_url = f"{self._org_path()}/members"
            all_pages, members = get_all(self._http, members_url, token=token)
            off_pages, off = get_all(
                self._http, members_url, token=token, params={"filter": "2fa_disabled"}
            )
            disabled = {m["login"] for m in off}
            rows = [
                {"login": m["login"], "two_factor_enabled": m["login"] not in disabled}
                for m in members
            ]
            raw = {"members": all_pages, "members_2fa_disabled": off_pages}
            return _Read(
                rows=rows,
                raw=raw,
                extra={"pages": len(all_pages), "pages_2fa_disabled": len(off_pages)},
            )

        return self._run(
            Capability.LIST_ORG_MEMBERS, "GET /orgs/{org}/members (+filter=2fa_disabled)", read
        )

    def get_branch_protection(self) -> CollectionResult:
        def read(token: str) -> _Read:
            pages, repos = get_all(self._http, f"{API_URL}/installation/repositories", token=token)
            headers = {**HEADERS, "Authorization": f"Bearer {token}"}
            rows: list[dict[str, Any]] = []
            protections: dict[str, Any] = {}
            for repo in repos:
                owner = repo.get("owner", {}).get("login") or self.org
                name, branch = repo["name"], repo["default_branch"]
                url = (
                    f"{API_URL}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
                    f"/branches/{quote(branch, safe='')}/protection"
                )
                response = self._http.get(url, headers=headers)
                if response.status_code == 404:
                    # "Branch not protected".
                    protections[repo["full_name"]] = response.json()
                    rows.append(
                        {"repo": name, "branch": branch, "protected": False, "required_reviews": 0}
                    )
                    continue
                _check(response, "GET /repos/{owner}/{repo}/branches/{branch}/protection")
                body = response.json()
                protections[repo["full_name"]] = body
                reviews = body.get("required_pull_request_reviews") or {}
                rows.append(
                    {
                        "repo": name,
                        "branch": branch,
                        "protected": True,
                        "required_reviews": int(reviews.get("required_approving_review_count", 0)),
                    }
                )
            total = pages[-1].get("total_count") if pages and isinstance(pages[-1], dict) else None
            raw = {"repositories": pages, "protection": protections}
            return _Read(
                rows=rows,
                raw=raw,
                extra={"pages": len(pages), "branch": "default branch of each repository"},
                total=total if isinstance(total, int) else None,
            )

        return self._run(
            Capability.GET_BRANCH_PROTECTION,
            "GET /installation/repositories + /repos/{owner}/{repo}/branches/{branch}/protection",
            read,
        )


registry.register(GitHubConnector)
