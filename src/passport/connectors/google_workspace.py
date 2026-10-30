"""Google Workspace connector: users' 2-Step Verification from the Admin SDK (R5, KTD7).

Access is an OAuth refresh token for the Directory read-only user scope, granted by
a Workspace administrator and stored envelope-encrypted in the vault (KTD6). Each
read exchanges it for a short-lived access token and lists every user of the
domain, following ``nextPageToken`` to the last page.

A consenting user who is not an administrator can get an empty user list rather
than an error. An empty list is therefore recorded as an empty observation (never
compliant, KTD7) whose parameters flag that admin consent is probably missing.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx

from passport.connectors.base import Capability, Connector
from passport.connectors.models import ConnectionKind
from passport.connectors.observation import CollectionResult, Failure, FailureKind, Observed
from passport.connectors.registry import registry
from passport.db.base import utcnow

COLLECTOR_VERSION = "google-workspace-1"
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - an endpoint, not a secret
USERS_URL = "https://admin.googleapis.com/admin/directory/v1/users"
# Admin SDK Directory, users, read-only: the only scope requested.
SCOPES = ("https://www.googleapis.com/auth/admin.directory.user.readonly",)
PAGE_SIZE = 500

ADMIN_CONSENT_NOTICE = (
    "A Google Workspace administrator must complete this step. Google only returns the "
    "user directory to an administrator, so if someone without admin rights consents, "
    "Passport receives an empty user list and every identity check stays not checkable."
)
EMPTY_LIST_NOTE = (
    "Google returned no users for this domain. This usually means the person who "
    "consented is not a Workspace administrator; reconnect as an administrator."
)


class _ReadFailedError(Exception):
    def __init__(self, kind: FailureKind, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


def failure_kind_for_status(status_code: int) -> FailureKind | None:
    if status_code in (400, 401, 403):
        return FailureKind.UNAUTHORIZED
    if status_code == 429:
        return FailureKind.RATE_LIMITED
    return None


class GoogleWorkspaceConnector(Connector):
    """Reads one Workspace domain's users with the stored refresh token."""

    kind = ConnectionKind.GOOGLE_WORKSPACE
    collector_version = COLLECTOR_VERSION

    def __init__(
        self,
        *,
        domain: str,
        refresh_token: str,
        client_id: str,
        client_secret: str,
        http: httpx.Client,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.domain = domain
        self.scope = (domain,)
        self._refresh_token = refresh_token
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = http
        self._clock = clock

    def __repr__(self) -> str:
        return f"GoogleWorkspaceConnector(domain={self.domain!r})"

    def _access_token(self) -> str:
        response = self._http.post(
            TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
        )
        if response.status_code != 200:
            kind = failure_kind_for_status(response.status_code) or FailureKind.UNAUTHORIZED
            error = _json(response).get("error", f"HTTP {response.status_code}")
            raise _ReadFailedError(kind, f"token refresh refused: {error}")
        token = _json(response).get("access_token")
        if not isinstance(token, str):
            raise _ReadFailedError(FailureKind.UNAUTHORIZED, "token refresh returned no token")
        return token

    def list_users_mfa(self) -> CollectionResult:
        capability = Capability.LIST_USERS_MFA
        endpoint = f"GET {USERS_URL}"
        parameters: dict[str, Any] = {"domain": self.domain, "maxResults": PAGE_SIZE}
        try:
            token = self._access_token()
            pages: list[Any] = []
            rows: list[dict[str, Any]] = []
            page_token: str | None = None
            while True:
                query: dict[str, Any] = {"domain": self.domain, "maxResults": PAGE_SIZE}
                if page_token:
                    query["pageToken"] = page_token
                response = self._http.get(
                    USERS_URL, params=query, headers={"Authorization": f"Bearer {token}"}
                )
                if response.status_code != 200:
                    kind = failure_kind_for_status(response.status_code)
                    if kind is None:
                        response.raise_for_status()
                        raise _ReadFailedError(FailureKind.UNAUTHORIZED, "unexpected response")
                    raise _ReadFailedError(
                        kind, f"{endpoint}: HTTP {response.status_code} on page {len(pages) + 1}"
                    )
                body = _json(response)
                pages.append(body)
                rows.extend(
                    {"user": u["primaryEmail"], "mfa": u.get("isEnrolledIn2Sv") is True}
                    for u in body.get("users", [])
                )
                page_token = body.get("nextPageToken")
                if not page_token:
                    break
        except _ReadFailedError as exc:
            return self._failure(capability, endpoint, parameters, exc.kind, exc.detail)
        except httpx.TimeoutException as exc:
            return self._failure(
                capability, endpoint, parameters, FailureKind.TIMEOUT, f"{endpoint}: {exc}"
            )
        parameters["pages"] = len(pages)
        if not rows:
            parameters["admin_consent_suspected"] = True
            parameters["note"] = EMPTY_LIST_NOTE
        return Observed(
            capability=capability,
            endpoint=endpoint,
            parameters=parameters,
            rows=rows,
            raw_response={"pages": pages},
            collector_version=self.collector_version,
            collected_at=self._clock(),
            scope=self.scope,
            pagination_complete=True,
        )

    def _failure(
        self,
        capability: Capability,
        endpoint: str,
        parameters: dict[str, Any],
        kind: FailureKind,
        detail: str,
    ) -> Failure:
        return Failure(
            capability=capability,
            kind=kind,
            detail=detail,
            endpoint=endpoint,
            parameters=parameters,
            collector_version=self.collector_version,
            collected_at=self._clock(),
            scope=self.scope,
        )


def _json(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


registry.register(GoogleWorkspaceConnector)
