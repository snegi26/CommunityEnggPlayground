"""Setup flows for the AWS, Google Workspace, and GitHub connections (U7, F1).

Every flow is two steps. ``begin_*`` stores a pending setup server-side, bound to
the org (row-level security), the user, and the browser session, and returns a
single-use token: the OAuth ``state`` for Google and GitHub, the verification
handle for AWS. ``complete_*`` consumes that token, checks the provider, and only
then creates the connection. Platform credentials come from the environment
(KTD6) and are never logged or written to events.
"""

import hashlib
import hmac
import json
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import DateTime, ForeignKey, String, Uuid, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from passport.connectors.aws import (
    SECURITY_AUDIT_POLICY_ARN,
    AwsConnector,
    AwsTrustPolicyError,
    ClientFactory,
    account_id_from_role_arn,
    assumed_role_clients,
    generate_external_id,
    verify_role_trust,
)
from passport.connectors.base import Connector
from passport.connectors.github import (
    GitHubAppCredentials,
    GitHubConnector,
    GitHubError,
    exchange_oauth_code,
    list_user_installations,
)
from passport.connectors.google_workspace import (
    ADMIN_CONSENT_NOTICE,
    AUTHORIZATION_URL,
    SCOPES,
    TOKEN_URL,
    GoogleWorkspaceConnector,
)
from passport.connectors.models import Connection, ConnectionKind, ConnectionStatus
from passport.connectors.observation import Observed
from passport.connectors.registry import create_connection
from passport.connectors.vault import Vault, load_secret
from passport.controls.models import ScopeEntry, ScopeKind
from passport.controls.settings import add_scope_entry, list_scope_entries
from passport.db.base import Base, CreatedAtMixin, IdMixin, utcnow
from passport.db.models import OrgScoped
from passport.provenance.actor import Actor, require_human
from passport.provenance.service import append_event

SETUP_TTL = timedelta(minutes=30)
AWS_TEMPLATE_PATH = Path(__file__).resolve().parents[3] / "deploy" / "aws-readonly-role.yaml"
DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class PlatformSettings(BaseSettings):
    """Platform-wide credentials (KTD6). Secrets are ``SecretStr`` so reprs never show them."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    github_app_id: str | None = None
    github_app_private_key: SecretStr | None = None
    # The app's public slug (install URL) and its OAuth client, for user-to-server checks.
    github_app_slug: str | None = None
    github_app_client_id: str | None = None
    github_app_client_secret: SecretStr | None = None
    google_oauth_client_id: str | None = None
    google_oauth_client_secret: SecretStr | None = None
    # The principal customer roles trust; it assumes them from our instance role.
    aws_platform_principal_arn: str | None = None

    def github_credentials(self) -> GitHubAppCredentials:
        if not self.github_app_id or self.github_app_private_key is None:
            raise SetupError("GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY must be set")
        return GitHubAppCredentials(
            app_id=self.github_app_id, private_key=self.github_app_private_key.get_secret_value()
        )


class SetupError(Exception):
    """A setup step was refused; the message is safe to show the user."""


class AwsSetupError(SetupError):
    pass


class GoogleSetupError(SetupError):
    pass


class GitHubSetupError(SetupError):
    pass


class ConnectionSetup(IdMixin, CreatedAtMixin, OrgScoped, Base):
    """A setup in progress. Only the token's hash is stored."""

    __tablename__ = "connection_setups"

    kind: Mapped[str] = mapped_column(String(30))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"))
    session_key_hash: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def org_id_from_state(state: str) -> uuid.UUID:
    """The org a setup token belongs to; the callback route sets this org's context.

    The token carries its org id so a provider callback, which arrives at one fixed
    URL, can be routed to the right org; the route must still verify membership, and
    :func:`_consume` re-checks the token under that org's row-level security.
    """
    prefix, _, _ = state.partition(".")
    try:
        return uuid.UUID(prefix)
    except ValueError:
        raise SetupError("this setup link is invalid or has expired; start again") from None


def _start(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    kind: ConnectionKind,
    *,
    session_key: str,
    payload: dict[str, Any],
) -> str:
    human = require_human(actor)
    token = f"{org_id}.{secrets.token_urlsafe(32)}"
    setup = ConnectionSetup(
        org_id=org_id,
        kind=kind.value,
        token_hash=_sha256(token),
        user_id=human.user_id,
        session_key_hash=_sha256(session_key),
        payload=payload,
        expires_at=utcnow() + SETUP_TTL,
    )
    session.add(setup)
    session.flush()
    append_event(
        session,
        org_id=org_id,
        actor=human,
        event_type="connection_setup.started",
        subject_kind="connection_setup",
        subject_id=setup.id,
        payload={"kind": kind.value},
    )
    return token


def _consume(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    kind: ConnectionKind,
    *,
    token: str,
    session_key: str,
    error: type[SetupError],
) -> dict[str, Any]:
    """Verify and delete a pending setup; any mismatch is refused the same way."""
    human = require_human(actor)
    refused = error("this setup link is invalid or has expired; start again")
    if not token or org_id_from_state(token) != org_id:
        raise refused
    # Row-level security limits this lookup to the active org.
    setup = session.scalars(
        select(ConnectionSetup).where(ConnectionSetup.token_hash == _sha256(token))
    ).one_or_none()
    if setup is None:
        raise refused
    payload = dict(setup.payload)
    matches = (
        setup.org_id == org_id
        and setup.kind == kind.value
        and setup.user_id == human.user_id
        and hmac.compare_digest(setup.session_key_hash, _sha256(session_key))
        and setup.expires_at > utcnow()
    )
    # Single use, whether or not it matched.
    session.delete(setup)
    session.flush()
    if not matches:
        raise refused
    return payload


def _ensure_scope_entry(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    kind: ScopeKind,
    identifier: str,
    label: str = "",
) -> ScopeEntry | None:
    """Add a non-production scope entry unless the org already declared it."""
    existing = {e.identifier for e in list_scope_entries(session, kind)}
    if identifier in existing:
        return None
    return add_scope_entry(session, org_id, actor, kind, identifier, label=label, production=False)


# --- AWS -------------------------------------------------------------------------------


@dataclass(frozen=True)
class AwsSetupStart:
    token: str
    external_id: str
    principal_arn: str
    template_body: str
    template_parameters: dict[str, str]
    instructions: str


def begin_aws_setup(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    *,
    session_key: str,
    platform: PlatformSettings,
) -> AwsSetupStart:
    """Generate this connection's external id and the role template to deploy with it."""
    principal = platform.aws_platform_principal_arn
    if not principal:
        raise AwsSetupError("AWS_PLATFORM_PRINCIPAL_ARN is not configured")
    external_id = generate_external_id()
    token = _start(
        session,
        org_id,
        actor,
        ConnectionKind.AWS,
        session_key=session_key,
        payload={"external_id": external_id},
    )
    parameters = {"PlatformPrincipalArn": principal, "ExternalId": external_id}
    instructions = (
        "Deploy the CloudFormation template in the AWS account to connect, with "
        f"PlatformPrincipalArn={principal} and ExternalId={external_id}. It creates a role "
        f"with the AWS-managed SecurityAudit policy ({SECURITY_AUDIT_POLICY_ARN}) that only "
        "our principal can assume, and only with this external id. Then paste the role ARN "
        "from the stack outputs to verify."
    )
    return AwsSetupStart(
        token=token,
        external_id=external_id,
        principal_arn=principal,
        template_body=AWS_TEMPLATE_PATH.read_text(),
        template_parameters=parameters,
        instructions=instructions,
    )


def complete_aws_setup(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    *,
    session_key: str,
    token: str,
    role_arn: str,
    sts: Any,
    clients: ClientFactory | None = None,
) -> Connection:
    """Verify the role's trust policy, connect, and pre-fill the account inventory."""
    payload = _consume(
        session,
        org_id,
        actor,
        ConnectionKind.AWS,
        token=token,
        session_key=session_key,
        error=AwsSetupError,
    )
    external_id = str(payload["external_id"])
    role_arn = role_arn.strip()
    try:
        account_id = account_id_from_role_arn(role_arn)
    except ValueError as exc:
        raise AwsSetupError(str(exc)) from exc
    try:
        verify_role_trust(sts, role_arn=role_arn, external_id=external_id)
    except AwsTrustPolicyError as exc:
        raise AwsSetupError(str(exc)) from exc
    connection = create_connection(
        session,
        org_id=org_id,
        actor=actor,
        kind=ConnectionKind.AWS,
        display_name=f"AWS account {account_id}",
        config={"role_arn": role_arn, "external_id": external_id, "account_id": account_id},
    )
    factory = clients or assumed_role_clients(sts=sts, role_arn=role_arn, external_id=external_id)
    prefill_aws_scope(session, org_id, actor, AwsConnector(account_id=account_id, clients=factory))
    return connection


def prefill_aws_scope(
    session: Session, org_id: uuid.UUID, actor: Actor, connector: AwsConnector
) -> list[ScopeEntry]:
    """Add the organization's accounts (or just this one) as non-production entries.

    When the role can call Organizations ``ListAccounts`` every active account is
    added for the user to mark as production (U4); otherwise only the connected
    account. Entries the org already declared are left untouched.
    """
    accounts: list[tuple[str, str]] = []
    result = connector.list_accounts()
    if isinstance(result, Observed):
        accounts = [
            (str(r["account"]), str(r.get("name", "")))
            for r in result.rows
            if r.get("status", "ACTIVE") == "ACTIVE"
        ]
    if connector.account_id not in {a for a, _ in accounts}:
        accounts.insert(0, (connector.account_id, ""))
    added: list[ScopeEntry] = []
    for account, label in accounts:
        entry = _ensure_scope_entry(
            session, org_id, actor, ScopeKind.AWS_ACCOUNT, account, label=label
        )
        if entry is not None:
            added.append(entry)
    return added


# --- Google Workspace ------------------------------------------------------------------


@dataclass(frozen=True)
class GoogleSetupStart:
    token: str
    authorization_url: str
    # Shown on the setup page: only an administrator's consent yields the directory.
    admin_consent_notice: str


def _normalize_domain(domain: str) -> str:
    value = domain.strip().lower()
    if not DOMAIN_PATTERN.match(value):
        raise GoogleSetupError("enter the Workspace domain, for example example.com")
    return value


def begin_google_setup(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    *,
    session_key: str,
    domain: str,
    redirect_uri: str,
    platform: PlatformSettings,
) -> GoogleSetupStart:
    if not platform.google_oauth_client_id or platform.google_oauth_client_secret is None:
        raise GoogleSetupError("GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET must be set")
    domain = _normalize_domain(domain)
    token = _start(
        session,
        org_id,
        actor,
        ConnectionKind.GOOGLE_WORKSPACE,
        session_key=session_key,
        payload={"domain": domain, "redirect_uri": redirect_uri},
    )
    query = {
        "client_id": platform.google_oauth_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        # Offline access with a fresh consent screen, so Google issues a refresh token.
        "access_type": "offline",
        "prompt": "consent",
        "hd": domain,
        "state": token,
    }
    return GoogleSetupStart(
        token=token,
        authorization_url=f"{AUTHORIZATION_URL}?{urlencode(query)}",
        admin_consent_notice=ADMIN_CONSENT_NOTICE,
    )


def complete_google_setup(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    *,
    session_key: str,
    state: str,
    code: str,
    vault: Vault,
    platform: PlatformSettings,
    http: httpx.Client,
) -> Connection:
    """Exchange the code, keep the refresh token in the vault, and connect the domain."""
    payload = _consume(
        session,
        org_id,
        actor,
        ConnectionKind.GOOGLE_WORKSPACE,
        token=state,
        session_key=session_key,
        error=GoogleSetupError,
    )
    if not platform.google_oauth_client_id or platform.google_oauth_client_secret is None:
        raise GoogleSetupError("GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET must be set")
    response = http.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": platform.google_oauth_client_id,
            "client_secret": platform.google_oauth_client_secret.get_secret_value(),
            "redirect_uri": payload["redirect_uri"],
        },
    )
    if response.status_code != 200:
        raise GoogleSetupError("Google did not accept the authorization; start again")
    body = response.json()
    refresh_token = body.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise GoogleSetupError(
            "Google returned no refresh token; remove Passport's access in the Google "
            "account settings and connect again"
        )
    granted = set(str(body.get("scope", "")).split())
    if not set(SCOPES) <= granted:
        raise GoogleSetupError(
            "the directory read-only permission was not granted; an administrator must "
            "consent to every requested permission"
        )
    domain = str(payload["domain"])
    connection = create_connection(
        session,
        org_id=org_id,
        actor=actor,
        kind=ConnectionKind.GOOGLE_WORKSPACE,
        display_name=domain,
        config={"domain": domain},
        secret=json.dumps({"refresh_token": refresh_token}).encode(),
        vault=vault,
    )
    _ensure_scope_entry(session, org_id, actor, ScopeKind.WORKSPACE_DOMAIN, domain)
    return connection


# --- GitHub ----------------------------------------------------------------------------


@dataclass(frozen=True)
class GitHubSetupStart:
    token: str
    install_url: str


def begin_github_setup(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    *,
    session_key: str,
    platform: PlatformSettings,
) -> GitHubSetupStart:
    if not platform.github_app_slug:
        raise GitHubSetupError("GITHUB_APP_SLUG is not configured")
    token = _start(
        session, org_id, actor, ConnectionKind.GITHUB, session_key=session_key, payload={}
    )
    url = f"https://github.com/apps/{platform.github_app_slug}/installations/new"
    return GitHubSetupStart(token=token, install_url=f"{url}?{urlencode({'state': token})}")


def complete_github_setup(
    session: Session,
    org_id: uuid.UUID,
    actor: Actor,
    *,
    session_key: str,
    state: str,
    installation_id: int | str,
    code: str,
    platform: PlatformSettings,
    http: httpx.Client,
) -> Connection:
    """Bind an installation to this org, only if the installing user can access it.

    The installation id in the callback is attacker-controllable, so it is accepted
    only with (1) our state token bound to this org, user, and browser session, and
    (2) the user's own OAuth token listing that installation. An installation already
    actively bound to another org is refused by a unique index (migration 0009).
    """
    _consume(
        session,
        org_id,
        actor,
        ConnectionKind.GITHUB,
        token=state,
        session_key=session_key,
        error=GitHubSetupError,
    )
    try:
        installation = int(installation_id)
    except (TypeError, ValueError):
        raise GitHubSetupError("the installation id is not valid") from None
    if not platform.github_app_client_id or platform.github_app_client_secret is None:
        raise GitHubSetupError("GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET must be set")
    try:
        user_token = exchange_oauth_code(
            http,
            client_id=platform.github_app_client_id,
            client_secret=platform.github_app_client_secret.get_secret_value(),
            code=code,
        )
        accessible = list_user_installations(http, user_token=user_token)
    except GitHubError as exc:
        raise GitHubSetupError("GitHub did not confirm your access; start again") from exc
    match = next((i for i in accessible if i.get("id") == installation), None)
    if match is None:
        raise GitHubSetupError("your GitHub account cannot access that installation")
    account = match.get("account") or {}
    login = account.get("login")
    if not isinstance(login, str) or account.get("type") != "Organization":
        raise GitHubSetupError("install the app on a GitHub organization, not a user account")

    already_here = session.scalars(
        select(Connection).where(
            Connection.kind == ConnectionKind.GITHUB.value,
            Connection.status == ConnectionStatus.ACTIVE.value,
            Connection.config["installation_id"].astext == str(installation),
        )
    ).first()
    if already_here is not None:
        raise GitHubSetupError("this GitHub installation is already connected")
    try:
        with session.begin_nested():
            connection = create_connection(
                session,
                org_id=org_id,
                actor=actor,
                kind=ConnectionKind.GITHUB,
                display_name=login,
                config={"installation_id": str(installation), "org": login},
            )
    except IntegrityError:
        raise GitHubSetupError(
            "this GitHub installation is already connected to another Passport organization"
        ) from None
    _ensure_scope_entry(session, org_id, actor, ScopeKind.GITHUB_ORG, login)
    return connection


# --- building a connector for a stored connection ---------------------------------------


def connector_for(
    session: Session,
    connection: Connection,
    *,
    platform: PlatformSettings,
    vault: Vault | None = None,
    http: httpx.Client | None = None,
    sts: Any = None,
    aws_clients: ClientFactory | None = None,
) -> Connector:
    """The live connector for an active connection (the check runner, U11, uses this)."""
    kind = ConnectionKind(connection.kind)
    config = connection.config
    if kind is ConnectionKind.AWS:
        if aws_clients is None:
            if sts is None:
                import boto3

                sts = boto3.client("sts")
            aws_clients = assumed_role_clients(
                sts=sts, role_arn=config["role_arn"], external_id=config["external_id"]
            )
        return AwsConnector(account_id=config["account_id"], clients=aws_clients)
    if http is None:
        raise ValueError("an HTTP client is required for this connection kind")
    if kind is ConnectionKind.GOOGLE_WORKSPACE:
        if vault is None:
            raise ValueError("a vault is required to open the Google refresh token")
        secret = load_secret(session, vault, connection)
        if secret is None:
            raise SetupError("this Google connection has no stored token; reconnect it")
        if not platform.google_oauth_client_id or platform.google_oauth_client_secret is None:
            raise SetupError("GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET must be set")
        return GoogleWorkspaceConnector(
            domain=config["domain"],
            refresh_token=json.loads(secret)["refresh_token"],
            client_id=platform.google_oauth_client_id,
            client_secret=platform.google_oauth_client_secret.get_secret_value(),
            http=http,
        )
    return GitHubConnector(
        org=config["org"],
        installation_id=int(config["installation_id"]),
        credentials=platform.github_credentials(),
        http=http,
    )
