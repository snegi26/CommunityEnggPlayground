"""AWS connector reads and setup, replayed through botocore's Stubber (no live calls)."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import botocore.session
import pytest
from botocore.config import Config
from botocore.stub import ANY, Stubber
from sqlalchemy import select

from passport.connectors.aws import AwsConnector
from passport.connectors.base import Capability
from passport.connectors.models import Connection, ConnectionKind
from passport.connectors.observation import Failure, FailureKind, Observed
from passport.connectors.registry import registry
from passport.connectors.setup import (
    AWS_TEMPLATE_PATH,
    AwsSetupError,
    PlatformSettings,
    begin_aws_setup,
    complete_aws_setup,
)
from passport.controls.models import ScopeEntry, ScopeKind
from passport.controls.settings import add_scope_entry
from passport.db.engine import get_sessionmaker
from passport.db.rls import set_org_context
from passport.provenance.actor import Human
from tests.helpers import create_org, sign_up

FIXTURES = Path(__file__).parents[1] / "fixtures" / "provider_responses" / "aws"
ACCOUNT = "111122223333"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/PassportReadOnly"
PRINCIPAL = "arn:aws:iam::999900001111:role/passport-checker"
PLATFORM = PlatformSettings(aws_platform_principal_arn=PRINCIPAL)
CLOCK = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
SESSION_KEY = "browser-session-key"


def _fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


class Stubs:
    """One stubbed botocore client per service, handed out by a client factory."""

    def __init__(self) -> None:
        self._session = botocore.session.get_session()
        self.clients: dict[str, Any] = {}
        self.stubbers: dict[str, Stubber] = {}

    def __call__(self, service: str) -> Any:
        return self.client(service)

    def client(self, service: str) -> Any:
        if service not in self.clients:
            client = self._session.create_client(
                service,  # type: ignore[call-overload]
                region_name="us-east-1",
                aws_access_key_id="AKIDTEST",
                aws_secret_access_key="test-secret",
                config=Config(retries={"max_attempts": 1, "mode": "standard"}),
            )
            self.clients[service] = client
            stubber = Stubber(client)
            stubber.activate()
            self.stubbers[service] = stubber
        return self.clients[service]

    def stub(self, service: str) -> Stubber:
        self.client(service)
        return self.stubbers[service]

    def assert_done(self) -> None:
        for stubber in self.stubbers.values():
            stubber.assert_no_pending_responses()


@pytest.fixture
def stubs() -> Iterator[Stubs]:
    s = Stubs()
    yield s
    s.assert_done()


def _connector(stubs: Stubs) -> AwsConnector:
    return AwsConnector(
        account_id=ACCOUNT, clients=stubs, clock=lambda: CLOCK, sleep=lambda _: None
    )


def _assumed() -> dict[str, Any]:
    return {
        "Credentials": {
            "AccessKeyId": "ASIATESTTESTTEST",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": datetime(2026, 10, 30, 13, 0, tzinfo=UTC),
        },
        "AssumedRoleUser": {
            "AssumedRoleId": "AROATEST:passport-setup",
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/PassportReadOnly/passport-setup",
        },
    }


# --- reads ---------------------------------------------------------------------------


def test_a_console_user_with_mfa_off_is_named_in_the_observation(stubs: Stubs) -> None:
    iam = stubs.stub("iam")
    iam.add_response("generate_credential_report", {"State": "STARTED"}, {})
    iam.add_response("generate_credential_report", {"State": "COMPLETE"}, {})
    iam.add_response(
        "get_credential_report",
        {
            "Content": (FIXTURES / "credential_report.csv").read_bytes(),
            "ReportFormat": "text/csv",
            "GeneratedTime": datetime(2026, 10, 30, 11, 59, tzinfo=UTC),
        },
        {},
    )

    result = _connector(stubs).list_users_mfa()

    assert isinstance(result, Observed)
    # Console users only: the root row and the access-key-only user are left out.
    assert result.rows == [{"user": "alice", "mfa": True}, {"user": "bob", "mfa": False}]
    assert result.scope == (ACCOUNT,)
    assert result.capability is Capability.LIST_USERS_MFA
    assert result.endpoint == "iam:GetCredentialReport"
    assert result.checkable
    assert "bob,arn:aws:iam" in result.raw_response["content"]


def test_root_mfa_comes_from_the_account_summary(stubs: Stubs) -> None:
    stubs.stub("iam").add_response(
        "get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 0, "Users": 3}}, {}
    )
    result = _connector(stubs).get_root_mfa()
    assert isinstance(result, Observed)
    assert result.rows == [{"account": ACCOUNT, "root_mfa": False}]


def test_password_policy_minimum_length_and_a_missing_policy(stubs: Stubs) -> None:
    iam = stubs.stub("iam")
    iam.add_response(
        "get_account_password_policy", {"PasswordPolicy": {"MinimumPasswordLength": 14}}, {}
    )
    iam.add_client_error(
        "get_account_password_policy", service_error_code="NoSuchEntity", http_status_code=404
    )
    connector = _connector(stubs)

    first = connector.get_password_policy()
    assert isinstance(first, Observed)
    assert first.rows == [{"account": ACCOUNT, "minimum_length": 14}]

    # No custom policy: a row with no minimum, so a length claim is contradicted, not vacuous.
    second = connector.get_password_policy()
    assert isinstance(second, Observed)
    assert second.rows == [{"account": ACCOUNT, "minimum_length": None}]


def test_cloudtrail_trails_with_their_logging_status(stubs: Stubs) -> None:
    trails = _fixture("cloudtrail_describe_trails.json")
    ct = stubs.stub("cloudtrail")
    ct.add_response("describe_trails", trails, {"includeShadowTrails": True})
    ct.add_response("get_trail_status", {"IsLogging": True}, {"Name": ANY})
    ct.add_response("get_trail_status", {"IsLogging": False}, {"Name": ANY})

    result = _connector(stubs).list_cloudtrail_trails()

    assert isinstance(result, Observed)
    assert result.rows == [
        {"name": "org-trail", "logging": True, "multi_region": True},
        {"name": "legacy-eu", "logging": False, "multi_region": False},
    ]


def test_s3_bucket_encryption_consumes_every_page(stubs: Stubs) -> None:
    s3 = stubs.stub("s3")
    created = datetime(2025, 1, 1, tzinfo=UTC)
    s3.add_response(
        "list_buckets",
        {"Buckets": [{"Name": "logs", "CreationDate": created}], "ContinuationToken": "next"},
        {"MaxBuckets": 1000},
    )
    s3.add_response(
        "list_buckets",
        {"Buckets": [{"Name": "uploads", "CreationDate": created}]},
        {"MaxBuckets": 1000, "ContinuationToken": "next"},
    )
    s3.add_response(
        "get_bucket_encryption",
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
            }
        },
        {"Bucket": "logs"},
    )
    s3.add_client_error(
        "get_bucket_encryption",
        service_error_code="ServerSideEncryptionConfigurationNotFoundError",
        http_status_code=404,
        expected_params={"Bucket": "uploads"},
    )

    result = _connector(stubs).list_s3_bucket_encryption()

    assert isinstance(result, Observed)
    assert result.rows == [
        {"bucket": "logs", "encrypted": True},
        {"bucket": "uploads", "encrypted": False},
    ]
    assert result.pagination_complete and result.complete
    assert result.parameters["pages"] == 2


def test_account_public_access_block_settings(stubs: Stubs) -> None:
    stubs.stub("s3control").add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            }
        },
        {"AccountId": ACCOUNT},
    )
    result = _connector(stubs).get_s3_public_access_block()
    assert isinstance(result, Observed)
    assert result.rows == [
        {
            "account": ACCOUNT,
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": False,
            "restrict_public_buckets": True,
        }
    ]


def test_organization_accounts_are_listed_across_pages(stubs: Stubs) -> None:
    orgs = stubs.stub("organizations")
    orgs.add_response("list_accounts", _fixture("organizations_list_accounts_page1.json"), {})
    orgs.add_response(
        "list_accounts",
        _fixture("organizations_list_accounts_page2.json"),
        {"NextToken": "page-2-token"},
    )
    result = _connector(stubs).list_accounts()
    assert isinstance(result, Observed)
    assert [r["account"] for r in result.rows] == ["111122223333", "444455556666", "777788889999"]
    assert result.rows[1] == {"account": "444455556666", "name": "Production", "status": "ACTIVE"}
    assert result.complete and result.parameters["pages"] == 2
    assert len(result.raw_response["pages"]) == 2


def test_access_denied_is_an_unauthorized_failure(stubs: Stubs) -> None:
    stubs.stub("iam").add_client_error(
        "get_account_summary", service_error_code="AccessDenied", http_status_code=403
    )
    result = _connector(stubs).get_root_mfa()
    assert isinstance(result, Failure)
    assert result.kind is FailureKind.UNAUTHORIZED
    assert result.scope == (ACCOUNT,)


def test_the_aws_connector_is_registered_for_its_kind() -> None:
    assert registry.connector_class(ConnectionKind.AWS) is AwsConnector


def test_the_role_template_grants_security_audit_behind_the_external_id() -> None:
    body = AWS_TEMPLATE_PATH.read_text()
    assert "arn:aws:iam::aws:policy/SecurityAudit" in body
    assert "sts:ExternalId" in body
    assert "policy/ReadOnlyAccess" not in body


# --- setup ---------------------------------------------------------------------------


@pytest.mark.usefixtures("database_urls")
def test_setup_fails_when_the_trust_policy_does_not_require_the_external_id(
    stubs: Stubs,
) -> None:
    owner = sign_up()
    org = create_org(owner)
    sts = stubs.client("sts")
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        start = begin_aws_setup(
            db, org, Human(owner.user_id), session_key=SESSION_KEY, platform=PLATFORM
        )
        stub = stubs.stub("sts")
        stub.add_response(
            "assume_role",
            _assumed(),
            {"RoleArn": ROLE_ARN, "RoleSessionName": ANY, "ExternalId": start.external_id},
        )
        # Without the external id the role still lets us in: the confused-deputy gap.
        stub.add_response("assume_role", _assumed(), {"RoleArn": ROLE_ARN, "RoleSessionName": ANY})

        with pytest.raises(AwsSetupError, match="trust policy") as excinfo:
            complete_aws_setup(
                db,
                org,
                Human(owner.user_id),
                session_key=SESSION_KEY,
                token=start.token,
                role_arn=ROLE_ARN,
                sts=sts,
                clients=stubs,
            )
        assert "sts:ExternalId" in str(excinfo.value)
        assert db.scalars(select(Connection)).all() == []


@pytest.mark.usefixtures("database_urls")
def test_setup_fails_clearly_when_the_role_cannot_be_assumed_with_the_external_id(
    stubs: Stubs,
) -> None:
    owner = sign_up()
    org = create_org(owner)
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        start = begin_aws_setup(
            db, org, Human(owner.user_id), session_key=SESSION_KEY, platform=PLATFORM
        )
        stubs.stub("sts").add_client_error(
            "assume_role", service_error_code="AccessDenied", http_status_code=403
        )
        with pytest.raises(AwsSetupError, match="trust policy"):
            complete_aws_setup(
                db,
                org,
                Human(owner.user_id),
                session_key=SESSION_KEY,
                token=start.token,
                role_arn=ROLE_ARN,
                sts=stubs.client("sts"),
                clients=stubs,
            )
        assert db.scalars(select(Connection)).all() == []


@pytest.mark.usefixtures("database_urls")
def test_a_verified_setup_connects_and_prefills_accounts_as_non_production(
    stubs: Stubs,
) -> None:
    owner = sign_up()
    org = create_org(owner)
    actor = Human(owner.user_id)
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        # Already declared (and marked production) before setup: kept as it is.
        add_scope_entry(db, org, actor, ScopeKind.AWS_ACCOUNT, "444455556666", production=True)
        start = begin_aws_setup(db, org, actor, session_key=SESSION_KEY, platform=PLATFORM)
        assert start.principal_arn == PRINCIPAL
        assert len(start.external_id) >= 32
        assert start.template_parameters == {
            "PlatformPrincipalArn": PRINCIPAL,
            "ExternalId": start.external_id,
        }
        assert start.external_id in start.instructions

        sts = stubs.stub("sts")
        sts.add_response(
            "assume_role",
            _assumed(),
            {"RoleArn": ROLE_ARN, "RoleSessionName": ANY, "ExternalId": start.external_id},
        )
        sts.add_client_error(
            "assume_role",
            service_error_code="AccessDenied",
            http_status_code=403,
            expected_params={"RoleArn": ROLE_ARN, "RoleSessionName": ANY},
        )
        orgs = stubs.stub("organizations")
        orgs.add_response("list_accounts", _fixture("organizations_list_accounts_page1.json"), {})
        orgs.add_response(
            "list_accounts",
            _fixture("organizations_list_accounts_page2.json"),
            {"NextToken": "page-2-token"},
        )

        conn = complete_aws_setup(
            db,
            org,
            actor,
            session_key=SESSION_KEY,
            token=start.token,
            role_arn=ROLE_ARN,
            sts=stubs.client("sts"),
            clients=stubs,
        )
        db.commit()

        set_org_context(db, org)
        assert conn.kind == ConnectionKind.AWS.value
        assert conn.config == {
            "role_arn": ROLE_ARN,
            "external_id": start.external_id,
            "account_id": ACCOUNT,
        }
        entries = {
            e.identifier: (e.label, e.production) for e in db.scalars(select(ScopeEntry)).all()
        }
        assert entries == {
            "111122223333": ("Management", False),
            "444455556666": ("", True),
            "777788889999": ("Staging", False),
        }
        # The setup token is single use.
        with pytest.raises(AwsSetupError):
            complete_aws_setup(
                db,
                org,
                actor,
                session_key=SESSION_KEY,
                token=start.token,
                role_arn=ROLE_ARN,
                sts=stubs.client("sts"),
                clients=stubs,
            )


@pytest.mark.usefixtures("database_urls")
def test_a_setup_token_from_another_org_or_session_is_rejected(stubs: Stubs) -> None:
    owner_x, owner_y = sign_up(), sign_up()
    org_x, org_y = create_org(owner_x, "X"), create_org(owner_y, "Y")
    with get_sessionmaker()() as db:
        set_org_context(db, org_x)
        start = begin_aws_setup(
            db, org_x, Human(owner_x.user_id), session_key=SESSION_KEY, platform=PLATFORM
        )
        db.commit()

        set_org_context(db, org_x)
        with pytest.raises(AwsSetupError):
            complete_aws_setup(
                db,
                org_x,
                Human(owner_x.user_id),
                session_key="another-browser",
                token=start.token,
                role_arn=ROLE_ARN,
                sts=stubs.client("sts"),
                clients=stubs,
            )
        db.rollback()

        set_org_context(db, org_y)
        with pytest.raises(AwsSetupError):
            complete_aws_setup(
                db,
                org_y,
                Human(owner_y.user_id),
                session_key=SESSION_KEY,
                token=start.token,
                role_arn=ROLE_ARN,
                sts=stubs.client("sts"),
                clients=stubs,
            )
        assert db.scalars(select(Connection)).all() == []
