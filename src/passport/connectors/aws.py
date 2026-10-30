"""AWS connector: read-only reads through a cross-account role (R5, KTD6, KTD7).

We hold no customer secret. The customer creates a role (``deploy/aws-readonly-role.yaml``)
trusting our platform principal on condition of a per-connection external id that we
generate, with the AWS-managed ``SecurityAudit`` policy attached. Each read assumes
that role and calls one AWS read API; every observation's scope is the account id.

Service clients come from a factory, so tests replay recorded responses through
botocore's Stubber and production builds clients from assumed-role credentials.
"""

import csv
import io
import re
import secrets
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    ReadTimeoutError,
)

from passport.connectors.base import Capability, Connector
from passport.connectors.models import ConnectionKind
from passport.connectors.observation import CollectionResult, Failure, FailureKind, Observed
from passport.connectors.registry import registry
from passport.db.base import utcnow

COLLECTOR_VERSION = "aws-1"
DEFAULT_REGION = "us-east-1"
ROLE_SESSION_NAME = "passport-readonly"
SECURITY_AUDIT_POLICY_ARN = "arn:aws:iam::aws:policy/SecurityAudit"
ROLE_ARN_PATTERN = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):role/[\w+=,.@/-]{1,512}$")

UNAUTHORIZED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AuthFailure",
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidClientTokenId",
        "UnauthorizedOperation",
        "UnrecognizedClientException",
    }
)
RATE_LIMIT_CODES = frozenset(
    {
        "RequestLimitExceeded",
        "SlowDown",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
    }
)

# Returns a boto3/botocore client for a service name ("iam", "s3", ...).
ClientFactory = Callable[[str], Any]


def generate_external_id() -> str:
    """A fresh, unguessable external id; always ours, never chosen by the customer."""
    return secrets.token_urlsafe(32)


def account_id_from_role_arn(role_arn: str) -> str:
    match = ROLE_ARN_PATTERN.match(role_arn.strip())
    if match is None:
        raise ValueError("not an IAM role ARN (arn:aws:iam::<account id>:role/<name>)")
    return match.group(1)


def assumed_role_clients(
    *, sts: Any, role_arn: str, external_id: str, region: str = DEFAULT_REGION
) -> ClientFactory:
    """A client factory that assumes the customer role once, then builds clients from it."""
    import boto3

    cache: dict[str, Any] = {}

    def factory(service: str) -> Any:
        if "session" not in cache:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=ROLE_SESSION_NAME,
                ExternalId=external_id,
                DurationSeconds=900,
            )
            creds = response["Credentials"]
            cache["session"] = boto3.session.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        if service not in cache:
            cache[service] = cache["session"].client(service)
        return cache[service]

    return factory


def error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


class _ReadFailedError(Exception):
    def __init__(self, kind: FailureKind, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


class AwsConnector(Connector):
    """Reads one AWS account through the customer's SecurityAudit role."""

    kind = ConnectionKind.AWS
    collector_version = COLLECTOR_VERSION

    def __init__(
        self,
        *,
        account_id: str,
        clients: ClientFactory,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], None] = time.sleep,
        report_attempts: int = 10,
        report_interval_seconds: float = 2.0,
    ) -> None:
        self.account_id = account_id
        self.scope = (account_id,)
        self._clients = clients
        self._clock = clock
        self._sleep = sleep
        self._report_attempts = report_attempts
        self._report_interval = report_interval_seconds

    # --- plumbing ------------------------------------------------------------------

    def _run(
        self,
        capability: Capability,
        endpoint: str,
        read: Callable[[], tuple[list[dict[str, Any]], Any, dict[str, Any]]],
    ) -> CollectionResult:
        parameters: dict[str, Any] = {"account_id": self.account_id}
        try:
            rows, raw, extra = read()
        except _ReadFailedError as exc:
            return self._failure(capability, endpoint, parameters, exc.kind, exc.detail)
        except ClientError as exc:
            code = error_code(exc)
            if code in UNAUTHORIZED_CODES:
                kind = FailureKind.UNAUTHORIZED
            elif code in RATE_LIMIT_CODES:
                kind = FailureKind.RATE_LIMITED
            else:
                raise
            return self._failure(capability, endpoint, parameters, kind, f"{endpoint}: {code}")
        except (ReadTimeoutError, ConnectTimeoutError) as exc:
            return self._failure(
                capability, endpoint, parameters, FailureKind.TIMEOUT, f"{endpoint}: {exc}"
            )
        parameters.update(extra)
        return Observed(
            capability=capability,
            endpoint=endpoint,
            parameters=parameters,
            rows=rows,
            raw_response=raw,
            collector_version=self.collector_version,
            collected_at=self._clock(),
            scope=self.scope,
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

    def _client(self, service: str) -> Any:
        return self._clients(service)

    # --- reads ---------------------------------------------------------------------

    def list_accounts(self) -> CollectionResult:
        def read() -> tuple[list[dict[str, Any]], Any, dict[str, Any]]:
            client = self._client("organizations")
            pages: list[Any] = []
            rows: list[dict[str, Any]] = []
            token: str | None = None
            while True:
                page = client.list_accounts(**({"NextToken": token} if token else {}))
                pages.append(_jsonable(page))
                rows.extend(
                    {"account": a["Id"], "name": a.get("Name", ""), "status": a.get("Status", "")}
                    for a in page.get("Accounts", [])
                )
                token = page.get("NextToken")
                if not token:
                    break
            return rows, {"pages": pages}, {"pages": len(pages)}

        return self._run(Capability.LIST_ACCOUNTS, "organizations:ListAccounts", read)

    def list_users_mfa(self) -> CollectionResult:
        def read() -> tuple[list[dict[str, Any]], Any, dict[str, Any]]:
            iam = self._client("iam")
            for attempt in range(self._report_attempts):
                state = iam.generate_credential_report().get("State")
                if state == "COMPLETE":
                    break
                if attempt + 1 < self._report_attempts:
                    self._sleep(self._report_interval)
            else:
                raise _ReadFailedError(
                    FailureKind.TIMEOUT, "the IAM credential report was not ready in time"
                )
            report = iam.get_credential_report()
            content = report["Content"]
            text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
            rows = [
                {"user": line["user"], "mfa": line.get("mfa_active") == "true"}
                for line in csv.DictReader(io.StringIO(text))
                # Console users only; root MFA is read from the account summary.
                if line.get("user") != "<root_account>" and line.get("password_enabled") == "true"
            ]
            generated = report.get("GeneratedTime")
            raw = {
                "content": text,
                "generated_time": generated.isoformat() if generated else None,
            }
            return rows, raw, {"users": "console users (password_enabled)"}

        return self._run(Capability.LIST_USERS_MFA, "iam:GetCredentialReport", read)

    def get_root_mfa(self) -> CollectionResult:
        def read() -> tuple[list[dict[str, Any]], Any, dict[str, Any]]:
            summary = self._client("iam").get_account_summary()
            enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled") == 1
            row = {"account": self.account_id, "root_mfa": enabled}
            return [row], _jsonable(summary), {}

        return self._run(Capability.GET_ROOT_MFA, "iam:GetAccountSummary", read)

    def get_password_policy(self) -> CollectionResult:
        def read() -> tuple[list[dict[str, Any]], Any, dict[str, Any]]:
            try:
                response = self._client("iam").get_account_password_policy()
            except ClientError as exc:
                if error_code(exc) != "NoSuchEntity":
                    raise
                # No custom policy is set: record that, with no minimum length observed.
                raw = {"error": "NoSuchEntity"}
                return [{"account": self.account_id, "minimum_length": None}], raw, {}
            length = response.get("PasswordPolicy", {}).get("MinimumPasswordLength")
            row = {"account": self.account_id, "minimum_length": length}
            return [row], _jsonable(response), {}

        return self._run(Capability.GET_PASSWORD_POLICY, "iam:GetAccountPasswordPolicy", read)

    def list_cloudtrail_trails(self) -> CollectionResult:
        def read() -> tuple[list[dict[str, Any]], Any, dict[str, Any]]:
            client = self._client("cloudtrail")
            # Shadow trails included so multi-region trails homed elsewhere are seen.
            described = client.describe_trails(includeShadowTrails=True)
            rows: list[dict[str, Any]] = []
            statuses: dict[str, Any] = {}
            seen: set[str] = set()
            for trail in described.get("trailList", []):
                arn = trail.get("TrailARN") or trail["Name"]
                if arn in seen:
                    continue
                seen.add(arn)
                status = client.get_trail_status(Name=arn)
                statuses[arn] = _jsonable(status)
                rows.append(
                    {
                        "name": trail["Name"],
                        "logging": status.get("IsLogging") is True,
                        "multi_region": trail.get("IsMultiRegionTrail") is True,
                    }
                )
            raw = {"describe_trails": _jsonable(described), "trail_status": statuses}
            return rows, raw, {"include_shadow_trails": True}

        return self._run(
            Capability.LIST_CLOUDTRAIL_TRAILS,
            "cloudtrail:DescribeTrails+GetTrailStatus",
            read,
        )

    def list_s3_bucket_encryption(self) -> CollectionResult:
        def read() -> tuple[list[dict[str, Any]], Any, dict[str, Any]]:
            s3 = self._client("s3")
            pages: list[Any] = []
            buckets: list[str] = []
            token: str | None = None
            while True:
                kwargs: dict[str, Any] = {"MaxBuckets": 1000}
                if token:
                    kwargs["ContinuationToken"] = token
                page = s3.list_buckets(**kwargs)
                pages.append(_jsonable(page))
                buckets.extend(b["Name"] for b in page.get("Buckets", []))
                token = page.get("ContinuationToken")
                if not token:
                    break
            rows: list[dict[str, Any]] = []
            encryption: dict[str, Any] = {}
            for bucket in buckets:
                try:
                    response = s3.get_bucket_encryption(Bucket=bucket)
                except ClientError as exc:
                    if error_code(exc) != "ServerSideEncryptionConfigurationNotFoundError":
                        raise
                    encryption[bucket] = {"error": error_code(exc)}
                    rows.append({"bucket": bucket, "encrypted": False})
                    continue
                encryption[bucket] = _jsonable(response)
                rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                encrypted = any(
                    r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                    for r in rules
                )
                rows.append({"bucket": bucket, "encrypted": encrypted})
            raw = {"list_buckets": pages, "encryption": encryption}
            return rows, raw, {"pages": len(pages)}

        return self._run(
            Capability.LIST_S3_BUCKET_ENCRYPTION, "s3:ListBuckets+GetBucketEncryption", read
        )

    def get_s3_public_access_block(self) -> CollectionResult:
        def read() -> tuple[list[dict[str, Any]], Any, dict[str, Any]]:
            try:
                response = self._client("s3control").get_public_access_block(
                    AccountId=self.account_id
                )
            except ClientError as exc:
                if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                    raise
                # Never configured: every setting is off.
                response = {"PublicAccessBlockConfiguration": {}}
            config = response.get("PublicAccessBlockConfiguration", {})
            row = {
                "account": self.account_id,
                "block_public_acls": config.get("BlockPublicAcls") is True,
                "ignore_public_acls": config.get("IgnorePublicAcls") is True,
                "block_public_policy": config.get("BlockPublicPolicy") is True,
                "restrict_public_buckets": config.get("RestrictPublicBuckets") is True,
            }
            return [row], _jsonable(response), {}

        return self._run(
            Capability.GET_S3_PUBLIC_ACCESS_BLOCK, "s3control:GetPublicAccessBlock", read
        )


def _jsonable(value: Any) -> Any:
    """Strip boto3 response metadata and make datetimes and bytes JSON-safe for IPE."""
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items() if k != "ResponseMetadata"}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


# --- setup verification -----------------------------------------------------------------


class AwsTrustPolicyError(Exception):
    """The customer role's trust policy is not set up the way setup requires."""


def verify_role_trust(sts: Any, *, role_arn: str, external_id: str) -> None:
    """Assume-role with the external id must work, and without it must be refused.

    The second check catches a trust policy missing the ``sts:ExternalId`` condition,
    which would let anyone who learns the role ARN use our principal against it.
    """
    try:
        sts.assume_role(
            RoleArn=role_arn, RoleSessionName=f"{ROLE_SESSION_NAME}-setup", ExternalId=external_id
        )
    except (ClientError, BotoCoreError) as exc:
        raise AwsTrustPolicyError(
            f"We could not assume {role_arn} with the external id shown in setup. Check that "
            "the role exists and that its trust policy names our principal with an "
            "sts:ExternalId condition equal to that external id."
        ) from exc
    try:
        sts.assume_role(RoleArn=role_arn, RoleSessionName=f"{ROLE_SESSION_NAME}-setup-check")
    except ClientError as exc:
        if error_code(exc) in UNAUTHORIZED_CODES:
            return
        raise
    raise AwsTrustPolicyError(
        f"The trust policy of {role_arn} lets our principal assume it without the external "
        "id. Add a Condition requiring sts:ExternalId to equal the external id shown in "
        "setup (the provided CloudFormation template does this), then verify again."
    )


registry.register(AwsConnector)
