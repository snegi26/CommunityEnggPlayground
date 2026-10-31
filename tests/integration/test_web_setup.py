"""Sign-in pages, org switcher, and the F1 setup wizard (U14) through the real HTTP app."""

import re
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pyotp
import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient
from procrastinate.testing import InMemoryConnector
from sqlalchemy import func, select

from passport.agent.jobs import run_drafting
from passport.auth.service import RECOVERY_CODE_COUNT
from passport.checks.jobs import run_checks_for_org
from passport.connectors.models import Connection
from passport.connectors.setup import ConnectionSetup, PlatformSettings
from passport.controls.models import ControlMapping, OrgFrameworkSettings, ScopeEntry
from passport.db.models import Claim, ClaimState, DocumentVersion, Event, EvidenceItem
from passport.documents.models import DocumentSpan
from passport.documents.storage import LocalDirectoryStorage
from passport.jobs import app as jobs_app
from passport.provenance.service import verify_chain
from passport.reports.builder import build_report
from passport.tenancy.models import Invitation, Membership
from passport.web.routes.setup import SetupProviders, get_setup_providers, get_upload_storage
from tests.helpers import PASSWORD, SignedInUser, create_org, new_client, sign_up
from tests.integration import test_github_connector as gh
from tests.integration.test_web_passport import (
    AWS_PROD,
    aws_fake,
    csrf,
    db_for,
    factory,
    row_html,
)
from tests.unit.test_drafting_verification import StubClient, claim, end_turn, propose_turn

pytestmark = pytest.mark.usefixtures("database_urls")

POLICY_MD = (Path(__file__).parents[1] / "fixtures" / "policies" / "access_control.md").read_bytes()
MFA_SENTENCE = (
    "MFA is required on all production accounts, including administrator and break-glass accounts."
)
ROLE_ARN = f"arn:aws:iam::{AWS_PROD}:role/PassportReadOnly"
PRINCIPAL = "arn:aws:iam::999900001111:role/passport-checker"
STAGING = "222222222222"


class FakeSts:
    """Assume-role with the external id succeeds when ``trusts`` is set; never without it."""

    def __init__(self, *, trusts: bool) -> None:
        self.trusts = trusts
        self.calls: list[dict[str, Any]] = []

    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.trusts and "ExternalId" in kwargs:
            return {
                "Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}
            }
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "AssumeRole")


class FakeOrganizations:
    def list_accounts(self, **_: Any) -> dict[str, Any]:
        return {
            "Accounts": [
                {"Id": AWS_PROD, "Name": "Production", "Status": "ACTIVE"},
                {"Id": STAGING, "Name": "Staging", "Status": "ACTIVE"},
            ]
        }


def use_providers(client: TestClient, **kwargs: Any) -> SetupProviders:
    providers = SetupProviders(**kwargs)
    client.app.dependency_overrides[get_setup_providers] = lambda: providers  # type: ignore[attr-defined]
    return providers


@pytest.fixture
def storage(tmp_path: Path) -> LocalDirectoryStorage:
    return LocalDirectoryStorage(tmp_path / "storage")


@pytest.fixture
def owner(storage: LocalDirectoryStorage) -> SignedInUser:
    user = sign_up()
    user.client.app.dependency_overrides[get_upload_storage] = lambda: storage  # type: ignore[attr-defined]
    return user


@pytest.fixture
def org_id(owner: SignedInUser) -> uuid.UUID:
    return create_org(owner)


@pytest.fixture
def jobs() -> Iterator[InMemoryConnector]:
    connector = InMemoryConnector()
    with jobs_app.replace_connector(connector):
        yield connector


def post(client: TestClient, path: str, data: dict[str, Any] | None = None, **kw: Any) -> Any:
    return client.post(path, data={"csrf_token": csrf(client), **(data or {})}, **kw)


# --- sign-in pages ---------------------------------------------------------------------


def test_login_then_mfa_verify_pages_sign_a_user_in() -> None:
    user = sign_up()
    client = new_client()
    page = client.get("/orgs/" + str(uuid.uuid4()) + "/passport", follow_redirects=False)
    assert page.status_code == 303 and page.headers["location"].startswith("/login?next=")

    wrong = client.post(
        "/login",
        data={"csrf_token": csrf(client, "/login"), "email": user.email, "password": "nope"},
    )
    assert wrong.status_code == 401 and "not correct" in wrong.text
    login = client.post(
        "/login",
        data={
            "csrf_token": csrf(client, "/login"),
            "email": user.email,
            "password": PASSWORD,
            "next": "/",
        },
        follow_redirects=False,
    )
    assert login.status_code == 303 and login.headers["location"].startswith("/login/mfa")
    assert user.totp is not None
    verified = client.post(
        "/login/mfa",
        data={"csrf_token": csrf(client, "/login/mfa"), "code": user.totp.now(), "next": "/"},
        follow_redirects=False,
    )
    assert verified.status_code == 303 and verified.headers["location"] == "/"
    assert "Your organizations" in client.get("/").text


def test_a_login_post_without_its_pre_session_token_is_rejected() -> None:
    user = sign_up()
    client = new_client()
    refused = client.post("/login", data={"email": user.email, "password": PASSWORD})
    assert refused.status_code == 403


def test_mfa_enrollment_shows_the_setup_uri_as_text_and_recovery_codes_once() -> None:
    user = sign_up(mfa=False)
    org = create_org(user)
    page = user.client.get(f"/orgs/{org}/passport", follow_redirects=False)
    assert page.status_code == 303 and page.headers["location"].startswith("/mfa/enroll")

    started = post(user.client, "/mfa/enroll", {"next": f"/orgs/{org}/passport"})
    uri = re.search(r'<code class="uri">(otpauth://[^<]+)</code>', started.text)
    assert uri, started.text
    secret = parse_qs(urlparse(uri.group(1).replace("&amp;", "&")).query)["secret"][0]
    confirmed = post(
        user.client,
        "/mfa/enroll/confirm",
        {"code": pyotp.TOTP(secret).now(), "next": f"/orgs/{org}/passport"},
    )
    codes = re.findall(r"<li><code>([0-9a-f]{10})</code></li>", confirmed.text)
    assert len(codes) == RECOVERY_CODE_COUNT
    assert user.client.get(f"/orgs/{org}/passport").status_code == 200
    assert codes[0] not in user.client.get("/mfa/enroll").text


def test_the_org_switcher_lists_each_membership_and_creates_orgs() -> None:
    consultant = sign_up()
    first = create_org(consultant, "Client A")
    created = post(consultant.client, "/orgs/create", {"name": "Client B"}, follow_redirects=False)
    assert created.status_code == 303
    second = uuid.UUID(created.headers["location"].split("/")[2])
    home = consultant.client.get("/").text
    assert "Client A" in home and "Client B" in home
    passport = consultant.client.get(f"/orgs/{first}/passport").text
    assert f'value="{second}"' in passport  # the switcher offers the other client
    switched = consultant.client.get(f"/switch?org_id={second}", follow_redirects=False)
    assert switched.headers["location"] == f"/orgs/{second}/passport"
    outsider = sign_up()
    assert outsider.client.get(f"/orgs/{first}/passport").status_code == 404


# --- the wizard ------------------------------------------------------------------------


def _resume(client: TestClient, org_id: uuid.UUID) -> str:
    response = client.get(f"/orgs/{org_id}/setup", follow_redirects=False)
    assert response.status_code == 303
    return str(response.headers["location"]).rsplit("/", 1)[1]


def _save_settings(client: TestClient, org_id: uuid.UUID) -> None:
    for framework, audit_type in (("soc2", "soc2_type2"), ("iso27001", "iso27001_certification")):
        saved = post(
            client,
            f"/orgs/{org_id}/setup/settings/{framework}",
            {
                "audit_type": audit_type,
                "window_start": "2026-01-01",
                "window_end": "2026-12-31",
                "policy_review_days": "365",
                "access_review_days": "90",
                "expiring_soon_days": "30",
            },
            follow_redirects=False,
        )
        assert saved.status_code == 303, saved.text


def _connect_aws(client: TestClient, org_id: uuid.UUID) -> None:
    use_providers(
        client,
        platform=PlatformSettings(aws_platform_principal_arn=PRINCIPAL),
        sts=lambda: FakeSts(trusts=True),
        aws_clients=lambda service: FakeOrganizations(),
    )
    started = post(client, f"/orgs/{org_id}/setup/aws/start")
    token = re.search(r'name="token" value="([^"]+)"', started.text)
    assert token
    done = post(
        client,
        f"/orgs/{org_id}/setup/aws/verify",
        {"token": token.group(1), "role_arn": ROLE_ARN},
        follow_redirects=False,
    )
    assert done.status_code == 303, done.text


def test_the_wizard_resumes_at_the_first_incomplete_step(
    owner: SignedInUser, org_id: uuid.UUID, jobs: InMemoryConnector
) -> None:
    client = owner.client
    assert _resume(client, org_id) == "connect"
    _connect_aws(client, org_id)
    assert _resume(client, org_id) == "settings"

    # Defaults alone carry no audit window, so the step is not complete until saved.
    bad = post(
        client,
        f"/orgs/{org_id}/setup/settings/soc2",
        {"audit_type": "soc2_type2", "window_start": "2026-12-31", "window_end": "2026-01-01"},
    )
    assert bad.status_code == 422 and "window end must be after" in bad.text
    assert _resume(client, org_id) == "settings"
    _save_settings(client, org_id)
    assert _resume(client, org_id) == "upload"

    post(
        client,
        f"/orgs/{org_id}/setup/upload/evidence",
        {"title": "Access review Q3", "source": "Okta export", "collected_at": "2026-10-01"},
        files={"file": ("review.csv", b"user,reviewed\nalice,yes\n")},
    )
    assert _resume(client, org_id) == "map"
    with db_for(org_id) as db:
        evidence_id = db.scalars(select(EvidenceItem.id)).one()
    mapped = post(
        client,
        f"/orgs/{org_id}/setup/map",
        {"item": f"evidence:{evidence_id}", "control": "soc2:CC6.1"},
        follow_redirects=False,
    )
    assert mapped.status_code == 303
    assert _resume(client, org_id) == "invite"

    invited = post(
        client,
        f"/orgs/{org_id}/setup/invite",
        {"email": "approver@example.com", "role": "approver"},
    )
    assert "/invitations/" in invited.text
    assert _resume(client, org_id) == "done"
    # A later visit to an earlier step still shows it complete.
    assert "Done" in client.get(f"/orgs/{org_id}/setup/connect").text


def test_a_failed_aws_verification_shows_the_trust_policy_message_and_retry_reverifies(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    client = owner.client
    failing = FakeSts(trusts=False)
    use_providers(
        client,
        platform=PlatformSettings(aws_platform_principal_arn=PRINCIPAL),
        sts=lambda: failing,
        aws_clients=lambda service: FakeOrganizations(),
    )
    started = post(client, f"/orgs/{org_id}/setup/aws/start")
    token = re.search(r'name="token" value="([^"]+)"', started.text).group(1)  # type: ignore[union-attr]
    external_id = re.search(r"External id: <code>([^<]+)</code>", started.text).group(1)  # type: ignore[union-attr]

    failed = post(
        client, f"/orgs/{org_id}/setup/aws/verify", {"token": token, "role_arn": ROLE_ARN}
    )
    assert failed.status_code == 422
    assert "Verification failed." in failed.text
    assert "trust policy names our principal with an" in failed.text
    assert "Retry verification" in failed.text
    # The retry form re-submits the same pending setup, so the deployed external id holds.
    assert f'name="token" value="{token}"' in failed.text and external_id in failed.text
    assert failing.calls and failing.calls[0]["ExternalId"] == external_id

    use_providers(
        client,
        platform=PlatformSettings(aws_platform_principal_arn=PRINCIPAL),
        sts=lambda: FakeSts(trusts=True),
        aws_clients=lambda service: FakeOrganizations(),
    )
    retried = post(
        client,
        f"/orgs/{org_id}/setup/aws/verify",
        {"token": token, "role_arn": ROLE_ARN},
    )
    assert retried.status_code == 200
    assert f"Connected AWS account {AWS_PROD}." in retried.text
    with db_for(org_id) as db:
        assert db.scalars(select(Connection)).one().config["external_id"] == external_id
        assert db.scalar(select(func.count()).select_from(ConnectionSetup)) == 0
        entries = {e.identifier: e for e in db.scalars(select(ScopeEntry))}
        assert set(entries) == {AWS_PROD, STAGING}
        prod_id = entries[AWS_PROD].id

    # Mark the pre-filled production account as production (R18 inventory).
    post(
        client,
        f"/orgs/{org_id}/setup/scope/{prod_id}/production",
        {"production": "true"},
    )
    page = client.get(f"/orgs/{org_id}/setup/settings").text
    assert "Mark not production" in page
    with db_for(org_id) as db:
        prod = db.scalars(select(ScopeEntry).where(ScopeEntry.identifier == AWS_PROD)).one()
        assert prod.production


def test_the_github_callback_binds_the_installation_for_the_org_in_its_state(
    owner: SignedInUser, org_id: uuid.UUID
) -> None:
    client = owner.client
    fake = gh.FakeGitHub()
    use_providers(
        client,
        platform=gh.PLATFORM,
        http=lambda: httpx.Client(transport=httpx.MockTransport(fake)),
    )
    started = post(client, f"/orgs/{org_id}/setup/github/start", follow_redirects=False)
    assert started.status_code == 303
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]

    # The same user signed in from another browser session cannot complete it.
    other_session = new_client()
    assert other_session.post(
        "/auth/login", json={"email": owner.email, "password": PASSWORD}
    ).json()["mfa_required"]
    assert owner.totp is not None
    other_session.post("/auth/mfa/verify", json={"code": owner.totp.now()})
    callback = f"/setup/github/callback?installation_id={gh.INSTALLATION}&code=installer"
    hijack = other_session.get(f"{callback}&state={state}")
    assert hijack.status_code == 422 and "invalid or has expired" in hijack.text
    # A member of another org cannot use this org's state.
    stranger = sign_up()
    assert stranger.client.get(f"{callback}&state={state}").status_code == 404

    done = client.get(f"{callback}&state={state}")
    assert done.status_code == 200 and f"Connected {gh.ORG}." in done.text
    again = client.get(f"{callback}&state={state}")
    assert again.status_code == 422 and "invalid or has expired; start again" in again.text
    assert "Retry" in again.text


def test_the_upload_route_carries_confirmations_over_then_enqueues_drafting(
    owner: SignedInUser, org_id: uuid.UUID, jobs: InMemoryConnector
) -> None:
    client = owner.client
    first = post(
        client,
        f"/orgs/{org_id}/setup/upload/policy",
        {"title": "Access control"},
        files={"file": ("access_control.md", POLICY_MD)},
        follow_redirects=False,
    )
    assert first.status_code == 303
    v1 = uuid.UUID(first.headers["location"].split("/")[4])
    [job] = list(jobs.jobs.values())
    assert job["task_name"] == "passport.agent.draft_claims"
    assert job["args"] == {"org_id": str(org_id), "document_version_id": str(v1)}

    # Draft and confirm the MFA claim on version 1.
    with db_for(org_id) as db:
        span = next(
            s.span_id
            for s in db.scalars(select(DocumentSpan))
            if s.text.startswith("MFA is required")
        )
    run_drafting(
        org_id, v1, client=StubClient([propose_turn(claim(span, MFA_SENTENCE)), end_turn()])
    )
    with db_for(org_id) as db:
        drafted = db.scalars(select(Claim)).one()
    post(client, f"/orgs/{org_id}/claims/{drafted.id}/confirm")

    changed = POLICY_MD.replace(b"every quarter", b"every month")
    with db_for(org_id) as db:
        document_id = db.get(DocumentVersion, v1).document_id  # type: ignore[union-attr]
    second = post(
        client,
        f"/orgs/{org_id}/setup/upload/policy",
        {"document_id": str(document_id)},
        files={"file": ("access_control.md", changed)},
        follow_redirects=False,
    )
    v2 = uuid.UUID(second.headers["location"].split("/")[4])
    assert v2 != v1
    with db_for(org_id) as db:
        carried = db.scalars(select(Claim).where(Claim.document_version_id == v2)).one()
        assert carried.revision_of == drafted.id
        assert carried.state is ClaimState.CONFIRMED and carried.confirmed_by == owner.user_id
        assert db.scalars(select(Event).where(Event.event_type == "claim.carried_over")).one()
    drafting_jobs = [
        j for j in jobs.jobs.values() if j["task_name"] == "passport.agent.draft_claims"
    ]
    assert [j["args"]["document_version_id"] for j in drafting_jobs] == [str(v1), str(v2)]
    page = client.get(f"/orgs/{org_id}/versions/{v2}/claims").text
    assert MFA_SENTENCE in page and "Confirmed" in page


def test_a_rejected_upload_shows_the_reason_and_stores_nothing(
    owner: SignedInUser, org_id: uuid.UUID, jobs: InMemoryConnector
) -> None:
    refused = post(
        owner.client,
        f"/orgs/{org_id}/setup/upload/policy",
        files={"file": ("policy.exe", b"MZ")},
    )
    assert refused.status_code == 422 and "message error" in refused.text
    assert jobs.jobs == {}


# --- F1 walkthrough --------------------------------------------------------------------


def test_f1_walkthrough_against_fakes_completes_end_to_end(
    owner: SignedInUser, storage: LocalDirectoryStorage, jobs: InMemoryConnector
) -> None:
    client = owner.client
    # A consultant adds a client organization.
    created = post(client, "/orgs/create", {"name": "Client Co"}, follow_redirects=False)
    org_id = uuid.UUID(created.headers["location"].split("/")[2])
    assert _resume(client, org_id) == "connect"

    # 1. Connect AWS read-only; its accounts pre-fill the inventory.
    _connect_aws(client, org_id)
    # 2. Settings and scope: audit windows per framework, production account marked.
    _save_settings(client, org_id)
    with db_for(org_id) as db:
        prod = db.scalars(select(ScopeEntry).where(ScopeEntry.identifier == AWS_PROD)).one().id
    post(client, f"/orgs/{org_id}/setup/scope/{prod}/production", {"production": "true"})
    # 3. Upload a policy; drafting is enqueued.
    uploaded = post(
        client,
        f"/orgs/{org_id}/setup/upload/policy",
        files={"file": ("access_control.md", POLICY_MD)},
        follow_redirects=False,
    )
    version_id = uuid.UUID(uploaded.headers["location"].split("/")[4])
    with db_for(org_id) as db:
        document_id = db.get(DocumentVersion, version_id).document_id  # type: ignore[union-attr]
    # 4. Map it to SOC 2 and ISO 27001 controls.
    for control in ("soc2:CC6.1", "iso27001:5.15"):
        post(
            client,
            f"/orgs/{org_id}/setup/map",
            {"item": f"document:{document_id}", "control": control},
        )
    # 5. Invite the approver, who joins with their own login and MFA.
    invited = post(
        client,
        f"/orgs/{org_id}/setup/invite",
        {"email": "client-approver@example.com", "role": "approver"},
    )
    link = re.search(r"<code>(https://testserver/invitations/[^<]+)</code>", invited.text).group(1)  # type: ignore[union-attr]
    assert _resume(client, org_id) == "done"
    approver = sign_up("client-approver@example.com")
    accepted = post(approver.client, urlparse(link).path, follow_redirects=False)
    assert accepted.headers["location"] == f"/orgs/{org_id}/passport"

    # The agent drafts claims (the queued job, run with a stub model).
    [job] = [j for j in jobs.jobs.values() if j["task_name"] == "passport.agent.draft_claims"]
    assert job["args"]["document_version_id"] == str(version_id)
    with db_for(org_id) as db:
        spans = {s.text.split(" ")[0]: s.span_id for s in db.scalars(select(DocumentSpan))}
    run_drafting(
        org_id,
        version_id,
        client=StubClient([propose_turn(claim(spans["MFA"], MFA_SENTENCE)), end_turn()]),
    )
    # Unconfirmed claims are visible as such on the passport before review.
    passport = client.get(f"/orgs/{org_id}/passport").text
    assert "Not trusted" in row_html(passport, "document", document_id)

    # The approver reviews and confirms the drafted claim.
    review = approver.client.get(f"/orgs/{org_id}/versions/{version_id}/claims").text
    assert MFA_SENTENCE in review and "Unconfirmed" in review
    claim_id = re.search(r"/claims/([0-9a-f-]{36})/confirm", review).group(1)  # type: ignore[union-attr]
    post(approver.client, f"/orgs/{org_id}/claims/{claim_id}/confirm")

    # The owner re-runs checks; the job runs against a fake AWS connector.
    pressed = post(client, f"/orgs/{org_id}/checks/rerun", {"framework": "soc2"})
    assert "Queued" in pressed.text
    [run_job] = [
        j for j in jobs.jobs.values() if j["task_name"] == "passport.checks.run_org_checks"
    ]
    run_id = uuid.UUID(run_job["args"]["run_id"])
    fakes = {f"AWS account {AWS_PROD}": aws_fake()}
    run_checks_for_org(org_id, run_id, connector_factory=factory(fakes))
    with db_for(org_id) as db:
        report_id = build_report(db, org_id, run_id).id
        db.commit()

    # The first passport and report: the item has a trusted status naming the offender.
    for framework in ("soc2", "iso27001"):
        page = client.get(f"/orgs/{org_id}/passport?framework={framework}").text
        row = row_html(page, "document", document_id)
        assert "Contradicted" in row and "Trusted" in row and "bob" in row
        assert "unapproved" in row
    report = client.get(f"/orgs/{org_id}/reports/{report_id}").text
    assert "Weekly report: Client Co" in report and "Contradicted" in report
    with db_for(org_id) as db:
        assert verify_chain(db, org_id).ok
        assert db.scalar(select(func.count()).select_from(ControlMapping)) == 2
        assert db.scalar(select(func.count()).select_from(OrgFrameworkSettings)) == 2
        assert db.scalar(select(func.count()).select_from(Invitation)) == 1
        assert db.scalar(select(func.count()).select_from(Membership)) == 2
