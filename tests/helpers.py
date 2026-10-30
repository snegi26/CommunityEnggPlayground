"""Test helpers for signing users in through the real HTTP endpoints."""

import uuid
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import pyotp
from fastapi.testclient import TestClient

from passport.app import create_app

PASSWORD = "correct horse battery staple"


def new_client() -> TestClient:
    # Session cookies are Secure, so the client must speak https.
    return TestClient(create_app(), base_url="https://testserver")


@dataclass
class SignedInUser:
    client: TestClient
    email: str
    user_id: uuid.UUID
    totp: pyotp.TOTP | None
    recovery_codes: list[str]


def sign_up(email: str | None = None, *, mfa: bool = True) -> SignedInUser:
    email = email or f"{uuid.uuid4().hex[:8]}@example.com"
    client = new_client()
    created = client.post(
        "/auth/register", json={"email": email, "name": email, "password": PASSWORD}
    )
    assert created.status_code == 201, created.text
    assert (
        client.post("/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200
    )
    totp, codes = None, []
    if mfa:
        uri = client.post("/auth/mfa/enroll").json()["provisioning_uri"]
        secret = parse_qs(urlparse(uri).query)["secret"][0]
        totp = pyotp.TOTP(secret)
        codes = client.post("/auth/mfa/confirm", json={"code": totp.now()}).json()["recovery_codes"]
    return SignedInUser(
        client=client,
        email=email,
        user_id=uuid.UUID(created.json()["user_id"]),
        totp=totp,
        recovery_codes=codes,
    )


def create_org(owner: SignedInUser, name: str = "Acme") -> uuid.UUID:
    response = owner.client.post("/orgs", json={"name": name})
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["org_id"])


def invite_and_join(
    owner: SignedInUser,
    org_id: uuid.UUID,
    member: SignedInUser,
    role: str,
    *,
    external: bool = False,
) -> None:
    token = owner.client.post(
        f"/orgs/{org_id}/invitations",
        json={"email": member.email, "role": role, "external": external},
    ).json()["token"]
    accepted = member.client.post(f"/invitations/{token}/accept")
    assert accepted.status_code == 200, accepted.text
