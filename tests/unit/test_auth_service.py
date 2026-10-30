import pytest

from tests.helpers import PASSWORD, create_org, new_client, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")


def test_owner_without_totp_must_enroll_before_reaching_the_org() -> None:
    owner = sign_up(mfa=False)
    org = create_org(owner)

    response = owner.client.get(f"/orgs/{org}")

    assert response.status_code == 403
    assert response.json()["detail"] == "mfa_enrollment_required"


def test_mfa_user_must_verify_code_after_password() -> None:
    owner = sign_up()
    org = create_org(owner)
    client = new_client()
    login = client.post("/auth/login", json={"email": owner.email, "password": PASSWORD})

    assert login.json() == {"mfa_required": True}
    assert client.get(f"/orgs/{org}").json()["detail"] == "mfa_verification_required"
    assert owner.totp is not None
    assert client.post("/auth/mfa/verify", json={"code": owner.totp.now()}).status_code == 200
    assert client.get(f"/orgs/{org}").status_code == 200


def test_unknown_email_and_wrong_password_fail_identically() -> None:
    user = sign_up()
    client = new_client()

    wrong_password = client.post("/auth/login", json={"email": user.email, "password": "nope"})
    unknown_email = client.post(
        "/auth/login", json={"email": "ghost@example.com", "password": "nope"}
    )

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


def test_wrong_totp_code_is_rejected_without_detail() -> None:
    user = sign_up()
    client = new_client()
    client.post("/auth/login", json={"email": user.email, "password": PASSWORD})

    response = client.post("/auth/mfa/verify", json={"code": "000000"})

    assert response.status_code == 401
    assert response.json() == {"detail": "invalid_code"}


def test_reset_link_alone_does_not_bypass_mfa() -> None:
    from passport.auth.service import request_password_reset
    from passport.db.engine import get_sessionmaker

    user = sign_up()
    with get_sessionmaker()() as db:
        token = request_password_reset(db, email=user.email)
        db.commit()
    client = new_client()

    without_factor = client.post(
        "/auth/password-reset/complete", json={"token": token, "new_password": "new-pass-123"}
    )
    with_recovery = client.post(
        "/auth/password-reset/complete",
        json={
            "token": token,
            "new_password": "new-pass-123",
            "second_factor": user.recovery_codes[0],
        },
    )

    assert without_factor.status_code == 400
    assert with_recovery.status_code == 200
    assert (
        client.post(
            "/auth/login", json={"email": user.email, "password": "new-pass-123"}
        ).status_code
        == 200
    )


def test_recovery_code_cannot_be_reused() -> None:
    user = sign_up()
    code = user.recovery_codes[0]
    first, second = new_client(), new_client()
    for c in (first, second):
        c.post("/auth/login", json={"email": user.email, "password": PASSWORD})

    assert first.post("/auth/mfa/verify", json={"code": code}).status_code == 200
    assert second.post("/auth/mfa/verify", json={"code": code}).status_code == 401


def test_repeated_failures_lock_the_account_temporarily() -> None:
    user = sign_up()
    client = new_client()
    for _ in range(5):
        assert (
            client.post("/auth/login", json={"email": user.email, "password": "x"}).status_code
            == 401
        )

    locked = client.post("/auth/login", json={"email": user.email, "password": PASSWORD})

    assert locked.status_code == 429


def test_owner_can_reset_a_members_mfa() -> None:
    owner, member = sign_up(), sign_up()
    org = create_org(owner)
    from tests.helpers import invite_and_join

    invite_and_join(owner, org, member, "approver")

    reset = owner.client.post(f"/orgs/{org}/members/{member.user_id}/reset-mfa")

    assert reset.status_code == 200
    fresh = new_client()
    fresh.post("/auth/login", json={"email": member.email, "password": PASSWORD})
    assert fresh.get(f"/orgs/{org}").json()["detail"] == "mfa_enrollment_required"
