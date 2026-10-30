import uuid

import psycopg
import pytest
from sqlalchemy import text

from passport.db.engine import get_sessionmaker
from passport.db.rls import set_org_context, set_user_context
from passport.settings import libpq_url
from tests.helpers import create_org, invite_and_join, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")


def test_consultant_sees_only_the_active_orgs_rows() -> None:
    """Covers AE5 at the membership level: X's context never yields Y's members."""
    consultant = sign_up()
    x_owner, y_owner = sign_up(), sign_up()
    org_x, org_y = create_org(x_owner, "X"), create_org(y_owner, "Y")
    invite_and_join(x_owner, org_x, consultant, "approver", external=True)
    invite_and_join(y_owner, org_y, consultant, "approver", external=True)

    with get_sessionmaker()() as db:
        set_user_context(db, consultant.user_id)
        set_org_context(db, org_x)
        orgs_seen = set(
            db.scalars(
                text("SELECT org_id FROM memberships WHERE user_id <> :me"),
                {"me": consultant.user_id},
            )
        )

    assert orgs_seen == {org_x}


def test_rls_hides_other_tenants_even_without_application_filters() -> None:
    owner_x, owner_y = sign_up(), sign_up()
    org_x, org_y = create_org(owner_x, "X"), create_org(owner_y, "Y")
    owner_y.client.post(
        f"/orgs/{org_y}/invitations", json={"email": "someone@example.com", "role": "viewer"}
    )

    with get_sessionmaker()() as db:
        set_user_context(db, owner_x.user_id)
        set_org_context(db, org_x)
        y_memberships = db.scalar(
            text("SELECT count(*) FROM memberships WHERE org_id = :y"), {"y": org_y}
        )
        y_invitations = db.scalar(text("SELECT count(*) FROM invitations"))
        y_orgs = db.scalar(text("SELECT count(*) FROM orgs WHERE id = :y"), {"y": org_y})

    assert (y_memberships, y_invitations, y_orgs) == (0, 0, 0)


def test_non_member_gets_not_found() -> None:
    owner, stranger = sign_up(), sign_up()
    org = create_org(owner)

    assert stranger.client.get(f"/orgs/{org}").status_code == 404
    assert stranger.client.get(f"/orgs/{uuid.uuid4()}").status_code == 404


def test_invitation_is_single_use() -> None:
    owner, first, second = sign_up(), sign_up(), sign_up()
    org = create_org(owner)
    token = owner.client.post(
        f"/orgs/{org}/invitations", json={"email": first.email, "role": "viewer"}
    ).json()["token"]

    assert first.client.post(f"/invitations/{token}/accept").status_code == 200
    assert second.client.post(f"/invitations/{token}/accept").status_code == 400


def test_expired_invitation_is_rejected(database_urls: dict[str, str]) -> None:
    owner, member = sign_up(), sign_up()
    org = create_org(owner)
    token = owner.client.post(
        f"/orgs/{org}/invitations", json={"email": member.email, "role": "viewer"}
    ).json()["token"]
    with psycopg.connect(libpq_url(database_urls["app"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", (str(org),))
        conn.execute("UPDATE invitations SET expires_at = now() - interval '1 minute'")

    assert member.client.post(f"/invitations/{token}/accept").status_code == 400


def test_approver_of_x_cannot_reach_y_through_their_inviter() -> None:
    consultant, approver, y_owner = sign_up(), sign_up(), sign_up()
    org_x = create_org(consultant, "X")
    org_y = create_org(y_owner, "Y")
    invite_and_join(y_owner, org_y, consultant, "owner", external=True)
    invite_and_join(consultant, org_x, approver, "approver")

    assert approver.client.get(f"/orgs/{org_x}").status_code == 200
    assert approver.client.get(f"/orgs/{org_y}").status_code == 404


def test_org_switcher_lists_exactly_the_users_memberships() -> None:
    consultant, other = sign_up(), sign_up()
    org_a, org_b = create_org(consultant, "A"), create_org(consultant, "B")
    create_org(other, "C")

    listed = {o["org_id"] for o in consultant.client.get("/orgs").json()}

    assert listed == {str(org_a), str(org_b)}


def test_scheduler_function_exposes_org_ids_only() -> None:
    owner = sign_up()
    org = create_org(owner)

    with get_sessionmaker()() as db:
        ids = list(db.scalars(text("SELECT passport_all_org_ids()")))
        with pytest.raises(Exception, match="column"):
            db.execute(text("SELECT name FROM passport_all_org_ids()"))

    assert ids == [org]
