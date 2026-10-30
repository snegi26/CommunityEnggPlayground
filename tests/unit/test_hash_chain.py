import uuid

import psycopg
import pytest

from passport.db.engine import get_sessionmaker
from passport.db.rls import set_org_context
from passport.provenance.actor import Agent, Human
from passport.provenance.service import append_event, verify_chain
from passport.settings import libpq_url
from tests.helpers import create_org, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")


def _append(org_id: uuid.UUID, n: int, actor: Human | Agent) -> None:
    with get_sessionmaker()() as db:
        set_org_context(db, org_id)
        for i in range(n):
            append_event(
                db,
                org_id=org_id,
                actor=actor,
                event_type="test.event",
                subject_kind="thing",
                subject_id=str(i),
                payload={"i": i},
            )
        db.commit()


def _verify(org_id: uuid.UUID) -> tuple[bool, int, int | None]:
    with get_sessionmaker()() as db:
        set_org_context(db, org_id)
        result = verify_chain(db, org_id)
    return result.ok, result.events_checked, result.first_bad_seq


def test_three_events_verify_and_tampering_breaks_at_that_event(
    database_urls: dict[str, str],
) -> None:
    owner = sign_up()
    org = create_org(owner)
    _append(org, 3, Human(user_id=owner.user_id))

    assert _verify(org) == (True, 3, None)

    # The table owner can still write (the app role cannot); simulate tampering.
    with psycopg.connect(libpq_url(database_urls["owner"])) as conn:
        conn.execute("SELECT set_config('app.org_id', %s, true)", (str(org),))
        conn.execute(
            "UPDATE events SET payload = '{\"i\": 99}' WHERE org_id = %s AND seq = 2", (org,)
        )

    assert _verify(org) == (False, 2, 2)


def test_agent_actor_fields_are_part_of_the_chain() -> None:
    owner = sign_up()
    org = create_org(owner)
    _append(org, 1, Agent(run_id=uuid.uuid4(), model_id="m-1", prompt_version="draft_v1"))

    assert _verify(org) == (True, 1, None)


@pytest.mark.parametrize("statement", ["UPDATE events SET seq = seq", "DELETE FROM events"])
def test_app_role_cannot_rewrite_events(database_urls: dict[str, str], statement: str) -> None:
    with (
        psycopg.connect(libpq_url(database_urls["app"])) as conn,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        conn.execute(statement)


def test_concurrent_appends_form_one_linear_chain() -> None:
    from concurrent.futures import ThreadPoolExecutor

    owner = sign_up()
    org = create_org(owner)
    actor = Human(user_id=owner.user_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: _append(org, 10, actor), range(2)))

    assert _verify(org) == (True, 20, None)


def test_chains_are_independent_per_org() -> None:
    owner_x, owner_y = sign_up(), sign_up()
    org_x, org_y = create_org(owner_x, "X"), create_org(owner_y, "Y")
    _append(org_x, 2, Human(user_id=owner_x.user_id))
    _append(org_y, 1, Human(user_id=owner_y.user_id))

    with get_sessionmaker()() as db:
        set_org_context(db, org_y)
        from sqlalchemy import select

        from passport.db.models import Event

        y_prev_hashes = set(db.scalars(select(Event.prev_hash)))
        set_org_context(db, org_x)
        x_hashes = set(db.scalars(select(Event.hash)))

    assert y_prev_hashes.isdisjoint(x_hashes)
    assert _verify(org_x) == (True, 2, None)
    assert _verify(org_y) == (True, 1, None)
