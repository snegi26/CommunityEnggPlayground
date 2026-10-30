import uuid

import pytest
from sqlalchemy import func, select

from passport.auth.models import User
from passport.auth.service import reset_member_mfa
from passport.db.engine import get_sessionmaker
from passport.db.models import Event
from passport.db.rls import set_org_context
from passport.provenance.actor import Agent, AgentNotPermittedError
from tests.helpers import create_org, invite_and_join, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")


def test_agent_cannot_perform_a_human_only_operation_and_nothing_is_recorded() -> None:
    owner, member = sign_up(), sign_up()
    org = create_org(owner)
    invite_and_join(owner, org, member, "approver")
    agent = Agent(run_id=uuid.uuid4(), model_id="m", prompt_version="p")

    with get_sessionmaker()() as db:
        set_org_context(db, org)
        target = db.get(User, member.user_id)
        assert target is not None
        with pytest.raises(AgentNotPermittedError):
            reset_member_mfa(db, actor=agent, org_id=org, target=target)
        db.rollback()
        set_org_context(db, org)
        events = db.scalar(select(func.count()).select_from(Event))

    assert events == 0


def test_owner_mfa_reset_writes_an_event_naming_the_owner() -> None:
    owner, member = sign_up(), sign_up()
    org = create_org(owner)
    invite_and_join(owner, org, member, "approver")

    owner.client.post(f"/orgs/{org}/members/{member.user_id}/reset-mfa")

    with get_sessionmaker()() as db:
        set_org_context(db, org)
        event = db.scalars(select(Event)).one()
    assert (event.event_type, event.actor_user_id, event.subject_id) == (
        "member.mfa_reset",
        owner.user_id,
        str(member.user_id),
    )
