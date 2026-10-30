"""Connections, stored credentials, disconnect, and persisted observations."""

import os
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from passport.connectors.base import Capability
from passport.connectors.fakes import FakeConnector, failure, partial, users_mfa
from passport.connectors.models import Connection, ConnectionKind, ConnectionStatus, VaultEntry
from passport.connectors.observation import FailureKind, record_result
from passport.connectors.registry import create_connection, disconnect_connection
from passport.connectors.vault import (
    LocalKeyProvider,
    Vault,
    VaultDecryptionError,
    load_secret,
)
from passport.db.engine import get_sessionmaker
from passport.db.models import Event, Observation
from passport.db.rls import set_org_context
from passport.provenance.actor import Agent, AgentNotPermittedError, Human
from passport.provenance.service import verify_chain
from tests.helpers import create_org, sign_up

pytestmark = pytest.mark.usefixtures("database_urls")

TOKEN = b'{"refresh_token": "1//secret"}'
VAULT = Vault(LocalKeyProvider(os.urandom(32)))


def _google(db: Session, org: uuid.UUID, owner: uuid.UUID) -> Connection:
    return create_connection(
        db,
        org_id=org,
        actor=Human(owner),
        kind=ConnectionKind.GOOGLE_WORKSPACE,
        display_name="example.com",
        config={"domain": "example.com"},
        secret=TOKEN,
        vault=VAULT,
    )


def test_a_connection_stores_its_secret_encrypted_and_writes_an_event() -> None:
    owner = sign_up()
    org = create_org(owner)
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        conn = _google(db, org, owner.user_id)
        db.commit()

        set_org_context(db, org)
        entry = db.scalars(select(VaultEntry)).one()
        assert TOKEN not in entry.ciphertext
        assert load_secret(db, VAULT, conn) == TOKEN
        event = db.scalars(select(Event)).one()
        assert (event.event_type, event.subject_id) == ("connection.created", str(conn.id))
        assert event.payload["credentials_stored"] is True
        assert "secret" not in str(event.payload)


def test_a_vault_entry_moved_to_another_orgs_connection_does_not_open() -> None:
    owner_x, owner_y = sign_up(), sign_up()
    org_x, org_y = create_org(owner_x, "X"), create_org(owner_y, "Y")
    with get_sessionmaker()() as db:
        set_org_context(db, org_x)
        conn_x = _google(db, org_x, owner_x.user_id)
        entry_x = db.scalars(select(VaultEntry)).one()
        stolen = (entry_x.provider, entry_x.key_id, entry_x.wrapped_key, entry_x.nonce)
        stolen_ct = entry_x.ciphertext
        assert conn_x.org_id == org_x
        db.commit()

        set_org_context(db, org_y)
        conn_y = create_connection(
            db,
            org_id=org_y,
            actor=Human(owner_y.user_id),
            kind=ConnectionKind.GOOGLE_WORKSPACE,
            display_name="y.example",
        )
        db.add(
            VaultEntry(
                org_id=org_y,
                connection_id=conn_y.id,
                provider=stolen[0],
                key_id=stolen[1],
                wrapped_key=stolen[2],
                nonce=stolen[3],
                ciphertext=stolen_ct,
            )
        )
        db.flush()
        with pytest.raises(VaultDecryptionError):
            load_secret(db, VAULT, conn_y)


def test_vault_entries_are_invisible_to_another_org() -> None:
    owner_x, owner_y = sign_up(), sign_up()
    org_x, org_y = create_org(owner_x, "X"), create_org(owner_y, "Y")
    with get_sessionmaker()() as db:
        set_org_context(db, org_x)
        _google(db, org_x, owner_x.user_id)
        db.commit()
        set_org_context(db, org_y)
        assert db.scalars(select(VaultEntry)).all() == []
        assert db.scalars(select(Connection)).all() == []


def test_disconnecting_deletes_the_vault_entry_and_writes_an_event() -> None:
    owner = sign_up()
    org = create_org(owner)
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        conn = _google(db, org, owner.user_id)
        db.commit()

        set_org_context(db, org)
        assert disconnect_connection(db, actor=Human(owner.user_id), connection=conn) is True
        db.commit()

        set_org_context(db, org)
        assert db.scalars(select(VaultEntry)).all() == []
        assert load_secret(db, VAULT, conn) is None
        refreshed = db.get(Connection, conn.id)
        assert refreshed is not None
        assert refreshed.status == ConnectionStatus.DISCONNECTED.value
        assert refreshed.disconnected_at is not None
        last = db.scalars(select(Event).order_by(Event.seq.desc())).first()
        assert last is not None
        assert last.event_type == "connection.disconnected"
        assert last.actor_user_id == owner.user_id
        assert last.payload["credentials_deleted"] is True
        # A repeat disconnect changes nothing and writes no event.
        assert disconnect_connection(db, actor=Human(owner.user_id), connection=conn) is False
        assert verify_chain(db, org).events_checked == 2


def test_the_agent_cannot_disconnect_a_connection() -> None:
    owner = sign_up()
    org = create_org(owner)
    agent = Agent(run_id=uuid.uuid4(), model_id="m", prompt_version="p")
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        conn = _google(db, org, owner.user_id)
        with pytest.raises(AgentNotPermittedError):
            disconnect_connection(db, actor=agent, connection=conn)
        assert db.scalars(select(VaultEntry)).one() is not None


def test_an_observation_is_persisted_with_its_ipe_fields_and_an_event() -> None:
    owner = sign_up()
    org = create_org(owner)
    at = datetime(2026, 10, 26, 6, tzinfo=UTC)
    fake = FakeConnector(
        ConnectionKind.AWS,
        scope=("111111111111",),
        responses={
            Capability.LIST_USERS_MFA: partial(users_mfa({"alice": True, "bob": False}), total=3)
        },
        clock=lambda: at,
    )
    result = fake.list_users_mfa()
    run = Agent(run_id=uuid.uuid4(), model_id="none", prompt_version="none")
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        conn_id = uuid.uuid4()
        row = record_result(db, org_id=org, actor=run, connection_id=conn_id, result=result)
        db.commit()

        set_org_context(db, org)
        stored = db.scalars(select(Observation)).one()
        assert stored.id == row.id
        assert (stored.outcome, stored.row_count, stored.total_count, stored.complete) == (
            "observed",
            2,
            3,
            False,
        )
        assert stored.response_sha256 == result.response_sha256
        assert stored.raw_response == result.raw_response
        assert stored.scope == ["111111111111"]
        assert stored.collector_version == "fake-1"
        assert stored.collected_at == at
        assert stored.endpoint == "fake://aws/list_users_mfa"
        assert stored.connection_id == conn_id
        event = db.scalars(select(Event)).one()
        assert event.event_type == "observation.recorded"
        assert event.payload["response_sha256"] == result.response_sha256


def test_a_failure_is_persisted_as_a_failed_outcome_with_no_rows() -> None:
    owner = sign_up()
    org = create_org(owner)
    fake = FakeConnector(
        ConnectionKind.GOOGLE_WORKSPACE,
        scope=("example.com",),
        responses={Capability.LIST_USERS_MFA: failure(FailureKind.UNAUTHORIZED, "token revoked")},
    )
    run = Agent(run_id=uuid.uuid4(), model_id="none", prompt_version="none")
    with get_sessionmaker()() as db:
        set_org_context(db, org)
        record_result(db, org_id=org, actor=run, connection_id=None, result=fake.list_users_mfa())
        db.commit()

        set_org_context(db, org)
        stored = db.scalars(select(Observation)).one()
        assert (stored.outcome, stored.row_count, stored.complete) == ("unauthorized", 0, False)
        assert stored.raw_response == {"failure": "unauthorized", "detail": "token revoked"}
        assert db.scalars(select(Event)).one().event_type == "observation.failed"
