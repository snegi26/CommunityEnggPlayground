"""Append-only, per-org hash-chained event log (KTD8).

Each event's hash covers the previous event's hash plus a canonical encoding of the
event, so editing any stored event breaks verification from that event onward.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from passport.db.base import utcnow
from passport.db.models import ChainHead, Event
from passport.provenance.actor import Actor, Agent, Human

GENESIS_HASH = "0" * 64


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _actor_fields(actor: Actor) -> dict[str, Any]:
    if isinstance(actor, Human):
        return {
            "actor_kind": "human",
            "actor_user_id": actor.user_id,
            "on_behalf_of_org": actor.on_behalf_of_org,
            "agent_run_id": None,
            "model_id": None,
            "prompt_version": None,
        }
    assert isinstance(actor, Agent)
    return {
        "actor_kind": "agent",
        "actor_user_id": None,
        "on_behalf_of_org": False,
        "agent_run_id": actor.run_id,
        "model_id": actor.model_id,
        "prompt_version": actor.prompt_version,
    }


def _event_digest(event: Event) -> str:
    body = {
        "seq": event.seq,
        "event_type": event.event_type,
        "subject_kind": event.subject_kind,
        "subject_id": event.subject_id,
        "actor_kind": event.actor_kind,
        "actor_user_id": event.actor_user_id,
        "on_behalf_of_org": event.on_behalf_of_org,
        "agent_run_id": event.agent_run_id,
        "model_id": event.model_id,
        "prompt_version": event.prompt_version,
        "payload_hash": event.payload_hash,
        "created_at": event.created_at.isoformat(),
    }
    return sha256_hex(event.prev_hash.encode() + canonical(body))


def append_event(
    session: Session,
    *,
    org_id: uuid.UUID,
    actor: Actor,
    event_type: str,
    subject_kind: str,
    subject_id: uuid.UUID | str,
    payload: dict[str, Any] | None = None,
) -> Event:
    """Append one event, serialized per org by a row lock on the chain head."""
    session.execute(
        insert(ChainHead)
        .values(org_id=org_id, seq=0, hash=GENESIS_HASH)
        .on_conflict_do_nothing(index_elements=["org_id"])
    )
    head = session.scalars(
        select(ChainHead).where(ChainHead.org_id == org_id).with_for_update()
    ).one()
    body = payload or {}
    event = Event(
        org_id=org_id,
        seq=head.seq + 1,
        event_type=event_type,
        subject_kind=subject_kind,
        subject_id=str(subject_id),
        payload=body,
        payload_hash=sha256_hex(canonical(body)),
        prev_hash=head.hash,
        created_at=utcnow(),
        **_actor_fields(actor),
    )
    event.hash = _event_digest(event)
    session.add(event)
    head.seq = event.seq
    head.hash = event.hash
    session.flush()
    return event


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    events_checked: int
    first_bad_seq: int | None = None


def verify_chain(session: Session, org_id: uuid.UUID) -> ChainVerification:
    prev = GENESIS_HASH
    count = 0
    for event in session.scalars(select(Event).where(Event.org_id == org_id).order_by(Event.seq)):
        count += 1
        if (
            event.seq != count
            or event.prev_hash != prev
            or event.payload_hash != sha256_hex(canonical(event.payload))
            or event.hash != _event_digest(event)
        ):
            return ChainVerification(ok=False, events_checked=count, first_bad_seq=event.seq)
        prev = event.hash
    head = session.get(ChainHead, org_id)
    if head is not None and (head.seq != count or head.hash != prev):
        return ChainVerification(ok=False, events_checked=count, first_bad_seq=count + 1)
    return ChainVerification(ok=True, events_checked=count)
