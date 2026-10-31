"""Which connection kind serves which capability, and the connection lifecycle.

Each kind declares the capabilities it serves; a connector class registered for a
kind must implement every one of them. Connections are created and disconnected
here, each change written as a provenance event (KTD8).
"""

import uuid
from collections.abc import Mapping
from typing import Any

from sqlalchemy.orm import Session

from passport.connectors.base import Capability, Connector, implements
from passport.connectors.models import Connection, ConnectionKind, ConnectionStatus
from passport.connectors.vault import Vault, delete_secret, store_secret
from passport.db.base import utcnow
from passport.provenance.actor import Actor, require_human
from passport.provenance.service import append_event

KIND_CAPABILITIES: Mapping[ConnectionKind, frozenset[Capability]] = {
    ConnectionKind.AWS: frozenset(
        {
            Capability.LIST_ACCOUNTS,
            Capability.LIST_USERS_MFA,
            Capability.GET_ROOT_MFA,
            Capability.GET_PASSWORD_POLICY,
            Capability.LIST_CLOUDTRAIL_TRAILS,
            Capability.LIST_S3_BUCKET_ENCRYPTION,
            Capability.GET_S3_PUBLIC_ACCESS_BLOCK,
        }
    ),
    ConnectionKind.GOOGLE_WORKSPACE: frozenset({Capability.LIST_USERS_MFA}),
    ConnectionKind.GITHUB: frozenset(
        {
            Capability.GET_ORG_TWO_FACTOR_REQUIREMENT,
            Capability.LIST_ORG_MEMBERS,
            Capability.GET_BRANCH_PROTECTION,
        }
    ),
}


class RegistryError(Exception):
    pass


def capabilities_for(kind: ConnectionKind) -> frozenset[Capability]:
    return KIND_CAPABILITIES[ConnectionKind(kind)]


def kinds_serving(capability: Capability) -> tuple[ConnectionKind, ...]:
    """Connection kinds able to serve ``capability``, in declaration order."""
    return tuple(kind for kind, caps in KIND_CAPABILITIES.items() if capability in caps)


class ConnectorRegistry:
    """Maps a connection kind to the connector class that reads it."""

    def __init__(self) -> None:
        self._classes: dict[ConnectionKind, type[Connector]] = {}

    def register[C: type[Connector]](self, cls: C) -> C:
        kind = ConnectionKind(cls.kind)
        if kind in self._classes:
            raise RegistryError(f"a connector is already registered for {kind}")
        missing = sorted(c.value for c in capabilities_for(kind) if not implements(cls, c))
        if missing:
            raise RegistryError(f"{cls.__name__} does not implement {', '.join(missing)}")
        self._classes[kind] = cls
        return cls

    def connector_class(self, kind: ConnectionKind) -> type[Connector]:
        try:
            return self._classes[ConnectionKind(kind)]
        except KeyError:
            raise RegistryError(f"no connector registered for {kind}") from None


# Live connectors register themselves here.
registry = ConnectorRegistry()


def create_connection(
    session: Session,
    *,
    org_id: uuid.UUID,
    actor: Actor,
    kind: ConnectionKind,
    display_name: str,
    config: dict[str, Any] | None = None,
    secret: bytes | None = None,
    vault: Vault | None = None,
) -> Connection:
    """Create a connection; ``config`` is non-secret, ``secret`` goes to the vault."""
    human = require_human(actor)
    connection = Connection(
        org_id=org_id,
        kind=ConnectionKind(kind).value,
        display_name=display_name,
        config=config or {},
        status=ConnectionStatus.ACTIVE.value,
    )
    session.add(connection)
    session.flush()
    if secret is not None:
        if vault is None:
            raise ValueError("a vault is required to store a connection secret")
        store_secret(session, vault, connection, secret)
    append_event(
        session,
        org_id=org_id,
        actor=human,
        event_type="connection.created",
        subject_kind="connection",
        subject_id=connection.id,
        payload={
            "kind": connection.kind,
            "display_name": display_name,
            "config": connection.config,
            "credentials_stored": secret is not None,
        },
    )
    return connection


def disconnect_connection(session: Session, *, actor: Actor, connection: Connection) -> bool:
    """Disconnect: delete the stored secret, mark the connection, and record an event.

    Returns False, writing nothing, when the connection is already disconnected.
    Claims that depended on it then have no serving connection (not checkable).
    """
    human = require_human(actor)
    if connection.status == ConnectionStatus.DISCONNECTED.value:
        return False
    credentials_deleted = delete_secret(session, connection)
    connection.status = ConnectionStatus.DISCONNECTED.value
    connection.disconnected_at = utcnow()
    session.flush()
    append_event(
        session,
        org_id=connection.org_id,
        actor=human,
        event_type="connection.disconnected",
        subject_kind="connection",
        subject_id=connection.id,
        payload={
            "kind": connection.kind,
            "display_name": connection.display_name,
            "credentials_deleted": credentials_deleted,
        },
    )
    return True
