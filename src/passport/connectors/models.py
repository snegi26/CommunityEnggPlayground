"""Connection and credential vault tables. Both are org-scoped and RLS-isolated."""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, LargeBinary, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from passport.db.base import Base, CreatedAtMixin, IdMixin
from passport.db.models import OrgScoped


class ConnectionKind(enum.StrEnum):
    AWS = "aws"
    GOOGLE_WORKSPACE = "google_workspace"
    GITHUB = "github"


class ConnectionStatus(enum.StrEnum):
    ACTIVE = "active"
    DISCONNECTED = "disconnected"


class Connection(IdMixin, CreatedAtMixin, OrgScoped, Base):
    """One read-only link from an org to a provider account (R5).

    ``config`` holds only non-secret identifiers (role ARN, external id, installation
    id, domain). Secrets live in ``vault_entries``, envelope-encrypted (KTD6).
    """

    __tablename__ = "connections"

    kind: Mapped[str] = mapped_column(String(30))
    display_name: Mapped[str] = mapped_column(String(200))
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(20), default=ConnectionStatus.ACTIVE.value)
    disconnected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class VaultEntry(IdMixin, CreatedAtMixin, OrgScoped, Base):
    """A connection's secret: ciphertext plus the data key wrapped by the key provider."""

    __tablename__ = "vault_entries"

    connection_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("connections.id", ondelete="CASCADE"), unique=True
    )
    provider: Mapped[str] = mapped_column(String(20))
    key_id: Mapped[str] = mapped_column(String(300))
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
