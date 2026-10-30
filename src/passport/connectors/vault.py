"""Envelope-encrypted connector credentials (KTD6).

Each secret gets a fresh 256-bit data key. The secret is sealed with AES-GCM under
that key, and the data key is wrapped by a :class:`KeyProvider`: AWS KMS in
production, or a local master key in development and tests. Both bind the org id
and connection id: KMS as its ``EncryptionContext``, AES-GCM as associated data on
both the wrap and the seal, so ciphertext stored for one tenant's connection cannot
be opened under another's.
"""

import base64
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal, Protocol

from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from passport.connectors.models import Connection, VaultEntry
from passport.provenance.service import canonical

NONCE_BYTES = 12
KEY_BYTES = 32


class VaultSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VAULT_", env_file=".env", extra="ignore")

    provider: Literal["local", "aws_kms"] = "local"
    # Base64 of 32 random bytes; the local provider's key-encryption key. No default, so a
    # deploy can never encrypt real tokens under a key that ships in the source (KTD6).
    local_master_key: str | None = None
    kms_key_id: str | None = None
    aws_region: str | None = None

    def master_key_bytes(self) -> bytes:
        if self.local_master_key is None:
            raise ValueError(
                "VAULT_LOCAL_MASTER_KEY must be set for the local provider; "
                "production uses VAULT_PROVIDER=aws_kms"
            )
        key = base64.b64decode(self.local_master_key)
        if len(key) != KEY_BYTES:
            raise ValueError("VAULT_LOCAL_MASTER_KEY must decode to 32 bytes")
        return key


class VaultDecryptionError(Exception):
    """The secret could not be opened: wrong org, connection, key, or tampered data."""


def encryption_context(org_id: uuid.UUID, connection_id: uuid.UUID) -> dict[str, str]:
    return {"org_id": str(org_id), "connection_id": str(connection_id)}


@dataclass(frozen=True)
class DataKey:
    plaintext: bytes
    wrapped: bytes
    key_id: str


class KeyProvider(Protocol):
    name: str

    def generate_data_key(self, context: Mapping[str, str]) -> DataKey: ...

    def decrypt_data_key(self, wrapped: bytes, key_id: str, context: Mapping[str, str]) -> bytes:
        """Unwrap a data key; raise :class:`VaultDecryptionError` on a context mismatch."""
        ...


class LocalKeyProvider:
    """Wraps data keys with a local AES-GCM master key, binding the context as AAD."""

    name = "local"
    key_id = "local"

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != KEY_BYTES:
            raise ValueError("local master key must be 32 bytes")
        self._master = AESGCM(master_key)

    def generate_data_key(self, context: Mapping[str, str]) -> DataKey:
        plaintext = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(NONCE_BYTES)
        wrapped = nonce + self._master.encrypt(nonce, plaintext, canonical(dict(context)))
        return DataKey(plaintext=plaintext, wrapped=wrapped, key_id=self.key_id)

    def decrypt_data_key(self, wrapped: bytes, key_id: str, context: Mapping[str, str]) -> bytes:
        nonce, body = wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:]
        try:
            return self._master.decrypt(nonce, body, canonical(dict(context)))
        except InvalidTag as exc:
            raise VaultDecryptionError("data key does not open under this context") from exc


class KmsClient(Protocol):
    """The two KMS calls the vault uses (a boto3 ``kms`` client satisfies this)."""

    def generate_data_key(
        self, *, KeyId: str, KeySpec: str, EncryptionContext: Mapping[str, str]
    ) -> Mapping[str, Any]: ...

    def decrypt(
        self, *, CiphertextBlob: bytes, KeyId: str, EncryptionContext: Mapping[str, str]
    ) -> Mapping[str, Any]: ...


class KmsKeyProvider:
    """Generates and unwraps data keys with AWS KMS under the org+connection context."""

    name = "aws_kms"

    def __init__(self, client: KmsClient, key_id: str) -> None:
        self._client = client
        self.key_id = key_id

    def generate_data_key(self, context: Mapping[str, str]) -> DataKey:
        response = self._client.generate_data_key(
            KeyId=self.key_id, KeySpec="AES_256", EncryptionContext=dict(context)
        )
        return DataKey(
            plaintext=bytes(response["Plaintext"]),
            wrapped=bytes(response["CiphertextBlob"]),
            key_id=self.key_id,
        )

    def decrypt_data_key(self, wrapped: bytes, key_id: str, context: Mapping[str, str]) -> bytes:
        try:
            response = self._client.decrypt(
                CiphertextBlob=wrapped, KeyId=key_id, EncryptionContext=dict(context)
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidCiphertextException":
                raise VaultDecryptionError("KMS refused the data key for this context") from exc
            raise
        return bytes(response["Plaintext"])


@dataclass(frozen=True)
class SealedSecret:
    provider: str
    key_id: str
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes


class Vault:
    def __init__(self, provider: KeyProvider) -> None:
        self.provider = provider

    def seal(
        self, plaintext: bytes, *, org_id: uuid.UUID, connection_id: uuid.UUID
    ) -> SealedSecret:
        context = encryption_context(org_id, connection_id)
        data_key = self.provider.generate_data_key(context)
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(data_key.plaintext).encrypt(nonce, plaintext, canonical(context))
        return SealedSecret(
            provider=self.provider.name,
            key_id=data_key.key_id,
            wrapped_key=data_key.wrapped,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def open(self, sealed: SealedSecret, *, org_id: uuid.UUID, connection_id: uuid.UUID) -> bytes:
        if sealed.provider != self.provider.name:
            raise VaultDecryptionError(
                f"secret was sealed by {sealed.provider}, vault uses {self.provider.name}"
            )
        context = encryption_context(org_id, connection_id)
        data_key = self.provider.decrypt_data_key(sealed.wrapped_key, sealed.key_id, context)
        try:
            return AESGCM(data_key).decrypt(sealed.nonce, sealed.ciphertext, canonical(context))
        except InvalidTag as exc:
            raise VaultDecryptionError("secret does not open under this context") from exc


def build_vault(settings: VaultSettings) -> Vault:
    if settings.provider == "aws_kms":
        if not settings.kms_key_id:
            raise ValueError("VAULT_KMS_KEY_ID is required for the aws_kms provider")
        import boto3

        client: KmsClient = boto3.client("kms", region_name=settings.aws_region)
        return Vault(KmsKeyProvider(client, settings.kms_key_id))
    return Vault(LocalKeyProvider(settings.master_key_bytes()))


@lru_cache
def get_vault() -> Vault:
    return build_vault(VaultSettings())


# --- Storage -------------------------------------------------------------------------


def store_secret(session: Session, vault: Vault, connection: Connection, plaintext: bytes) -> None:
    """Seal ``plaintext`` for ``connection`` and store it, replacing any earlier secret."""
    sealed = vault.seal(plaintext, org_id=connection.org_id, connection_id=connection.id)
    delete_secret(session, connection)
    session.add(
        VaultEntry(
            org_id=connection.org_id,
            connection_id=connection.id,
            provider=sealed.provider,
            key_id=sealed.key_id,
            wrapped_key=sealed.wrapped_key,
            nonce=sealed.nonce,
            ciphertext=sealed.ciphertext,
        )
    )
    session.flush()


def load_secret(session: Session, vault: Vault, connection: Connection) -> bytes | None:
    """Open ``connection``'s secret under its own org and id; None when none is stored."""
    entry = session.scalars(
        select(VaultEntry).where(VaultEntry.connection_id == connection.id)
    ).one_or_none()
    if entry is None:
        return None
    sealed = SealedSecret(
        provider=entry.provider,
        key_id=entry.key_id,
        wrapped_key=entry.wrapped_key,
        nonce=entry.nonce,
        ciphertext=entry.ciphertext,
    )
    return vault.open(sealed, org_id=connection.org_id, connection_id=connection.id)


def delete_secret(session: Session, connection: Connection) -> bool:
    """Delete ``connection``'s stored secret; True when one existed."""
    result = session.execute(
        delete(VaultEntry).where(VaultEntry.connection_id == connection.id).returning(VaultEntry.id)
    )
    deleted = result.first() is not None
    session.flush()
    return deleted
