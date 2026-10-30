"""Envelope encryption of connector credentials (KTD6)."""

import base64
import os
import uuid
from typing import Any

import pytest
from botocore.exceptions import ClientError

from passport.connectors.vault import (
    KmsKeyProvider,
    LocalKeyProvider,
    Vault,
    VaultDecryptionError,
    VaultSettings,
    encryption_context,
)

SECRET = b'{"refresh_token": "1//0g-very-secret"}'


def _local_vault(master: bytes | None = None) -> Vault:
    return Vault(LocalKeyProvider(master or os.urandom(32)))


def test_a_sealed_secret_opens_under_the_same_org_and_connection() -> None:
    vault = _local_vault()
    org, conn = uuid.uuid4(), uuid.uuid4()

    sealed = vault.seal(SECRET, org_id=org, connection_id=conn)

    assert vault.open(sealed, org_id=org, connection_id=conn) == SECRET
    assert SECRET not in sealed.ciphertext
    assert SECRET not in sealed.wrapped_key


def test_a_secret_encrypted_for_org_x_fails_to_decrypt_under_org_y_context() -> None:
    vault = _local_vault()
    org_x, org_y, conn = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    sealed = vault.seal(SECRET, org_id=org_x, connection_id=conn)

    with pytest.raises(VaultDecryptionError):
        vault.open(sealed, org_id=org_y, connection_id=conn)


def test_a_secret_fails_to_decrypt_under_another_connection_of_the_same_org() -> None:
    vault = _local_vault()
    org = uuid.uuid4()
    sealed = vault.seal(SECRET, org_id=org, connection_id=uuid.uuid4())

    with pytest.raises(VaultDecryptionError):
        vault.open(sealed, org_id=org, connection_id=uuid.uuid4())


def test_a_secret_fails_to_decrypt_under_a_different_master_key() -> None:
    org, conn = uuid.uuid4(), uuid.uuid4()
    sealed = _local_vault().seal(SECRET, org_id=org, connection_id=conn)

    with pytest.raises(VaultDecryptionError):
        _local_vault().open(sealed, org_id=org, connection_id=conn)


def test_each_seal_uses_a_fresh_data_key() -> None:
    vault = _local_vault()
    org, conn = uuid.uuid4(), uuid.uuid4()
    first = vault.seal(SECRET, org_id=org, connection_id=conn)
    second = vault.seal(SECRET, org_id=org, connection_id=conn)
    assert first.wrapped_key != second.wrapped_key
    assert first.ciphertext != second.ciphertext


class FakeKms:
    """Stands in for AWS KMS: a data key only decrypts under the context it was made with."""

    def __init__(self) -> None:
        self.keys: dict[bytes, tuple[bytes, dict[str, str]]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def generate_data_key(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("generate_data_key", kwargs))
        plaintext, blob = os.urandom(32), os.urandom(48)
        self.keys[blob] = (plaintext, dict(kwargs["EncryptionContext"]))
        return {"Plaintext": plaintext, "CiphertextBlob": blob, "KeyId": kwargs["KeyId"]}

    def decrypt(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("decrypt", kwargs))
        plaintext, context = self.keys[kwargs["CiphertextBlob"]]
        if context != kwargs.get("EncryptionContext"):
            raise ClientError(
                {"Error": {"Code": "InvalidCiphertextException", "Message": ""}}, "Decrypt"
            )
        return {"Plaintext": plaintext, "KeyId": kwargs["KeyId"]}


def test_kms_provider_binds_org_and_connection_as_encryption_context() -> None:
    kms = FakeKms()
    vault = Vault(KmsKeyProvider(kms, key_id="arn:aws:kms:eu-west-1:111:key/abc"))
    org, conn = uuid.uuid4(), uuid.uuid4()

    sealed = vault.seal(SECRET, org_id=org, connection_id=conn)

    assert vault.open(sealed, org_id=org, connection_id=conn) == SECRET
    expected = {"org_id": str(org), "connection_id": str(conn)}
    assert [c[1]["EncryptionContext"] for c in kms.calls] == [expected, expected]
    assert kms.calls[0][1]["KeySpec"] == "AES_256"
    assert sealed.provider == "aws_kms"
    assert sealed.key_id == "arn:aws:kms:eu-west-1:111:key/abc"


def test_kms_sealed_secret_fails_under_another_orgs_context() -> None:
    vault = Vault(KmsKeyProvider(FakeKms(), key_id="k"))
    org_x, org_y, conn = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    sealed = vault.seal(SECRET, org_id=org_x, connection_id=conn)

    with pytest.raises(VaultDecryptionError):
        vault.open(sealed, org_id=org_y, connection_id=conn)


def test_a_secret_sealed_by_one_provider_is_refused_by_another() -> None:
    org, conn = uuid.uuid4(), uuid.uuid4()
    sealed = Vault(KmsKeyProvider(FakeKms(), key_id="k")).seal(
        SECRET, org_id=org, connection_id=conn
    )
    with pytest.raises(VaultDecryptionError):
        _local_vault().open(sealed, org_id=org, connection_id=conn)


def test_encryption_context_names_org_and_connection() -> None:
    org, conn = uuid.uuid4(), uuid.uuid4()
    assert encryption_context(org, conn) == {"org_id": str(org), "connection_id": str(conn)}


def test_vault_settings_read_the_vault_env_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    key = os.urandom(32)
    monkeypatch.setenv("VAULT_LOCAL_MASTER_KEY", base64.b64encode(key).decode())
    monkeypatch.setenv("VAULT_PROVIDER", "local")
    settings = VaultSettings()
    assert settings.provider == "local"
    assert settings.master_key_bytes() == key


def test_vault_settings_reject_a_master_key_of_the_wrong_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VAULT_LOCAL_MASTER_KEY", base64.b64encode(b"short").decode())
    with pytest.raises(ValueError, match="32 bytes"):
        VaultSettings().master_key_bytes()


def test_local_provider_refuses_to_run_without_a_configured_master_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from passport.connectors.vault import VaultSettings

    monkeypatch.delenv("VAULT_LOCAL_MASTER_KEY", raising=False)

    with pytest.raises(ValueError, match="VAULT_LOCAL_MASTER_KEY must be set"):
        VaultSettings(_env_file=None).master_key_bytes()  # type: ignore[call-arg]
