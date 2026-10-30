"""Object storage for uploaded files, keyed by org and content hash.

Production will use S3; dev and tests use a local directory. Both satisfy ``ObjectStorage``,
so callers depend only on ``put`` and ``get``.
"""

import hashlib
import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Protocol

from passport.settings import get_settings

_KEY = re.compile(r"^[0-9a-f-]{36}/[0-9a-f]{64}$")


class ObjectStorage(Protocol):
    def put(self, org_id: uuid.UUID, data: bytes) -> str:
        """Store ``data`` and return its key (``<org id>/<sha256>``)."""
        ...

    def get(self, key: str) -> bytes: ...


def storage_key(org_id: uuid.UUID, data: bytes) -> str:
    return f"{org_id}/{hashlib.sha256(data).hexdigest()}"


class LocalDirectoryStorage:
    """Content-addressed files under ``root``; identical uploads share one file."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, key: str) -> Path:
        if not _KEY.match(key):
            raise ValueError(f"invalid storage key: {key!r}")
        return self.root / key

    def put(self, org_id: uuid.UUID, data: bytes) -> str:
        key = storage_key(org_id, data)
        path = self._path(key)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=path.parent)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(tmp, path)
        return key

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()


def get_storage() -> ObjectStorage:
    return LocalDirectoryStorage(Path(get_settings().storage_dir))
