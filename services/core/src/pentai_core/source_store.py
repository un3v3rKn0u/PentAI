from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_MAGIC = b"PENTAI-SOURCE-BLOB-V1\x00"
_NONCE_SIZE = 12


class SourceStoreError(RuntimeError):
    pass


class EncryptedSourceStore:
    def __init__(
        self, root: Path, key: bytes, *, failure_handler: Callable[[], None] | None = None
    ) -> None:
        if len(key) != 32:
            raise ValueError("source encryption key must contain 32 bytes")
        self.root = root
        self._cipher = AESGCM(key)
        self._failure_handler = failure_handler

    def _path(self, digest: str) -> Path:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise SourceStoreError("source digest is invalid")
        return self.root / digest[:2] / f"{digest}.blob"

    def store(self, content: bytes, digest: str) -> str:
        actual = hashlib.sha256(content).hexdigest()
        if actual != digest:
            raise SourceStoreError("source content digest does not match provenance")
        destination = self._path(digest)
        if destination.exists():
            if self.load(digest) != content:
                raise SourceStoreError("existing source blob does not match provenance")
            return f"encrypted-source:v1:{digest}"

        nonce = os.urandom(_NONCE_SIZE)
        payload = _MAGIC + nonce + self._cipher.encrypt(nonce, content, digest.encode("ascii"))
        temporary = destination.parent / f".{digest}.{uuid4().hex}.tmp"
        descriptor: int | None = None
        try:
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            directory_descriptor = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError as exc:
            if self._failure_handler is not None:
                self._failure_handler()
            raise SourceStoreError("encrypted source blob could not be persisted") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        return f"encrypted-source:v1:{digest}"

    def load(self, digest: str) -> bytes:
        path = self._path(digest)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise SourceStoreError("encrypted source blob is unavailable") from exc
        if not payload.startswith(_MAGIC) or len(payload) <= len(_MAGIC) + _NONCE_SIZE:
            raise SourceStoreError("encrypted source blob format is invalid")
        nonce_start = len(_MAGIC)
        nonce = payload[nonce_start : nonce_start + _NONCE_SIZE]
        ciphertext = payload[nonce_start + _NONCE_SIZE :]
        try:
            content = self._cipher.decrypt(nonce, ciphertext, digest.encode("ascii"))
        except InvalidTag as exc:
            raise SourceStoreError("encrypted source blob authentication failed") from exc
        if hashlib.sha256(content).hexdigest() != digest:
            raise SourceStoreError("decrypted source blob digest does not match provenance")
        return content
