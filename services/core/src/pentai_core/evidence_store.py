from __future__ import annotations

import hashlib
import os
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_MAGIC = b"PENTAI-EVIDENCE-ORIGINAL-V1\x00"
_NONCE_SIZE = 12


class EvidenceStoreError(RuntimeError):
    pass


class EncryptedEvidenceStore:
    """Content-addressed evidence originals under a domain-separated key."""

    def __init__(self, root: Path, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise ValueError("evidence master key must contain 32 bytes")
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"pentai-local-evidence-v1",
            info=b"immutable-originals",
        ).derive(master_key)
        self.root = root
        self._cipher = AESGCM(key)

    def _path(self, digest: str) -> Path:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise EvidenceStoreError("evidence digest is invalid")
        return self.root / digest[:2] / f"{digest}.blob"

    def store(self, content: bytes, digest: str) -> str:
        if hashlib.sha256(content).hexdigest() != digest:
            raise EvidenceStoreError("evidence content digest does not match metadata")
        destination = self._path(digest)
        if destination.exists():
            if self.load(digest) != content:
                raise EvidenceStoreError("existing evidence blob does not match metadata")
            return f"encrypted-evidence:v1:{digest}"
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
            directory = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise EvidenceStoreError("encrypted evidence could not be persisted") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        return f"encrypted-evidence:v1:{digest}"

    def load(self, digest: str) -> bytes:
        try:
            payload = self._path(digest).read_bytes()
        except OSError as exc:
            raise EvidenceStoreError("encrypted evidence is unavailable") from exc
        if not payload.startswith(_MAGIC) or len(payload) <= len(_MAGIC) + _NONCE_SIZE:
            raise EvidenceStoreError("encrypted evidence format is invalid")
        start = len(_MAGIC)
        nonce = payload[start : start + _NONCE_SIZE]
        try:
            content = self._cipher.decrypt(
                nonce, payload[start + _NONCE_SIZE :], digest.encode("ascii")
            )
        except InvalidTag as exc:
            raise EvidenceStoreError("encrypted evidence authentication failed") from exc
        if hashlib.sha256(content).hexdigest() != digest:
            raise EvidenceStoreError("decrypted evidence digest does not match metadata")
        return content

    def delete(self, digest: str) -> bool:
        path = self._path(digest)
        try:
            if not path.exists():
                return False
            path.unlink()
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            raise EvidenceStoreError("encrypted evidence could not be deleted") from exc
        return True
