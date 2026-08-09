from __future__ import annotations

import hashlib
from base64 import urlsafe_b64decode, urlsafe_b64encode

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class PolicySigner:
    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("policy signing seed must contain 32 bytes")
        self._private_key = Ed25519PrivateKey.from_private_bytes(seed)
        public_key = self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = "ed25519:" + hashlib.sha256(public_key).hexdigest()

    def sign(self, payload: bytes) -> str:
        return urlsafe_b64encode(self._private_key.sign(payload)).rstrip(b"=").decode("ascii")

    def verify(self, payload: bytes, signature: str, key_id: str) -> bool:
        if key_id != self.key_id:
            return False
        try:
            encoded = signature.encode("ascii")
            decoded = urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
            self._private_key.public_key().verify(decoded, payload)
        except (InvalidSignature, ValueError, UnicodeEncodeError):
            return False
        return True
