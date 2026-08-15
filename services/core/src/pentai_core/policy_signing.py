from __future__ import annotations

import hashlib
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pentai_policy import canonical_json


def gateway_fixture_execution_claim_v2_payload(document: dict[str, Any]) -> bytes:
    """Return the domain-separated canonical payload for a signed v2 fixture claim."""
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    return b"pentai-gateway-fixture-execution-claim-v2:" + canonical_json(unsigned).encode()


class PolicySigner:
    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("policy signing seed must contain 32 bytes")
        self._private_key = Ed25519PrivateKey.from_private_bytes(seed)
        public_key = self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._verifier = PolicyVerifier(public_key)
        self.key_id = self._verifier.key_id

    def sign(self, payload: bytes) -> str:
        return urlsafe_b64encode(self._private_key.sign(payload)).rstrip(b"=").decode("ascii")

    def verify(self, payload: bytes, signature: str, key_id: str) -> bool:
        return self._verifier.verify(payload, signature, key_id)

    def verifier(self) -> PolicyVerifier:
        return self._verifier


class PolicyVerifier:
    """Verify Ed25519 policy signatures without retaining signing capability."""

    def __init__(self, public_key: bytes) -> None:
        if len(public_key) != 32:
            raise ValueError("policy verification key must contain 32 bytes")
        self._public_key = Ed25519PublicKey.from_public_bytes(public_key)
        self.key_id = "ed25519:" + hashlib.sha256(public_key).hexdigest()

    def verify(self, payload: bytes, signature: str, key_id: str) -> bool:
        if key_id != self.key_id:
            return False
        try:
            encoded = signature.encode("ascii")
            decoded = urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
            self._public_key.verify(decoded, payload)
        except (InvalidSignature, ValueError, UnicodeEncodeError):
            return False
        return True
