from __future__ import annotations

import unittest

from pentai_core.policy_signing import PolicySigner, PolicyVerifier


class PolicySigningTests(unittest.TestCase):
    def test_signatures_are_deterministic_key_bound_and_tamper_evident(self) -> None:
        signer = PolicySigner(b"a" * 32)
        other = PolicySigner(b"b" * 32)
        payload = b"synthetic-policy-hash"
        signature = signer.sign(payload)
        verifier = signer.verifier()
        self.assertEqual(signature, signer.sign(payload))
        self.assertFalse(hasattr(verifier, "sign"))
        self.assertEqual(verifier.key_id, signer.key_id)
        self.assertEqual(len(verifier.public_key_bytes()), 32)
        self.assertTrue(verifier.verify(payload, signature, signer.key_id))
        self.assertFalse(verifier.verify(payload + b"x", signature, signer.key_id))
        self.assertFalse(other.verifier().verify(payload, signature, signer.key_id))
        self.assertFalse(verifier.verify(payload, "malformed", signer.key_id))

    def test_seed_must_be_exactly_256_bits(self) -> None:
        for seed in (b"", b"a" * 31, b"a" * 33):
            with self.assertRaises(ValueError):
                PolicySigner(seed)

    def test_public_verification_key_must_be_exactly_256_bits(self) -> None:
        for public_key in (b"", b"a" * 31, b"a" * 33):
            with self.assertRaises(ValueError):
                PolicyVerifier(public_key)


if __name__ == "__main__":
    unittest.main()
