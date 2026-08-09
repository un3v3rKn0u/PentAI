from __future__ import annotations

import unittest

from pentai_core.policy_signing import PolicySigner


class PolicySigningTests(unittest.TestCase):
    def test_signatures_are_deterministic_key_bound_and_tamper_evident(self) -> None:
        signer = PolicySigner(b"a" * 32)
        other = PolicySigner(b"b" * 32)
        payload = b"synthetic-policy-hash"
        signature = signer.sign(payload)
        self.assertEqual(signature, signer.sign(payload))
        self.assertTrue(signer.verify(payload, signature, signer.key_id))
        self.assertFalse(signer.verify(payload + b"x", signature, signer.key_id))
        self.assertFalse(other.verify(payload, signature, signer.key_id))
        self.assertFalse(signer.verify(payload, "malformed", signer.key_id))

    def test_seed_must_be_exactly_256_bits(self) -> None:
        for seed in (b"", b"a" * 31, b"a" * 33):
            with self.assertRaises(ValueError):
                PolicySigner(seed)


if __name__ == "__main__":
    unittest.main()
