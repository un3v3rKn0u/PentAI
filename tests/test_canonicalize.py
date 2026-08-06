from __future__ import annotations

import json
import unittest
from pathlib import Path

from pentai_policy import (
    CanonicalizationError,
    canonicalize_cidr,
    canonicalize_domain,
    canonicalize_ip,
    canonicalize_port,
    canonicalize_url,
)

FIXTURES = Path(__file__).parent / "fixtures" / "canonicalization-v1.json"


class CanonicalizationFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = json.loads(FIXTURES.read_text(encoding="utf-8"))

    def test_valid_domains(self) -> None:
        for case in self.cases["domain"]["valid"]:
            with self.subTest(case=case):
                self.assertEqual(canonicalize_domain(case["input"]), case["expected"])

    def test_invalid_domains(self) -> None:
        for value in self.cases["domain"]["invalid"]:
            with self.subTest(value=value):
                with self.assertRaises(CanonicalizationError):
                    canonicalize_domain(value)

    def test_valid_ips(self) -> None:
        for case in self.cases["ip"]["valid"]:
            with self.subTest(case=case):
                self.assertEqual(canonicalize_ip(case["input"]), case["expected"])

    def test_invalid_ips(self) -> None:
        for value in self.cases["ip"]["invalid"]:
            with self.subTest(value=value):
                with self.assertRaises(CanonicalizationError):
                    canonicalize_ip(value)

    def test_valid_cidrs(self) -> None:
        for case in self.cases["cidr"]["valid"]:
            with self.subTest(case=case):
                self.assertEqual(canonicalize_cidr(case["input"]), case["expected"])

    def test_invalid_cidrs(self) -> None:
        for value in self.cases["cidr"]["invalid"]:
            with self.subTest(value=value):
                with self.assertRaises(CanonicalizationError):
                    canonicalize_cidr(value)

    def test_valid_urls(self) -> None:
        for case in self.cases["url"]["valid"]:
            with self.subTest(case=case):
                result = canonicalize_url(case["input"])
                self.assertEqual(result["canonical_url"], case["expected_canonical_url"])

    def test_invalid_urls(self) -> None:
        for value in self.cases["url"]["invalid"]:
            with self.subTest(value=value):
                with self.assertRaises(CanonicalizationError):
                    canonicalize_url(value)

    def test_port_boundaries(self) -> None:
        self.assertEqual(canonicalize_port(1), 1)
        self.assertEqual(canonicalize_port("65535"), 65535)
        for invalid in (0, 65536, True, "080", "+443", "https"):
            with self.subTest(value=invalid):
                with self.assertRaises(CanonicalizationError):
                    canonicalize_port(invalid)


if __name__ == "__main__":
    unittest.main()
