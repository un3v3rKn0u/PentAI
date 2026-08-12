from __future__ import annotations

import ipaddress
import json
import unittest
from pathlib import Path
from urllib.parse import urlsplit

import idna
from hypothesis import given
from hypothesis import strategies as st
from pentai_policy import (
    CanonicalizationError,
    canonicalize_cidr,
    canonicalize_domain,
    canonicalize_ip,
    canonicalize_path,
    canonicalize_port,
    canonicalize_url,
    canonicalize_wildcard_domain,
)

FIXTURES = Path(__file__).parent / "fixtures" / "canonicalization-v1.json"


class CanonicalizationFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = json.loads(FIXTURES.read_text(encoding="utf-8"))

    def _assert_valid(self, kind: str, function: object) -> None:
        for case in self.cases[kind]["valid"]:
            with self.subTest(case=case):
                self.assertEqual(function(case["input"]), case["expected"])  # type: ignore[operator]

    def _assert_invalid(self, kind: str, function: object) -> None:
        for value in self.cases[kind]["invalid"]:
            with self.subTest(value=value), self.assertRaises(CanonicalizationError):
                function(value)  # type: ignore[operator]

    def test_domains(self) -> None:
        self._assert_valid("domain", canonicalize_domain)
        self._assert_invalid("domain", canonicalize_domain)

    def test_ips(self) -> None:
        self._assert_valid("ip", canonicalize_ip)
        self._assert_invalid("ip", canonicalize_ip)

    def test_cidrs(self) -> None:
        self._assert_valid("cidr", canonicalize_cidr)
        self._assert_invalid("cidr", canonicalize_cidr)

    def test_wildcards(self) -> None:
        self._assert_valid("wildcard", canonicalize_wildcard_domain)
        self._assert_invalid("wildcard", canonicalize_wildcard_domain)

    def test_paths(self) -> None:
        self._assert_valid("path", canonicalize_path)
        self._assert_invalid("path", canonicalize_path)

    def test_urls(self) -> None:
        for case in self.cases["url"]["valid"]:
            with self.subTest(case=case):
                result = canonicalize_url(case["input"])
                self.assertEqual(result["canonical_url"], case["expected_canonical_url"])
        self._assert_invalid("url", canonicalize_url)

    def test_port_boundaries(self) -> None:
        self.assertEqual(canonicalize_port(1), 1)
        self.assertEqual(canonicalize_port("65535"), 65535)
        for invalid in (0, 65536, True, "0", "080", "+443", "https", "٤٤٣"):
            with self.subTest(value=invalid), self.assertRaises(CanonicalizationError):
                canonicalize_port(invalid)


ascii_label = st.from_regex(
    r"[a-z](?:[a-z0-9-]{0,15}[a-z0-9])?", fullmatch=True
).filter(lambda label: label[2:4] != "--")
ascii_domain = st.lists(ascii_label, min_size=1, max_size=4).map(".".join)


@given(ascii_domain, st.booleans())
def test_domain_is_deterministic_idempotent_and_matches_idna(
    domain: str, trailing_dot: bool
) -> None:
    candidate = domain.upper() + ("." if trailing_dot else "")
    result = canonicalize_domain(candidate)
    assert result == canonicalize_domain(candidate)
    assert result == canonicalize_domain(result)
    reference = idna.encode(
        candidate.removesuffix("."), uts46=True, transitional=False, std3_rules=True
    ).decode("ascii")
    assert result == reference.lower()


@given(st.ip_addresses())
def test_ip_is_idempotent_and_differential(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> None:
    result = canonicalize_ip(str(address))
    assert result["value"] == address.compressed.lower()
    assert canonicalize_ip(result["value"]) == result


@st.composite
def networks(
    draw: st.DrawFn,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    address = draw(st.ip_addresses())
    prefix = draw(st.integers(min_value=0, max_value=address.max_prefixlen))
    return ipaddress.ip_network(f"{address}/{prefix}", strict=False)


@given(networks())
def test_cidr_is_idempotent_and_differential(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> None:
    result = canonicalize_cidr(network.with_prefixlen)
    assert result["canonical"] == network.with_prefixlen.lower()
    assert canonicalize_cidr(str(result["canonical"])) == result


@given(st.integers(min_value=1, max_value=65535))
def test_port_is_idempotent(port: int) -> None:
    assert canonicalize_port(port) == port
    assert canonicalize_port(str(port)) == port


safe_segment = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), blacklist_characters="/%\\?#"),
    max_size=12,
)


@given(st.lists(safe_segment, max_size=5), st.booleans())
def test_path_is_deterministic_and_idempotent(segments: list[str], trailing: bool) -> None:
    candidate = "/" + "/".join(segments) + ("/" if trailing and segments else "")
    result = canonicalize_path(candidate)
    assert canonicalize_path(candidate) == result
    assert canonicalize_path(result) == result


@given(
    ascii_domain,
    st.sampled_from(["http", "https"]),
    st.integers(min_value=1, max_value=65535),
)
def test_url_is_idempotent_and_stdlib_authority_differential(
    domain: str, scheme: str, port: int
) -> None:
    candidate = f"{scheme.upper()}://{domain.upper()}:{port}/a/./b/../c"
    result = canonicalize_url(candidate)
    assert canonicalize_url(str(result["canonical_url"])) == result
    parsed = urlsplit(str(result["canonical_url"]))
    assert parsed.hostname == domain
    parsed_port = parsed.port or {"http": 80, "https": 443}[parsed.scheme]
    assert parsed_port == result["port"]


@given(st.text(max_size=80))
def test_arbitrary_inputs_are_deterministic_or_fail_closed(value: str) -> None:
    functions = (
        canonicalize_domain,
        canonicalize_ip,
        canonicalize_cidr,
        canonicalize_path,
        canonicalize_url,
    )
    for function in functions:
        try:
            first = function(value)
        except CanonicalizationError:
            with unittest.TestCase().assertRaises(CanonicalizationError):
                function(value)
        else:
            assert function(value) == first


if __name__ == "__main__":
    unittest.main()
