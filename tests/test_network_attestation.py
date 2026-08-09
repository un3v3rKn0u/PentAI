from __future__ import annotations

import unittest
from dataclasses import dataclass
from datetime import UTC, datetime

from pentai_core.controlled_dns import (
    ControlledDnsError,
    ControlledResolver,
    RawDnsAnswer,
)
from pentai_core.network_attestation import (
    AttestationError,
    NetworkAttestor,
    RouteSnapshot,
    SourceObservation,
)


@dataclass(frozen=True)
class FixtureObserver:
    observation: SourceObservation

    def observe(self) -> SourceObservation:
        return self.observation


@dataclass(frozen=True)
class FixtureResolverBackend:
    answer: RawDnsAnswer

    def resolve(self, hostname: str, port: int) -> RawDnsAnswer:
        return self.answer


@dataclass(frozen=True)
class FixtureRouteInspector:
    snapshot: RouteSnapshot

    def inspect(self) -> RouteSnapshot:
        return self.snapshot


def fixture_route() -> FixtureRouteInspector:
    return FixtureRouteInspector(
        RouteSnapshot("synthetic-route", "tunnel_resolver", "fixture:controlled-dns")
    )


class NetworkAttestationTests(unittest.TestCase):
    def test_two_independent_observers_create_short_lived_attestation(self) -> None:
        attestor = NetworkAttestor(
            (
                FixtureObserver(SourceObservation("fixture:a", "192.0.2.10")),
                FixtureObserver(SourceObservation("fixture:b", "192.0.2.10")),
            ),
            fixture_route(),
        )
        result = attestor.measure(
            assessment_id="00000000-0000-4000-8000-000000000001",
            policy_hash="a" * 64,
            now=datetime(2026, 8, 9, tzinfo=UTC),
        )
        self.assertEqual(result["source_ipv4"], "192.0.2.10")
        self.assertEqual(result["observations"], ["fixture:a", "fixture:b"])
        self.assertEqual(result["expires_at"], "2026-08-09T00:00:30Z")

    def test_observer_disagreement_duplicate_identity_and_invalid_family_deny(self) -> None:
        cases = (
            (
                SourceObservation("fixture:a", "192.0.2.10"),
                SourceObservation("fixture:b", "192.0.2.11"),
                "ATTESTATION_DISAGREEMENT",
            ),
            (
                SourceObservation("fixture:a", "192.0.2.10"),
                SourceObservation("fixture:a", "192.0.2.10"),
                "ATTESTATION_ENDPOINTS_INVALID",
            ),
            (
                SourceObservation("fixture:a", source_ipv4="2001:db8::1"),
                SourceObservation("fixture:b", source_ipv4="2001:db8::1"),
                "ATTESTATION_ADDRESS_INVALID",
            ),
        )
        for first, second, expected in cases:
            with self.subTest(expected=expected), self.assertRaises(AttestationError) as raised:
                NetworkAttestor(
                    (FixtureObserver(first), FixtureObserver(second)), fixture_route()
                ).measure(
                    assessment_id="00000000-0000-4000-8000-000000000001",
                    policy_hash="a" * 64,
                )
            self.assertEqual(raised.exception.code, expected)

    def test_controlled_resolver_binds_attestation_and_canonicalizes_all_answers(self) -> None:
        resolver = ControlledResolver(
            FixtureResolverBackend(
                RawDnsAnswer(
                    addresses=("192.0.2.20", "192.0.2.21"),
                    cname_chain=("Alias.Example.test.",),
                )
            ),
            resolver_mode="tunnel_resolver",
            resolver_id="fixture:controlled-dns",
        )
        answer = resolver.resolve(
            "Example.test.",
            443,
            attestation={
                "resolver_mode": "tunnel_resolver",
                "resolver_id": "fixture:controlled-dns",
            },
        )
        self.assertEqual(answer.hostname, "example.test")
        self.assertEqual(answer.addresses, ("192.0.2.20", "192.0.2.21"))
        self.assertEqual(answer.cname_chain, ("alias.example.test",))

    def test_controlled_resolver_denies_mismatch_duplicates_and_oversized_answers(self) -> None:
        cases = (
            (
                RawDnsAnswer(("192.0.2.20",)),
                {"resolver_mode": "approved_resolver", "resolver_id": "fixture:dns"},
                "DNS_ATTESTATION_MISMATCH",
            ),
            (
                RawDnsAnswer(("192.0.2.20", "192.0.2.20")),
                {"resolver_mode": "tunnel_resolver", "resolver_id": "fixture:dns"},
                "DNS_ANSWER_INVALID",
            ),
            (
                RawDnsAnswer(tuple(f"192.0.2.{value}" for value in range(1, 18))),
                {"resolver_mode": "tunnel_resolver", "resolver_id": "fixture:dns"},
                "DNS_ANSWER_INVALID",
            ),
        )
        for raw, attestation, expected in cases:
            resolver = ControlledResolver(
                FixtureResolverBackend(raw),
                resolver_mode="tunnel_resolver",
                resolver_id="fixture:dns",
            )
            with self.subTest(expected=expected), self.assertRaises(ControlledDnsError) as raised:
                resolver.resolve("example.test", 443, attestation=attestation)
            self.assertEqual(raised.exception.code, expected)


if __name__ == "__main__":
    unittest.main()
