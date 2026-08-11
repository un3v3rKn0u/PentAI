from __future__ import annotations

import json
import os
import unittest
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

from pentai_core.config import Settings
from pentai_core.network_attestation import AttestationError, NetworkAttestor
from pentai_core.network_attestation_adapters import (
    ExactRouteInspector,
    HostRouteSnapshot,
    HttpsSourceObserver,
    SystemRouteProbe,
)
from pentai_core.network_safety_composition import compose_network_safety_supervisor


@dataclass
class FixtureTransport:
    documents: dict[str, object]
    calls: list[tuple[str, float, int]] = field(default_factory=list)

    def fetch(self, url: str, *, timeout_seconds: float, max_bytes: int) -> bytes:
        self.calls.append((url, timeout_seconds, max_bytes))
        value = self.documents[url]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, bytes):
            return value
        return json.dumps(value).encode()


@dataclass(frozen=True)
class FixtureRouteProbe:
    snapshot: HostRouteSnapshot

    def inspect(self) -> HostRouteSnapshot:
        return self.snapshot


@dataclass
class FixtureSafetyControl:
    assessment_ids: tuple[str, ...] = ("assessment-a",)
    pauses: list[tuple[str, str, str]] = field(default_factory=list)
    measurements: list[dict[str, object]] = field(default_factory=list)
    profile: dict[str, object] = field(
        default_factory=lambda: {
            "route_profile_id": "fixture-route",
            "route_interface": "utun9",
            "route_gateway": "10.0.0.1",
            "resolver_mode": "tunnel_resolver",
            "resolver_id": "fixture-resolver",
            "resolver_addresses": ["10.0.0.53"],
        }
    )
    profile_failure: Exception | None = None

    def has_network_authority(self) -> bool:
        return bool(self.assessment_ids)

    def network_authority_assessments(self) -> tuple[str, ...]:
        return self.assessment_ids

    def network_profile_for_assessment(self, engagement_id: str) -> dict[str, Any]:
        if self.profile_failure is not None:
            raise self.profile_failure
        return self.profile

    def verify_network_identity(
        self, engagement_id: str, *, attestor: Any, attestor_id: str
    ) -> dict[str, Any]:
        measured = attestor.measure(
            assessment_id=engagement_id,
            policy_hash="a" * 64,
            now=datetime(2026, 8, 10, tzinfo=UTC),
        )
        self.measurements.append(measured)
        return measured

    def set_global_safety(
        self, *, status: str, reason: str, actor_id: str
    ) -> dict[str, Any]:
        self.pauses.append((status, reason, actor_id))
        return {}


def configured_settings() -> Settings:
    return Settings(
        environment="test",
        test_mode=True,
        network_attestation_enabled=True,
        network_observers=(
            "observer-a|ipv4|https://observer-a.invalid/ip",
            "observer-b|ipv4|https://observer-b.invalid/ip",
        ),
        network_route_profile_id="fixture-route",
        network_route_interface="utun9",
        network_route_gateway="10.0.0.1",
        network_resolver_mode="tunnel_resolver",
        network_resolver_id="fixture-resolver",
        network_resolver_addresses=("10.0.0.53",),
        network_observer_timeout_seconds=0.2,
        network_route_timeout_seconds=0.2,
        network_watchdog_interval_seconds=0.1,
    )


class NetworkAttestationAdapterTests(unittest.TestCase):
    def test_https_observer_accepts_only_bounded_exact_public_ip_document(self) -> None:
        url = "https://observer-a.invalid/ip"
        transport = FixtureTransport({url: {"ip": "1.1.1.1"}})
        result = HttpsSourceObserver(
            endpoint_id="observer-a",
            url=url,
            address_family="ipv4",
            transport=transport,
            timeout_seconds=0.2,
        ).observe()
        self.assertEqual(result.source_ipv4, "1.1.1.1")
        self.assertEqual(transport.calls, [(url, 0.2, 1024)])

        invalid = (
            ({"ip": "127.0.0.1"}, "ATTESTATION_ADDRESS_INVALID"),
            ({"ip": "2001:4860:4860::8888"}, "ATTESTATION_ADDRESS_INVALID"),
            ({"ip": "1.1.1.1", "debug": "leak"}, "ATTESTATION_OBSERVATION_INVALID"),
            (b"not-json", "ATTESTATION_OBSERVATION_INVALID"),
        )
        for document, expected in invalid:
            with self.subTest(expected=expected):
                transport.documents[url] = document
                with self.assertRaises(AttestationError) as raised:
                    HttpsSourceObserver(
                        endpoint_id="observer-a",
                        url=url,
                        address_family="ipv4",
                        transport=transport,
                    ).observe()
                self.assertEqual(raised.exception.code, expected)

    def test_observer_configuration_rejects_redirectable_or_ambiguous_urls(self) -> None:
        for url in (
            "http://observer.invalid/ip",
            "https://user@observer.invalid/ip",
            "https://observer.invalid:8443/ip",
            "https://observer.invalid/ip?format=json",
        ):
            with self.subTest(url=url), self.assertRaises(AttestationError):
                HttpsSourceObserver(
                    endpoint_id="observer-a", url=url, address_family="ipv4"
                )

    def test_each_address_family_requires_two_agreeing_observers(self) -> None:
        transport = FixtureTransport(
            {
                "https://a.invalid/ip": {"ip": "1.1.1.1"},
                "https://b.invalid/ip": {"ip": "1.1.1.1"},
                "https://v6.invalid/ip": {"ip": "2001:4860:4860::8888"},
            }
        )
        inspector = ExactRouteInspector(
            probe=FixtureRouteProbe(
                HostRouteSnapshot("utun9", "10.0.0.1", ("10.0.0.53",))
            ),
            route_profile_id="fixture-route",
            expected_interface="utun9",
            expected_gateway="10.0.0.1",
            resolver_mode="tunnel_resolver",
            resolver_id="fixture-resolver",
            expected_resolvers=("10.0.0.53",),
        )
        observers = tuple(
            HttpsSourceObserver(
                endpoint_id=name,
                url=url,
                address_family=family,
                transport=transport,
            )
            for name, family, url in (
                ("a", "ipv4", "https://a.invalid/ip"),
                ("b", "ipv4", "https://b.invalid/ip"),
                ("v6", "ipv6", "https://v6.invalid/ip"),
            )
        )
        with self.assertRaises(AttestationError) as raised:
            NetworkAttestor(observers, inspector).measure(
                assessment_id="assessment-a", policy_hash="a" * 64
            )
        self.assertEqual(raised.exception.code, "ATTESTATION_ENDPOINTS_INSUFFICIENT")

    def test_exact_route_inspector_denies_interface_gateway_or_resolver_drift(self) -> None:
        expected = {
            "route_profile_id": "fixture-route",
            "expected_interface": "utun9",
            "expected_gateway": "10.0.0.1",
            "resolver_mode": "tunnel_resolver",
            "resolver_id": "fixture-resolver",
            "expected_resolvers": ("10.0.0.53",),
        }
        for snapshot in (
            HostRouteSnapshot("en0", "10.0.0.1", ("10.0.0.53",)),
            HostRouteSnapshot("utun9", "10.0.0.2", ("10.0.0.53",)),
            HostRouteSnapshot("utun9", "10.0.0.1", ("1.1.1.1",)),
        ):
            with self.subTest(snapshot=snapshot), self.assertRaises(AttestationError) as raised:
                ExactRouteInspector(probe=FixtureRouteProbe(snapshot), **expected).inspect()
            self.assertEqual(raised.exception.code, "ATTESTATION_ROUTE_MISMATCH")

    def test_system_route_probe_parses_owned_linux_fixture_and_denies_ambiguity(self) -> None:
        probe = SystemRouteProbe()
        route = '[{"dst":"default","gateway":"10.0.0.1","dev":"tun0"}]'
        with (
            patch("pentai_core.network_attestation_adapters.platform.system", return_value="Linux"),
            patch.object(SystemRouteProbe, "_run", return_value=route),
            patch(
                "pentai_core.network_attestation_adapters.Path.read_text",
                return_value="nameserver 10.0.0.53\n",
            ),
        ):
            self.assertEqual(
                probe.inspect(),
                HostRouteSnapshot("tun0", "10.0.0.1", ("10.0.0.53",)),
            )
        with (
            patch("pentai_core.network_attestation_adapters.platform.system", return_value="Linux"),
            patch.object(SystemRouteProbe, "_run", return_value=f"[{route[1:-1]},{route[1:-1]}]"),
        ):
            with self.assertRaises(AttestationError) as raised:
                probe.inspect()
            self.assertEqual(raised.exception.code, "ATTESTATION_ROUTE_INVALID")

    def test_configuration_is_explicit_and_complete(self) -> None:
        configured_settings().validate()
        with self.assertRaisesRegex(ValueError, "explicit enablement"):
            Settings(
                environment="test",
                test_mode=True,
                network_observers=("observer-a|ipv4|https://observer.invalid/ip",),
            ).validate()
        observer_only = Settings(
            environment="test",
            test_mode=True,
            network_attestation_enabled=True,
            network_observers=(
                "observer-a|ipv4|https://a.invalid/ip",
                "observer-b|ipv4|https://b.invalid/ip",
            ),
        )
        observer_only.validate()

    def test_environment_parses_network_configuration(self) -> None:
        environment = {
            "PENTAI_ENVIRONMENT": "test",
            "PENTAI_TEST_MODE": "1",
            "PENTAI_NETWORK_ATTESTATION_ENABLED": "1",
            "PENTAI_NETWORK_OBSERVERS": (
                "observer-a|ipv4|https://a.invalid/ip;"
                "observer-b|ipv4|https://b.invalid/ip"
            ),
        }
        with patch.dict(os.environ, environment, clear=True):
            settings = Settings.from_environment()
        self.assertTrue(settings.network_attestation_enabled)
        self.assertIsNone(settings.network_route_interface)
        self.assertEqual(settings.network_resolver_addresses, ())

    def test_composition_attests_before_ready_and_fails_closed(self) -> None:
        settings = Settings(
            **(
                configured_settings().__dict__
                | {
                    "network_route_profile_id": "ignored-legacy-route",
                    "network_route_interface": "ignored0",
                    "network_route_gateway": "192.0.2.99",
                    "network_resolver_mode": "approved_resolver",
                    "network_resolver_id": "ignored-legacy-resolver",
                    "network_resolver_addresses": ("192.0.2.53",),
                }
            )
        )
        settings.validate()
        transport = FixtureTransport(
            {
                "https://observer-a.invalid/ip": {"ip": "1.1.1.1"},
                "https://observer-b.invalid/ip": {"ip": "1.1.1.1"},
            }
        )
        control = FixtureSafetyControl()
        supervisor = compose_network_safety_supervisor(
            settings=settings,
            safety_control=control,
            transport=transport,
            route_probe=FixtureRouteProbe(
                HostRouteSnapshot("utun9", "10.0.0.1", ("10.0.0.53",))
            ),
        )
        supervisor.start()
        self.assertEqual(supervisor.status()["status"], "ready")
        self.assertEqual(control.measurements[0]["source_ipv4"], "1.1.1.1")
        self.assertEqual(control.measurements[0]["route_profile_id"], "fixture-route")
        supervisor.stop()

        invalid = Settings(**(settings.__dict__ | {"network_observers": ("invalid", "invalid2")}))
        degraded = compose_network_safety_supervisor(
            settings=invalid, safety_control=FixtureSafetyControl()
        )
        degraded.start()
        self.assertEqual(
            degraded.status()["reason_code"], "NETWORK_ATTESTATION_COMPOSITION_FAILED"
        )

        missing_profile = FixtureSafetyControl(profile_failure=ValueError("missing"))
        unavailable = compose_network_safety_supervisor(
            settings=configured_settings(),
            safety_control=missing_profile,
            transport=transport,
            route_probe=FixtureRouteProbe(
                HostRouteSnapshot("utun9", "10.0.0.1", ("10.0.0.53",))
            ),
        )
        unavailable.start()
        self.assertEqual(unavailable.status()["reason_code"], "NETWORK_IDENTITY_STARTUP_FAILED")
        self.assertEqual(missing_profile.pauses[-1][0], "paused")


if __name__ == "__main__":
    unittest.main()
