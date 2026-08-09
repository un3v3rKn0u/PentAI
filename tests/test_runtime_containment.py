from __future__ import annotations

import unittest
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from pentai_core.runtime_containment import (
    GatewayNetworkSnapshot,
    RuntimeContainmentAttestor,
    RuntimeSnapshot,
)
from pentai_core.worker_containment import ContainmentError
from pentai_policy.document import contract_issues


def safe_runtime() -> RuntimeSnapshot:
    return RuntimeSnapshot(
        runtime="podman",
        runtime_instance_id="fixture:rootless-podman",
        rootless=True,
        read_only_root_supported=True,
        capability_drop_supported=True,
        no_new_privileges_supported=True,
        host_namespace_isolation_supported=True,
        resource_limits_supported=True,
        temporary_mounts_supported=True,
        runtime_socket_mounted=False,
    )


def safe_network() -> GatewayNetworkSnapshot:
    return GatewayNetworkSnapshot(
        network_id="fixture:gateway-only",
        internal=True,
        gateway_is_only_egress=True,
        external_dns_disabled=True,
        ipv6_disabled=True,
    )


@dataclass(frozen=True)
class FixtureInspector:
    runtime: RuntimeSnapshot
    network: GatewayNetworkSnapshot

    def inspect_runtime(self) -> RuntimeSnapshot:
        return self.runtime

    def inspect_gateway_network(self) -> GatewayNetworkSnapshot:
        return self.network


class FailingInspector:
    def inspect_runtime(self) -> RuntimeSnapshot:
        raise OSError("synthetic inspection failure")

    def inspect_gateway_network(self) -> GatewayNetworkSnapshot:
        raise AssertionError("must not continue after runtime inspection failure")


class RuntimeContainmentTests(unittest.TestCase):
    def test_safe_measurements_create_short_lived_contract(self) -> None:
        result = RuntimeContainmentAttestor(
            FixtureInspector(safe_runtime(), safe_network())
        ).measure(now=datetime(2026, 8, 9, tzinfo=UTC))
        self.assertEqual(
            contract_issues(result, "worker-containment-attestation-v1.schema.json"), ()
        )
        self.assertEqual(result["observed_at"], "2026-08-09T00:00:00Z")
        self.assertEqual(result["expires_at"], "2026-08-09T00:00:30Z")
        self.assertTrue(result["rootless"])
        self.assertTrue(result["direct_egress_disabled"])

    def test_every_runtime_control_fails_closed(self) -> None:
        controls = (
            "rootless",
            "read_only_root_supported",
            "capability_drop_supported",
            "no_new_privileges_supported",
            "host_namespace_isolation_supported",
            "resource_limits_supported",
            "temporary_mounts_supported",
        )
        for field in controls:
            with self.subTest(field=field), self.assertRaises(ContainmentError) as raised:
                runtime = replace(safe_runtime(), **{field: False})
                RuntimeContainmentAttestor(
                    FixtureInspector(runtime, safe_network())
                ).measure()
            self.assertEqual(raised.exception.code, "CONTAINMENT_RUNTIME_UNSAFE")

        with self.assertRaises(ContainmentError) as raised:
            runtime = replace(safe_runtime(), runtime_socket_mounted=True)
            RuntimeContainmentAttestor(FixtureInspector(runtime, safe_network())).measure()
        self.assertEqual(raised.exception.code, "CONTAINMENT_RUNTIME_SOCKET")

    def test_every_network_control_fails_closed(self) -> None:
        for field in (
            "internal",
            "gateway_is_only_egress",
            "external_dns_disabled",
            "ipv6_disabled",
        ):
            with self.subTest(field=field), self.assertRaises(ContainmentError) as raised:
                network = replace(safe_network(), **{field: False})
                RuntimeContainmentAttestor(
                    FixtureInspector(safe_runtime(), network)
                ).measure()
            self.assertEqual(raised.exception.code, "CONTAINMENT_NETWORK_UNSAFE")

    def test_inspection_error_identity_and_lifetime_fail_closed(self) -> None:
        with self.assertRaises(ContainmentError) as raised:
            RuntimeContainmentAttestor(FailingInspector()).measure()
        self.assertEqual(raised.exception.code, "CONTAINMENT_INSPECTION_FAILED")

        with self.assertRaises(ContainmentError) as raised:
            RuntimeContainmentAttestor(
                FixtureInspector(replace(safe_runtime(), runtime="unknown"), safe_network())
            ).measure()
        self.assertEqual(raised.exception.code, "CONTAINMENT_RUNTIME_INVALID")

        for lifetime in (0, 61):
            with self.subTest(lifetime=lifetime), self.assertRaises(ContainmentError):
                RuntimeContainmentAttestor(
                    FixtureInspector(safe_runtime(), safe_network()),
                    lifetime_seconds=lifetime,
                )


if __name__ == "__main__":
    unittest.main()
