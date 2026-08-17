from __future__ import annotations

import unittest
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from pentai_core.runtime_containment import (
    ComposedWorkerRuntimeInspector,
    GatewayNetworkSnapshot,
    RuntimeContainmentAttestor,
    RuntimeSnapshot,
    WorkerContainmentAttestor,
    WorkerGatewayNetworkSnapshot,
    WorkerGatewayPeerEvidence,
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


def safe_worker_network() -> WorkerGatewayNetworkSnapshot:
    return WorkerGatewayNetworkSnapshot(
        network_id="fixture:worker-gateway",
        gateway_container_id="fixture:gateway-container",
        internal=True,
        gateway_is_only_peer=True,
        direct_egress_disabled=True,
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


@dataclass(frozen=True)
class FixtureWorkerInspector:
    runtime: RuntimeSnapshot
    network: WorkerGatewayNetworkSnapshot

    def inspect_runtime(self) -> RuntimeSnapshot:
        return self.runtime

    def inspect_worker_gateway_network(self) -> WorkerGatewayNetworkSnapshot:
        return self.network


@dataclass(frozen=True)
class FixturePeerEvidence:
    network_id: str
    gateway_container_id: str


@dataclass(frozen=True)
class FixturePeerVerifier:
    evidence: FixturePeerEvidence

    def verify(
        self, *, network_id: str, gateway_container_id: str
    ) -> WorkerGatewayPeerEvidence:
        del network_id, gateway_container_id
        return self.evidence


class RuntimeContainmentTests(unittest.TestCase):
    def test_composed_worker_inspector_binds_conformance_and_live_peer_evidence(self) -> None:
        inspector = ComposedWorkerRuntimeInspector(
            runtime_inspector=FixtureInspector(safe_runtime(), safe_network()),
            peer_verifier=FixturePeerVerifier(
                FixturePeerEvidence(
                    "fixture:gateway-only", "fixture:gateway-container"
                )
            ),
            worker_gateway_network_id="fixture:gateway-only",
            gateway_container_id="fixture:gateway-container",
        )
        result = WorkerContainmentAttestor(
            inspector,
            worker_gateway_network_id="fixture:gateway-only",
            gateway_container_id="fixture:gateway-container",
        ).measure(now=datetime(2026, 8, 17, tzinfo=UTC))
        self.assertEqual(result["worker_gateway_network_id"], "fixture:gateway-only")
        self.assertEqual(result["network_role"], "worker_gateway")

    def test_composed_worker_inspector_denies_mismatched_peer_evidence(self) -> None:
        inspector = ComposedWorkerRuntimeInspector(
            runtime_inspector=FixtureInspector(safe_runtime(), safe_network()),
            peer_verifier=FixturePeerVerifier(
                FixturePeerEvidence("fixture:gateway-only", "fixture:wrong-gateway")
            ),
            worker_gateway_network_id="fixture:gateway-only",
            gateway_container_id="fixture:gateway-container",
        )
        with self.assertRaises(ContainmentError) as raised:
            WorkerContainmentAttestor(
                inspector,
                worker_gateway_network_id="fixture:gateway-only",
                gateway_container_id="fixture:gateway-container",
            ).measure()
        self.assertEqual(raised.exception.code, "CONTAINMENT_IDENTITY_INVALID")

    def test_exact_worker_gateway_measurements_create_v2_contract(self) -> None:
        result = WorkerContainmentAttestor(
            FixtureWorkerInspector(safe_runtime(), safe_worker_network()),
            worker_gateway_network_id="fixture:worker-gateway",
            gateway_container_id="fixture:gateway-container",
        ).measure(now=datetime(2026, 8, 17, tzinfo=UTC))
        self.assertEqual(
            contract_issues(result, "worker-containment-attestation-v2.schema.json"), ()
        )
        self.assertEqual(result["schema_version"], "2.0.0")
        self.assertEqual(result["network_role"], "worker_gateway")
        self.assertEqual(result["worker_gateway_network_id"], "fixture:worker-gateway")
        self.assertEqual(result["observed_at"], "2026-08-17T00:00:00Z")
        self.assertEqual(result["expires_at"], "2026-08-17T00:00:30Z")

    def test_worker_attestation_denies_network_or_gateway_identity_drift(self) -> None:
        cases = (
            replace(safe_worker_network(), network_id="fixture:other-network"),
            replace(safe_worker_network(), gateway_container_id="fixture:other-gateway"),
        )
        for network in cases:
            with self.subTest(network=network), self.assertRaises(ContainmentError) as raised:
                WorkerContainmentAttestor(
                    FixtureWorkerInspector(safe_runtime(), network),
                    worker_gateway_network_id="fixture:worker-gateway",
                    gateway_container_id="fixture:gateway-container",
                ).measure()
            self.assertEqual(raised.exception.code, "CONTAINMENT_IDENTITY_INVALID")

    def test_every_worker_network_control_fails_closed(self) -> None:
        for field in (
            "internal",
            "gateway_is_only_peer",
            "direct_egress_disabled",
            "external_dns_disabled",
            "ipv6_disabled",
        ):
            with self.subTest(field=field), self.assertRaises(ContainmentError) as raised:
                WorkerContainmentAttestor(
                    FixtureWorkerInspector(
                        safe_runtime(), replace(safe_worker_network(), **{field: False})
                    ),
                    worker_gateway_network_id="fixture:worker-gateway",
                    gateway_container_id="fixture:gateway-container",
                ).measure()
            self.assertEqual(raised.exception.code, "CONTAINMENT_NETWORK_UNSAFE")

    def test_worker_attestation_rejects_invalid_expected_identity_and_lifetime(self) -> None:
        for network_id, gateway_id, lifetime in (
            ("--network", "fixture:gateway", 30),
            ("fixture:network", "", 30),
            ("fixture:network", "fixture:gateway", 0),
            ("fixture:network", "fixture:gateway", 61),
        ):
            with self.subTest(network_id=network_id, gateway_id=gateway_id, lifetime=lifetime):
                with self.assertRaises(ContainmentError):
                    WorkerContainmentAttestor(
                        FixtureWorkerInspector(safe_runtime(), safe_worker_network()),
                        worker_gateway_network_id=network_id,
                        gateway_container_id=gateway_id,
                        lifetime_seconds=lifetime,
                    )

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
