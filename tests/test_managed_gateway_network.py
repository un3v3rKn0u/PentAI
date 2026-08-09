from __future__ import annotations

import json
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from pentai_core.managed_gateway_network import (
    ManagedGatewayNetworkProvisioner,
    OciNetworkConformanceProbe,
    require_rootless_runtime,
)
from pentai_core.runtime_snapshot_collector import CommandResult, SnapshotCollectionError

DOCKER = Path("/usr/local/bin/docker")
NAME = "pentai-gateway-fixture"
NETWORK_ID = "fixture-network-id"
INSTANCE = "fixture-pentai"
IMAGE = "sha256:" + "a" * 64


def conformance(**updates: object) -> dict[str, object]:
    document: dict[str, object] = {
        "network_id": NETWORK_ID,
        "direct_egress_blocked": True,
        "external_dns_blocked": True,
        "ipv6_blocked": True,
        "runtime_socket_blocked": True,
        "host_mounts_blocked": True,
        "host_namespaces_blocked": True,
        "resource_limits_enforced": True,
    }
    document.update(updates)
    return document


def encoded(document: object, *, returncode: int = 0) -> CommandResult:
    return CommandResult(returncode, json.dumps(document).encode())


def listed(network_id: str = NETWORK_ID) -> CommandResult:
    return encoded({"ID": network_id, "Name": NAME})


def inspected(**updates: object) -> CommandResult:
    document: dict[str, object] = {
        "Id": NETWORK_ID,
        "Name": NAME,
        "Internal": True,
        "EnableIPv6": False,
        "Labels": {
            "com.pentai.managed": "true",
            "com.pentai.network-role": "worker-gateway",
            "com.pentai.direct-egress": "deny",
            "com.pentai.external-dns": "deny",
            "com.pentai.instance-id": INSTANCE,
        },
    }
    document.update(updates)
    return encoded(document)


@dataclass
class FixtureExecutor:
    responses: list[CommandResult]
    calls: list[tuple[tuple[str, ...], float, int]] = field(default_factory=list)

    def execute(
        self, argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
    ) -> CommandResult:
        self.calls.append((argv, timeout_seconds, max_output_bytes))
        return self.responses.pop(0)


def provisioner(executor: FixtureExecutor) -> ManagedGatewayNetworkProvisioner:
    return ManagedGatewayNetworkProvisioner(
        runtime="docker",
        executable=DOCKER,
        network_name=NAME,
        pentai_instance_id=INSTANCE,
        executor=executor,
    )


class ManagedGatewayNetworkTests(unittest.TestCase):
    def test_rootless_runtime_gate_requires_explicit_valid_evidence(self) -> None:
        accepted = (
            ("docker", DOCKER, {"SecurityOptions": ["name=rootless"]}),
            ("podman", Path("/usr/bin/podman"), {"host": {"rootless": True}}),
        )
        for runtime, executable, document in accepted:
            with self.subTest(runtime=runtime):
                require_rootless_runtime(
                    runtime=runtime,
                    executable=executable,
                    executor=FixtureExecutor([encoded(document)]),
                )

        denied = (
            ("docker", encoded({"SecurityOptions": ["name=seccomp"]})),
            ("podman", encoded({"host": {"rootless": False}})),
            ("docker", CommandResult(0, b"not-json")),
            ("docker", CommandResult(1, b"")),
        )
        for runtime, result in denied:
            with self.subTest(runtime=runtime), self.assertRaises(SnapshotCollectionError):
                require_rootless_runtime(
                    runtime=runtime,
                    executable=DOCKER,
                    executor=FixtureExecutor([result]),
                )

    def test_existing_owned_internal_network_is_idempotent(self) -> None:
        executor = FixtureExecutor([listed(), inspected()])
        result = provisioner(executor).ensure()
        self.assertEqual(result.network_id, NETWORK_ID)
        self.assertFalse(result.created)
        self.assertEqual(executor.calls[0][0][1:3], ("network", "ls"))
        self.assertEqual(executor.calls[1][0][1:3], ("network", "inspect"))

    def test_absent_network_is_created_with_fixed_deny_configuration(self) -> None:
        executor = FixtureExecutor(
            [CommandResult(0, b""), CommandResult(0, NETWORK_ID.encode()), listed(), inspected()]
        )
        result = provisioner(executor).ensure()
        self.assertEqual(result, type(result)(NETWORK_ID, True))
        command = executor.calls[1][0]
        self.assertEqual(command[:3], (str(DOCKER), "network", "create"))
        self.assertIn("--internal", command)
        self.assertIn("--ipv6=false", command)
        self.assertIn("com.docker.network.bridge.enable_ip_masquerade=false", command)
        self.assertIn("com.pentai.instance-id=" + INSTANCE, command)
        self.assertEqual(command[-1], NAME)

    def test_podman_network_creation_disables_dns(self) -> None:
        executor = FixtureExecutor([CommandResult(0, b""), CommandResult(1, b"")])
        provisioned = ManagedGatewayNetworkProvisioner(
            runtime="podman",
            executable=Path("/usr/local/bin/podman"),
            network_name=NAME,
            pentai_instance_id=INSTANCE,
            executor=executor,
        )
        with self.assertRaises(SnapshotCollectionError):
            provisioned.ensure()
        self.assertIn("--disable-dns", executor.calls[1][0])

    def test_ambiguous_unowned_and_unsafe_networks_deny(self) -> None:
        unowned = inspected(Labels={})
        cases = (
            (
                [encoded([{"ID": "one", "Name": NAME}, {"ID": "two", "Name": NAME}])],
                "NETWORK_IDENTITY_AMBIGUOUS",
            ),
            ([listed(), unowned], "NETWORK_OWNERSHIP_INVALID"),
            ([listed(), inspected(Internal=False)], "NETWORK_OWNERSHIP_INVALID"),
            ([listed(), inspected(EnableIPv6=True)], "NETWORK_OWNERSHIP_INVALID"),
        )
        for responses, expected in cases:
            with (
                self.subTest(expected=expected),
                self.assertRaises(SnapshotCollectionError) as raised,
            ):
                provisioner(FixtureExecutor(responses)).ensure()
            self.assertEqual(raised.exception.code, expected)

    def test_create_failure_and_unverified_race_deny(self) -> None:
        cases = (
            ([CommandResult(0, b""), CommandResult(1, b"")], "NETWORK_CREATE_FAILED"),
            (
                [
                    CommandResult(0, b""),
                    CommandResult(0, NETWORK_ID.encode()),
                    CommandResult(0, b""),
                ],
                "NETWORK_CREATE_UNVERIFIED",
            ),
        )
        for responses, expected in cases:
            with (
                self.subTest(expected=expected),
                self.assertRaises(SnapshotCollectionError) as raised,
            ):
                provisioner(FixtureExecutor(responses)).ensure()
            self.assertEqual(raised.exception.code, expected)

    def test_probe_uses_pinned_locked_down_fixture_and_parses_result(self) -> None:
        executor = FixtureExecutor(
            [encoded(conformance())]
        )
        result = OciNetworkConformanceProbe(
            executable=DOCKER, probe_image_digest=IMAGE, executor=executor
        ).verify(NETWORK_ID)
        self.assertTrue(result.direct_egress_blocked)
        command, timeout, output_limit = executor.calls[0]
        self.assertEqual(command[:3], (str(DOCKER), "run", "--rm"))
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--security-opt=no-new-privileges", command)
        self.assertIn(IMAGE, command)
        self.assertIn("--network-id=" + NETWORK_ID, command)
        self.assertEqual((timeout, output_limit), (10, 4096))

    def test_probe_identity_types_and_failures_deny(self) -> None:
        documents = (
            ({"network_id": NETWORK_ID}, "NETWORK_PROBE_INVALID"),
            (
                conformance(network_id="other-network"),
                "NETWORK_PROBE_MISMATCH",
            ),
            (
                conformance(direct_egress_blocked=1),
                "NETWORK_PROBE_INVALID",
            ),
        )
        for document, expected in documents:
            with (
                self.subTest(expected=expected),
                self.assertRaises(SnapshotCollectionError) as raised,
            ):
                OciNetworkConformanceProbe(
                    executable=DOCKER,
                    probe_image_digest=IMAGE,
                    executor=FixtureExecutor([encoded(document)]),
                ).verify(NETWORK_ID)
            self.assertEqual(raised.exception.code, expected)

    def test_probe_rejects_legacy_output_and_each_unsafe_control(self) -> None:
        legacy = conformance()
        legacy.pop("resource_limits_enforced")
        cases: list[tuple[dict[str, object], str]] = [(legacy, "missing-field")]
        for control in (
            "direct_egress_blocked",
            "external_dns_blocked",
            "ipv6_blocked",
            "runtime_socket_blocked",
            "host_mounts_blocked",
            "host_namespaces_blocked",
            "resource_limits_enforced",
        ):
            cases.append((conformance(**{control: False}), control))
        for document, label in cases:
            with self.subTest(control=label):
                probe = OciNetworkConformanceProbe(
                    executable=DOCKER,
                    probe_image_digest=IMAGE,
                    executor=FixtureExecutor([encoded(document)]),
                )
                if label == "missing-field":
                    with self.assertRaises(SnapshotCollectionError):
                        probe.verify(NETWORK_ID)
                else:
                    result = probe.verify(NETWORK_ID)
                    self.assertFalse(getattr(result, label))


if __name__ == "__main__":
    unittest.main()
