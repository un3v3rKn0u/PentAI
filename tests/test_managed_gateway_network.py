from __future__ import annotations

import json
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from pentai_core.managed_gateway_network import (
    ManagedGatewayNetworkProvisioner,
    NetworkProbeExecutionError,
    OciNetworkConformanceProbe,
    WorkerGatewayAttachmentInspector,
    WorkerGatewayAttachmentResult,
    WorkerGatewayPeerInspector,
    WorkerGatewayPeerResult,
    normalize_oci_image_digest,
    require_rootless_runtime,
)
from pentai_core.runtime_snapshot_collector import CommandResult, SnapshotCollectionError

DOCKER = Path("/usr/local/bin/docker")
NAME = "pentai-gateway-fixture"
NETWORK_ID = "fixture-network-id"
INSTANCE = "fixture-pentai"
IMAGE = "sha256:" + "a" * 64
GATEWAY_ID = "b" * 64
GATEWAY_NAME = "pentai-gateway"
WORKER_ID = "c" * 64
WORKER_NAME = "pentai-worker"


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


def podman_inspected(**updates: object) -> CommandResult:
    document: dict[str, object] = {
        "id": NETWORK_ID,
        "name": NAME,
        "internal": True,
        "ipv6_enabled": False,
        "labels": {
            "com.pentai.managed": "true",
            "com.pentai.network-role": "worker-gateway",
            "com.pentai.direct-egress": "deny",
            "com.pentai.external-dns": "deny",
            "com.pentai.instance-id": INSTANCE,
        },
    }
    document.update(updates)
    return encoded(document)


def peer_inspected(**updates: object) -> CommandResult:
    document: dict[str, object] = {
        "Id": NETWORK_ID,
        "Name": NAME,
        "Internal": True,
        "EnableIPv6": False,
        "Containers": {GATEWAY_ID: {"Name": GATEWAY_NAME}},
    }
    document.update(updates)
    return encoded(document)


def podman_peers(*peers: tuple[str, str], **updates: object) -> CommandResult:
    documents: list[dict[str, object]] = [
        {
            "Id": container_id,
            "Names": [name],
            "State": "running",
            "Networks": [NAME],
        }
        for container_id, name in peers
    ]
    for document in documents:
        document.update(updates)
    return encoded(documents)


def podman_peer_container(
    container_id: str, name: str, **updates: object
) -> CommandResult:
    document: dict[str, object] = {
        "Id": container_id,
        "Name": name,
        "State": {"Running": True},
        "HostConfig": {"NetworkMode": "bridge"},
        "NetworkSettings": {
            "Networks": {NAME: {"NetworkID": NAME}},
        },
    }
    document.update(updates)
    return encoded([document])


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
    def attachment_inspector(
        self, response: CommandResult | list[CommandResult], *, runtime: str = "docker"
    ) -> WorkerGatewayAttachmentInspector:
        return WorkerGatewayAttachmentInspector(
            runtime=runtime,
            executable=DOCKER,
            network_name=NAME,
            gateway_container_name=GATEWAY_NAME,
            worker_container_name=WORKER_NAME,
            executor=FixtureExecutor(
                response if isinstance(response, list) else [response]
            ),
        )

    def test_worker_network_requires_exactly_one_expected_gateway_peer(self) -> None:
        executor = FixtureExecutor([peer_inspected()])
        inspector = WorkerGatewayPeerInspector(
            runtime="docker",
            executable=DOCKER,
            network_name=NAME,
            gateway_container_name=GATEWAY_NAME,
            executor=executor,
        )
        self.assertEqual(
            inspector.verify(network_id=NETWORK_ID, gateway_container_id=GATEWAY_ID),
            WorkerGatewayPeerResult(NETWORK_ID, GATEWAY_ID),
        )
        command, timeout, output_limit = executor.calls[0]
        self.assertEqual(command[1:3], ("network", "inspect"))
        self.assertEqual((timeout, output_limit), (5, 65_536))

    def test_podman_worker_gateway_peer_shape_is_verified(self) -> None:
        executor = FixtureExecutor(
            [
                podman_inspected(),
                podman_peers((GATEWAY_ID, GATEWAY_NAME)),
                podman_peer_container(GATEWAY_ID, GATEWAY_NAME),
            ]
        )
        result = WorkerGatewayPeerInspector(
            runtime="podman",
            executable=Path("/usr/local/bin/podman"),
            network_name=NAME,
            gateway_container_name=GATEWAY_NAME,
            executor=executor,
        ).verify(network_id=NETWORK_ID, gateway_container_id=GATEWAY_ID)
        self.assertEqual(result.gateway_container_id, GATEWAY_ID)
        self.assertEqual(
            executor.calls[1][0][1:],
            (
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"network={NETWORK_ID}",
                "--format",
                "json",
            ),
        )
        self.assertEqual(
            executor.calls[2][0][1:],
            ("container", "inspect", GATEWAY_ID),
        )

    def test_missing_additional_or_wrong_gateway_peer_denies(self) -> None:
        cases = (
            peer_inspected(Containers={}),
            peer_inspected(
                Containers={
                    GATEWAY_ID: {"Name": GATEWAY_NAME},
                    "unexpected-worker": {"Name": "unexpected-worker"},
                }
            ),
            peer_inspected(Containers={GATEWAY_ID: {"Name": "wrong-gateway"}}),
        )
        for response in cases:
            with self.subTest(response=response), self.assertRaises(SnapshotCollectionError):
                WorkerGatewayPeerInspector(
                    runtime="docker",
                    executable=DOCKER,
                    network_name=NAME,
                    gateway_container_name=GATEWAY_NAME,
                    executor=FixtureExecutor([response]),
                ).verify(network_id=NETWORK_ID, gateway_container_id=GATEWAY_ID)

    def test_worker_peer_inspection_denies_network_identity_or_isolation_drift(self) -> None:
        cases = (
            peer_inspected(Id="changed-network"),
            peer_inspected(Name="changed-name"),
            peer_inspected(Internal=False),
            peer_inspected(EnableIPv6=True),
            CommandResult(0, b"not-json"),
            CommandResult(1, b""),
        )
        for response in cases:
            with self.subTest(response=response), self.assertRaises(SnapshotCollectionError):
                WorkerGatewayPeerInspector(
                    runtime="docker",
                    executable=DOCKER,
                    network_name=NAME,
                    gateway_container_name=GATEWAY_NAME,
                    executor=FixtureExecutor([response]),
                ).verify(network_id=NETWORK_ID, gateway_container_id=GATEWAY_ID)

    def test_attached_topology_requires_exact_gateway_and_worker_for_both_runtimes(self) -> None:
        docker = peer_inspected(
            Containers={
                GATEWAY_ID: {"Name": GATEWAY_NAME},
                WORKER_ID: {"Name": WORKER_NAME},
            }
        )
        podman = [
            podman_inspected(),
            podman_peers(
                (GATEWAY_ID, GATEWAY_NAME),
                (WORKER_ID, WORKER_NAME),
            ),
            podman_peer_container(GATEWAY_ID, GATEWAY_NAME),
            podman_peer_container(WORKER_ID, WORKER_NAME),
        ]
        for runtime, response in (("docker", docker), ("podman", podman)):
            with self.subTest(runtime=runtime):
                result = self.attachment_inspector(
                    response, runtime=runtime
                ).verify_attached(
                    network_id=NETWORK_ID,
                    gateway_container_id=GATEWAY_ID,
                    worker_container_id=WORKER_ID,
                )
                self.assertEqual(
                    result,
                    WorkerGatewayAttachmentResult(NETWORK_ID, GATEWAY_ID, WORKER_ID),
                )

    def test_podman_peer_discovery_rejects_ambiguous_or_unverified_members(self) -> None:
        malformed_listing = (
            CommandResult(0, b"not-json"),
            encoded({"Id": GATEWAY_ID}),
            podman_peers((GATEWAY_ID[:8], GATEWAY_NAME)),
            podman_peers((GATEWAY_ID, GATEWAY_NAME), State="exited"),
            podman_peers((GATEWAY_ID, GATEWAY_NAME), Networks=[NAME, "extra"]),
        )
        for listing in malformed_listing:
            with self.subTest(listing=listing), self.assertRaises(
                SnapshotCollectionError
            ):
                WorkerGatewayPeerInspector(
                    runtime="podman",
                    executable=Path("/usr/local/bin/podman"),
                    network_name=NAME,
                    gateway_container_name=GATEWAY_NAME,
                    executor=FixtureExecutor([podman_inspected(), listing]),
                ).verify(network_id=NETWORK_ID, gateway_container_id=GATEWAY_ID)

    def test_podman_attached_topology_rejects_an_extra_verified_peer(self) -> None:
        extra_id = "d" * 64
        with self.assertRaises(SnapshotCollectionError) as raised:
            self.attachment_inspector(
                [
                    podman_inspected(),
                    podman_peers(
                        (GATEWAY_ID, GATEWAY_NAME),
                        (WORKER_ID, WORKER_NAME),
                        (extra_id, "unexpected-peer"),
                    ),
                    podman_peer_container(GATEWAY_ID, GATEWAY_NAME),
                    podman_peer_container(WORKER_ID, WORKER_NAME),
                    podman_peer_container(extra_id, "unexpected-peer"),
                ],
                runtime="podman",
            ).verify_attached(
                network_id=NETWORK_ID,
                gateway_container_id=GATEWAY_ID,
                worker_container_id=WORKER_ID,
            )
        self.assertEqual(raised.exception.code, "WORKER_NETWORK_PEERS_INVALID")

        invalid_inspections = (
            podman_peer_container(GATEWAY_ID, GATEWAY_NAME, Name="renamed"),
            podman_peer_container(GATEWAY_ID, GATEWAY_NAME, State={"Running": False}),
            podman_peer_container(
                GATEWAY_ID,
                GATEWAY_NAME,
                NetworkSettings={"Networks": {"extra": {"NetworkID": NETWORK_ID}}},
            ),
            podman_peer_container(
                GATEWAY_ID,
                GATEWAY_NAME,
                NetworkSettings={"Networks": {NAME: {"NetworkID": NETWORK_ID}}},
            ),
            CommandResult(0, b"not-json"),
        )
        for inspection in invalid_inspections:
            with self.subTest(inspection=inspection), self.assertRaises(
                SnapshotCollectionError
            ):
                WorkerGatewayPeerInspector(
                    runtime="podman",
                    executable=Path("/usr/local/bin/podman"),
                    network_name=NAME,
                    gateway_container_name=GATEWAY_NAME,
                    executor=FixtureExecutor(
                        [
                            podman_inspected(),
                            podman_peers((GATEWAY_ID, GATEWAY_NAME)),
                            inspection,
                        ]
                    ),
                ).verify(network_id=NETWORK_ID, gateway_container_id=GATEWAY_ID)

    def test_attached_topology_denies_missing_extra_or_renamed_peers(self) -> None:
        exact = {
            GATEWAY_ID: {"Name": GATEWAY_NAME},
            WORKER_ID: {"Name": WORKER_NAME},
        }
        cases = (
            {},
            {GATEWAY_ID: {"Name": GATEWAY_NAME}},
            {**exact, "unexpected-peer": {"Name": "unexpected-peer"}},
            {**exact, GATEWAY_ID: {"Name": "renamed-gateway"}},
            {**exact, WORKER_ID: {"Name": "renamed-worker"}},
            {**exact, WORKER_ID: "malformed"},
        )
        for peers in cases:
            with self.subTest(peers=peers), self.assertRaises(SnapshotCollectionError):
                self.attachment_inspector(
                    peer_inspected(Containers=peers)
                ).verify_attached(
                    network_id=NETWORK_ID,
                    gateway_container_id=GATEWAY_ID,
                    worker_container_id=WORKER_ID,
                )

    def test_attached_topology_denies_ambiguous_identity_or_network_drift(self) -> None:
        exact = {
            GATEWAY_ID: {"Name": GATEWAY_NAME},
            WORKER_ID: {"Name": WORKER_NAME},
        }
        responses = (
            peer_inspected(Id="changed", Containers=exact),
            peer_inspected(Name="changed", Containers=exact),
            peer_inspected(Internal=False, Containers=exact),
            peer_inspected(EnableIPv6=True, Containers=exact),
            CommandResult(0, b"not-json"),
            CommandResult(1, b""),
        )
        for response in responses:
            with self.subTest(response=response), self.assertRaises(SnapshotCollectionError):
                self.attachment_inspector(response).verify_attached(
                    network_id=NETWORK_ID,
                    gateway_container_id=GATEWAY_ID,
                    worker_container_id=WORKER_ID,
                )
        with self.assertRaises(SnapshotCollectionError):
            self.attachment_inspector(peer_inspected(Containers=exact)).verify_attached(
                network_id=NETWORK_ID,
                gateway_container_id=GATEWAY_ID,
                worker_container_id=GATEWAY_ID,
            )

    def test_image_digest_normalizes_strict_docker_and_podman_forms(self) -> None:
        raw = "a" * 64
        self.assertEqual(normalize_oci_image_digest(raw), "sha256:" + raw)
        self.assertEqual(normalize_oci_image_digest("sha256:" + raw), "sha256:" + raw)
        for invalid in ("", "a" * 63, "A" * 64, "sha512:" + raw, " sha256:" + raw):
            with self.subTest(invalid=invalid), self.assertRaises(SnapshotCollectionError):
                normalize_oci_image_digest(invalid)

    def test_rootless_runtime_gate_requires_explicit_valid_evidence(self) -> None:
        accepted = (
            ("docker", DOCKER, {"SecurityOptions": ["name=rootless"]}),
            (
                "podman",
                Path("/usr/bin/podman"),
                {"host": {"security": {"rootless": True}}},
            ),
        )
        for runtime, executable, document in accepted:
            with self.subTest(runtime=runtime):
                executor = FixtureExecutor([encoded(document)])
                require_rootless_runtime(
                    runtime=runtime,
                    executable=executable,
                    executor=executor,
                )
                self.assertEqual(executor.calls[0][1], 10)

        denied = (
            ("docker", encoded({"SecurityOptions": ["name=seccomp"]})),
            ("podman", encoded({"host": {"security": {"rootless": False}}})),
            ("podman", encoded({"host": {"rootless": True}})),
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

    def test_podman_network_creation_uses_runtime_specific_identity_and_filter(self) -> None:
        executor = FixtureExecutor(
            [
                CommandResult(0, b""),
                CommandResult(0, NAME.encode()),
                encoded({"id": NETWORK_ID, "name": NAME}),
                podman_inspected(),
            ]
        )
        provisioned = ManagedGatewayNetworkProvisioner(
            runtime="podman",
            executable=Path("/usr/local/bin/podman"),
            network_name=NAME,
            pentai_instance_id=INSTANCE,
            executor=executor,
        )
        result = provisioned.ensure()
        self.assertEqual(result.network_id, NETWORK_ID)
        self.assertEqual(executor.calls[0][0][4], "name=" + NAME)
        self.assertIn("--disable-dns", executor.calls[1][0])

    def test_owned_fixture_subnet_is_explicit_and_test_net_only(self) -> None:
        executor = FixtureExecutor(
            [CommandResult(0, b""), CommandResult(0, NETWORK_ID.encode()), listed(), inspected()]
        )
        fixture = ManagedGatewayNetworkProvisioner(
            runtime="docker",
            executable=DOCKER,
            network_name=NAME,
            pentai_instance_id=INSTANCE,
            executor=executor,
            fixture_subnet="192.0.2.0/24",
        )
        fixture.ensure()
        command = executor.calls[1][0]
        self.assertEqual(command[command.index("--subnet") + 1], "192.0.2.0/24")
        with self.assertRaises(SnapshotCollectionError):
            ManagedGatewayNetworkProvisioner(
                runtime="docker",
                executable=DOCKER,
                network_name=NAME,
                pentai_instance_id=INSTANCE,
                executor=FixtureExecutor([]),
                fixture_subnet="10.0.0.0/8",
            )

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
        executor = FixtureExecutor([encoded(conformance())])
        result = OciNetworkConformanceProbe(
            executable=DOCKER, probe_image_digest=IMAGE, executor=executor
        ).verify(NETWORK_ID)
        self.assertTrue(result.direct_egress_blocked)
        command, timeout, output_limit = executor.calls[0]
        self.assertEqual(
            command[:4], (str(DOCKER), "run", "--log-driver=none", "--rm")
        )
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--security-opt=no-new-privileges", command)
        self.assertIn(IMAGE, command)
        self.assertIn("--network-id=" + NETWORK_ID, command)
        self.assertEqual((timeout, output_limit), (10, 4096))

    def test_probe_retries_only_bounded_startup_failures(self) -> None:
        pauses: list[float] = []
        executor = FixtureExecutor(
            [CommandResult(125, b""), CommandResult(125, b""), encoded(conformance())]
        )
        result = OciNetworkConformanceProbe(
            executable=DOCKER,
            probe_image_digest=IMAGE,
            executor=executor,
            sleeper=pauses.append,
        ).verify(NETWORK_ID)
        self.assertTrue(result.direct_egress_blocked)
        self.assertEqual(len(executor.calls), 3)
        self.assertEqual(pauses, [0.25, 0.25])

    def test_probe_persistent_startup_failure_denies_after_exact_bound(self) -> None:
        executor = FixtureExecutor([CommandResult(125, b"") for _ in range(3)])
        with self.assertRaises(SnapshotCollectionError) as raised:
            OciNetworkConformanceProbe(
                executable=DOCKER,
                probe_image_digest=IMAGE,
                executor=executor,
                sleeper=lambda _: None,
            ).verify(NETWORK_ID)
        self.assertEqual(raised.exception.code, "NETWORK_PROBE_STARTUP_FAILED")
        self.assertIn("3 bounded attempts", str(raised.exception))
        self.assertEqual(len(executor.calls), 3)

    def test_probe_does_not_retry_invalid_or_unsafe_success_output(self) -> None:
        executor = FixtureExecutor([encoded({"network_id": NETWORK_ID})])
        with self.assertRaises(SnapshotCollectionError) as raised:
            OciNetworkConformanceProbe(
                executable=DOCKER,
                probe_image_digest=IMAGE,
                executor=executor,
                sleeper=lambda _: self.fail("invalid output must not be retried"),
            ).verify(NETWORK_ID)
        self.assertEqual(raised.exception.code, "NETWORK_PROBE_INVALID")
        self.assertEqual(len(executor.calls), 1)

        probe_failure = FixtureExecutor([CommandResult(2, b"", b"probe rejected input")])
        with self.assertRaises(NetworkProbeExecutionError) as raised:
            OciNetworkConformanceProbe(
                executable=DOCKER,
                probe_image_digest=IMAGE,
                executor=probe_failure,
                sleeper=lambda _: self.fail("probe failures must not be retried"),
            ).verify(NETWORK_ID)
        self.assertEqual(raised.exception.code, "NETWORK_PROBE_FAILED")
        self.assertEqual(raised.exception.returncode, 2)
        self.assertEqual(raised.exception.stderr, b"probe rejected input")
        self.assertEqual(len(probe_failure.calls), 1)

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
