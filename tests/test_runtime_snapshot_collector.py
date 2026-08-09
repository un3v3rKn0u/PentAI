from __future__ import annotations

import json
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from pentai_core.runtime_containment import RuntimeContainmentAttestor
from pentai_core.runtime_snapshot_collector import (
    CommandResult,
    LocalBoundedCommandExecutor,
    NetworkConformanceResult,
    OciRuntimeSnapshotCollector,
    SnapshotCollectionError,
)

DOCKER = Path("/usr/local/bin/docker")
INSTANCE = "fixture-runtime"
NETWORK = "fixture-network"
PENTAI = "fixture-pentai"


def docker_info(**updates: object) -> dict[str, object]:
    document: dict[str, object] = {
        "ID": INSTANCE,
        "ServerVersion": "29.6.2",
        "SecurityOptions": ["name=seccomp", "name=rootless"],
        "MemoryLimit": True,
        "PidsLimit": True,
    }
    document.update(updates)
    return document


def docker_network(**updates: object) -> dict[str, object]:
    document: dict[str, object] = {
        "Id": NETWORK,
        "Internal": True,
        "EnableIPv6": False,
        "Labels": {
            "com.pentai.managed": "true",
            "com.pentai.network-role": "worker-gateway",
            "com.pentai.direct-egress": "deny",
            "com.pentai.external-dns": "deny",
            "com.pentai.instance-id": PENTAI,
        },
    }
    document.update(updates)
    return document


@dataclass
class FixtureExecutor:
    responses: list[CommandResult]
    commands: list[tuple[str, ...]] = field(default_factory=list)

    def execute(
        self, argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
    ) -> CommandResult:
        self.commands.append(argv)
        if timeout_seconds != 5 or max_output_bytes != 262_144:
            raise AssertionError("collector did not apply fixed bounds")
        return self.responses.pop(0)


@dataclass(frozen=True)
class FixtureConformance:
    result: NetworkConformanceResult = NetworkConformanceResult(
        NETWORK, True, True, True, True, True, True, True
    )

    def verify(self, network_id: str) -> NetworkConformanceResult:
        if network_id != NETWORK:
            raise AssertionError("unexpected network identity")
        return self.result


def response(document: object, *, returncode: int = 0) -> CommandResult:
    return CommandResult(returncode, json.dumps(document).encode())


def collector(executor: FixtureExecutor) -> OciRuntimeSnapshotCollector:
    return OciRuntimeSnapshotCollector(
        runtime="docker",
        executable=DOCKER,
        runtime_instance_id=INSTANCE,
        gateway_network_id=NETWORK,
        pentai_instance_id=PENTAI,
        executor=executor,
        network_conformance=FixtureConformance(),
    )


class RuntimeSnapshotCollectorTests(unittest.TestCase):
    def test_fixed_commands_produce_safe_typed_snapshots(self) -> None:
        executor = FixtureExecutor([response(docker_info()), response(docker_network())])
        inspected = collector(executor)
        runtime = inspected.inspect_runtime()
        network = inspected.inspect_gateway_network()
        self.assertTrue(runtime.rootless)
        self.assertTrue(runtime.resource_limits_supported)
        self.assertTrue(network.gateway_is_only_egress)
        self.assertEqual(
            executor.commands,
            [
                (str(DOCKER), "info", "--format", "{{json .}}"),
                (
                    str(DOCKER),
                    "network",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    NETWORK,
                ),
            ],
        )

    def test_collector_drives_contract_valid_attestation(self) -> None:
        executor = FixtureExecutor([response(docker_info()), response(docker_network())])
        result = RuntimeContainmentAttestor(collector(executor)).measure()
        self.assertEqual(result["runtime_instance_id"], INSTANCE)
        self.assertEqual(result["gateway_network_id"], NETWORK)
        self.assertFalse(result["runtime_socket_mounted"])

    def test_podman_uses_fixed_commands_and_requires_rootless_security(self) -> None:
        executable = Path("/usr/local/bin/podman")
        executor = FixtureExecutor(
            [
                response(
                    {
                        "host": {
                            "machineId": INSTANCE,
                            "security": {"rootless": True},
                        },
                        "version": {"Version": "5.6.0"},
                    }
                ),
                response(
                    {
                        "id": NETWORK,
                        "internal": True,
                        "ipv6_enabled": False,
                        "labels": docker_network()["Labels"],
                    }
                ),
            ]
        )
        inspected = OciRuntimeSnapshotCollector(
            runtime="podman",
            executable=executable,
            runtime_instance_id=INSTANCE,
            gateway_network_id=NETWORK,
            pentai_instance_id=PENTAI,
            executor=executor,
            network_conformance=FixtureConformance(),
        )
        self.assertTrue(inspected.inspect_runtime().rootless)
        self.assertTrue(inspected.inspect_gateway_network().internal)
        self.assertEqual(
            executor.commands,
            [
                (str(executable), "info", "--format", "json"),
                (
                    str(executable),
                    "network",
                    "inspect",
                    "--format",
                    "json",
                    NETWORK,
                ),
            ],
        )

    def test_runtime_identity_rootless_limits_and_version_fail_closed(self) -> None:
        cases = (
            (docker_info(ID="other-runtime"), "RUNTIME_IDENTITY_MISMATCH"),
            (docker_info(SecurityOptions=["name=seccomp"]), "RUNTIME_ROOTLESS_REQUIRED"),
            (docker_info(MemoryLimit=False), "RUNTIME_LIMITS_UNAVAILABLE"),
            (docker_info(ServerVersion="23.0.9"), "RUNTIME_VERSION_UNSUPPORTED"),
        )
        for document, expected in cases:
            with (
                self.subTest(expected=expected),
                self.assertRaises(SnapshotCollectionError) as raised,
            ):
                collector(FixtureExecutor([response(document)])).inspect_runtime()
            self.assertEqual(raised.exception.code, expected)

    def test_network_identity_ownership_and_isolation_fail_closed(self) -> None:
        bad_labels = dict(docker_network()["Labels"])
        bad_labels["com.pentai.instance-id"] = "other-pentai"
        cases = (
            (docker_network(Id="other-network"), "NETWORK_IDENTITY_MISMATCH"),
            (docker_network(Labels=bad_labels), "NETWORK_OWNERSHIP_INVALID"),
            (docker_network(Internal=False), "NETWORK_ISOLATION_INVALID"),
            (docker_network(EnableIPv6=True), "NETWORK_ISOLATION_INVALID"),
        )
        for document, expected in cases:
            with (
                self.subTest(expected=expected),
                self.assertRaises(SnapshotCollectionError) as raised,
            ):
                collector(FixtureExecutor([response(document)])).inspect_gateway_network()
            self.assertEqual(raised.exception.code, expected)

    def test_malformed_failed_and_oversized_results_deny(self) -> None:
        cases = (
            (CommandResult(1, b""), "RUNTIME_INSPECTION_FAILED"),
            (CommandResult(0, b"not-json"), "RUNTIME_OUTPUT_INVALID"),
            (response([docker_info(), docker_info()]), "RUNTIME_OUTPUT_INVALID"),
            (CommandResult(0, b"x" * 262_145), "RUNTIME_OUTPUT_TOO_LARGE"),
        )
        for result, expected in cases:
            with (
                self.subTest(expected=expected),
                self.assertRaises(SnapshotCollectionError) as raised,
            ):
                collector(FixtureExecutor([result])).inspect_runtime()
            self.assertEqual(raised.exception.code, expected)

    def test_constructor_rejects_untrusted_identifiers_and_executable(self) -> None:
        for network_id in ("", "--host-network", "x" * 129):
            with self.subTest(network_id=network_id), self.assertRaises(SnapshotCollectionError):
                OciRuntimeSnapshotCollector(
                    runtime="docker",
                    executable=DOCKER,
                    runtime_instance_id=INSTANCE,
                    gateway_network_id=network_id,
                    pentai_instance_id=PENTAI,
                    executor=FixtureExecutor([]),
                    network_conformance=FixtureConformance(),
                )
        with self.assertRaises(SnapshotCollectionError):
            OciRuntimeSnapshotCollector(
                runtime="docker",
                executable=Path("docker"),
                runtime_instance_id=INSTANCE,
                gateway_network_id=NETWORK,
                pentai_instance_id=PENTAI,
                executor=FixtureExecutor([]),
                network_conformance=FixtureConformance(),
            )

    def test_network_probe_failure_and_identity_mismatch_deny(self) -> None:
        cases = (
            (
                NetworkConformanceResult("other-network", True, True, True, True, True, True, True),
                "NETWORK_CONFORMANCE_MISMATCH",
            ),
            (
                NetworkConformanceResult(NETWORK, False, True, True, True, True, True, True),
                "NETWORK_CONFORMANCE_UNSAFE",
            ),
            (
                NetworkConformanceResult(NETWORK, True, False, True, True, True, True, True),
                "NETWORK_CONFORMANCE_UNSAFE",
            ),
            (
                NetworkConformanceResult(NETWORK, True, True, False, True, True, True, True),
                "NETWORK_CONFORMANCE_UNSAFE",
            ),
            (
                NetworkConformanceResult(NETWORK, True, True, True, False, True, True, True),
                "NETWORK_CONFORMANCE_UNSAFE",
            ),
            (
                NetworkConformanceResult(NETWORK, True, True, True, True, False, True, True),
                "NETWORK_CONFORMANCE_UNSAFE",
            ),
            (
                NetworkConformanceResult(NETWORK, True, True, True, True, True, False, True),
                "NETWORK_CONFORMANCE_UNSAFE",
            ),
            (
                NetworkConformanceResult(NETWORK, True, True, True, True, True, True, False),
                "NETWORK_CONFORMANCE_UNSAFE",
            ),
        )
        for conformance, expected in cases:
            with (
                self.subTest(expected=expected),
                self.assertRaises(SnapshotCollectionError) as raised,
            ):
                OciRuntimeSnapshotCollector(
                    runtime="docker",
                    executable=DOCKER,
                    runtime_instance_id=INSTANCE,
                    gateway_network_id=NETWORK,
                    pentai_instance_id=PENTAI,
                    executor=FixtureExecutor([response(docker_network())]),
                    network_conformance=FixtureConformance(conformance),
                ).inspect_gateway_network()
            self.assertEqual(raised.exception.code, expected)

    def test_local_executor_rejects_command_and_bound_changes(self) -> None:
        executable = Path("/bin/echo")
        runner = LocalBoundedCommandExecutor(executable)
        with self.assertRaises(SnapshotCollectionError):
            runner.execute(("/bin/date",), timeout_seconds=1, max_output_bytes=100)
        with self.assertRaises(SnapshotCollectionError):
            runner.execute((str(executable), "ok"), timeout_seconds=11, max_output_bytes=100)


if __name__ == "__main__":
    unittest.main()
