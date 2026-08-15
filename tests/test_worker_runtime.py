from __future__ import annotations

import copy
import json
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from pentai_core.runtime_snapshot_collector import CommandResult
from pentai_core.worker_runtime import OciWorkerIsolationController, WorkerRuntimeError

OCI = Path("/usr/bin/docker")
WORKER, CONTAINER, IMAGE = "worker-fixture", "b" * 64, "sha256:" + "a" * 64


def inspection() -> dict[str, object]:
    return {
        "Id": CONTAINER,
        "State": {"Running": True},
        "Config": {
            "Image": IMAGE,
            "Labels": {
                "com.pentai.managed": "true",
                "com.pentai.runtime-role": "worker-isolation",
                "com.pentai.worker-id": WORKER,
            },
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "PidMode": "private",
            "IpcMode": "private",
            "PidsLimit": 16,
            "Memory": 33_554_432,
            "NanoCpus": 250_000_000,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "Binds": None,
        },
        "NetworkSettings": {"Networks": {}},
    }


@dataclass
class Executor:
    responses: list[CommandResult]
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def execute(
        self, argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
    ) -> CommandResult:
        self.calls.append(argv)
        return self.responses.pop(0)


class WorkerRuntimeTests(unittest.TestCase):
    def test_launches_digest_pinned_sentinel_without_network(self) -> None:
        executor = Executor([CommandResult(0, CONTAINER.encode())])
        self.assertEqual(
            OciWorkerIsolationController(executable=OCI, executor=executor).launch(WORKER, IMAGE),
            CONTAINER,
        )
        command = executor.calls[0]
        for expected in (
            "--network=none",
            "--read-only",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            IMAGE,
        ):
            self.assertIn(expected, command)

    def test_verifies_exact_runtime_identity_and_no_networks(self) -> None:
        executor = Executor([CommandResult(0, json.dumps(inspection()).encode())])
        OciWorkerIsolationController(executable=OCI, executor=executor).verify(
            WORKER, CONTAINER, IMAGE
        )

    def test_each_network_or_identity_drift_denies(self) -> None:
        cases = (
            ("HostConfig", "NetworkMode", "bridge"),
            ("NetworkSettings", "Networks", {"bridge": {}}),
            ("Config", "Image", "sha256:" + "c" * 64),
            ("Config", "Labels", {}),
            ("HostConfig", "Privileged", True),
            ("HostConfig", "Binds", ["/host-data:/worker-data"]),
        )
        for section, key, value in cases:
            with self.subTest(key=key):
                document = copy.deepcopy(inspection())
                parent = document[section]
                assert isinstance(parent, dict)
                parent[key] = value
                controller = OciWorkerIsolationController(
                    executable=OCI,
                    executor=Executor([CommandResult(0, json.dumps(document).encode())]),
                )
                with self.assertRaises(WorkerRuntimeError) as raised:
                    controller.verify(WORKER, CONTAINER, IMAGE)
                self.assertEqual(raised.exception.code, "WORKER_CONTAINMENT_INVALID")

    def test_invalid_inputs_and_subprocess_failures_deny(self) -> None:
        controller = OciWorkerIsolationController(
            executable=OCI, executor=Executor([CommandResult(1, b"")])
        )
        with self.assertRaises(WorkerRuntimeError):
            controller.launch("bad worker", IMAGE)
        with self.assertRaises(WorkerRuntimeError) as raised:
            controller.launch(WORKER, IMAGE)
        self.assertEqual(raised.exception.code, "WORKER_LAUNCH_FAILED")

    def test_termination_is_id_bound(self) -> None:
        executor = Executor([CommandResult(0, b"")])
        controller = OciWorkerIsolationController(executable=OCI, executor=executor)
        controller.terminate(CONTAINER)
        self.assertEqual(executor.calls[0], (str(OCI), "rm", "--force", CONTAINER))
        with self.assertRaises(WorkerRuntimeError):
            controller.terminate("not-a-container")


if __name__ == "__main__":
    unittest.main()
