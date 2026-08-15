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
        "Image": IMAGE,
        "State": {"Running": True},
        "Config": {
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


@dataclass
class CapabilityMonitor:
    result: bool = True
    pids: list[int] = field(default_factory=list)

    def all_dropped(self, pid: int) -> bool:
        self.pids.append(pid)
        return self.result


def controller(executor: Executor) -> OciWorkerIsolationController:
    return OciWorkerIsolationController(runtime="docker", executable=OCI, executor=executor)


class WorkerRuntimeTests(unittest.TestCase):
    def test_launches_digest_pinned_sentinel_without_network(self) -> None:
        executor = Executor([CommandResult(0, CONTAINER.encode())])
        self.assertEqual(
            controller(executor).launch(WORKER, IMAGE),
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
        controller(executor).verify(WORKER, CONTAINER, IMAGE)

    def test_podman_uses_live_process_capabilities_and_bounded_termination(self) -> None:
        document = inspection()
        document["Image"] = "a" * 64
        state = document["State"]
        assert isinstance(state, dict)
        state["Pid"] = 1234
        host = document["HostConfig"]
        assert isinstance(host, dict)
        host["CapDrop"] = []
        monitor = CapabilityMonitor()
        executor = Executor(
            [CommandResult(0, json.dumps(document).encode()), CommandResult(0, b"")]
        )
        podman = OciWorkerIsolationController(
            runtime="podman",
            executable=Path("/usr/bin/podman"),
            executor=executor,
            capability_monitor=monitor,
        )
        podman.verify(WORKER, CONTAINER, IMAGE)
        podman.terminate(CONTAINER)
        self.assertEqual(monitor.pids, [1234])
        self.assertEqual(executor.calls[1][-2:], ("--time=0", CONTAINER))

        monitor.result = False
        denied = OciWorkerIsolationController(
            runtime="podman",
            executable=Path("/usr/bin/podman"),
            executor=Executor([CommandResult(0, json.dumps(document).encode())]),
            capability_monitor=monitor,
        )
        with self.assertRaises(WorkerRuntimeError) as raised:
            denied.verify(WORKER, CONTAINER, IMAGE)
        self.assertEqual(raised.exception.code, "WORKER_CONTAINMENT_INVALID")

    def test_each_network_or_identity_drift_denies(self) -> None:
        cases = (
            ("HostConfig", "NetworkMode", "bridge", "network_mode"),
            ("NetworkSettings", "Networks", {"bridge": {}}, "network_attachments"),
            ("root", "Image", "sha256:" + "c" * 64, "image_identity"),
            ("root", "Image", "latest", "image_identity"),
            ("Config", "Labels", {}, "ownership_labels"),
            ("HostConfig", "Privileged", True, "non_privileged"),
            ("HostConfig", "Binds", ["/host-data:/worker-data"], "no_binds"),
        )
        for section, key, value, failed_control in cases:
            with self.subTest(key=key):
                document = copy.deepcopy(inspection())
                if section == "root":
                    document[key] = value
                else:
                    parent = document[section]
                    assert isinstance(parent, dict)
                    parent[key] = value
                runtime_controller = controller(
                    Executor([CommandResult(0, json.dumps(document).encode())])
                )
                with self.assertRaises(WorkerRuntimeError) as raised:
                    runtime_controller.verify(WORKER, CONTAINER, IMAGE)
                self.assertEqual(raised.exception.code, "WORKER_CONTAINMENT_INVALID")
                self.assertIn(failed_control, str(raised.exception))

    def test_invalid_inputs_and_subprocess_failures_deny(self) -> None:
        runtime_controller = controller(Executor([CommandResult(1, b"")]))
        with self.assertRaises(WorkerRuntimeError):
            runtime_controller.launch("bad worker", IMAGE)
        with self.assertRaises(WorkerRuntimeError) as raised:
            runtime_controller.launch(WORKER, IMAGE)
        self.assertEqual(raised.exception.code, "WORKER_LAUNCH_FAILED")

        with self.assertRaises(WorkerRuntimeError):
            OciWorkerIsolationController(
                runtime="podman", executable=Path("/usr/bin/podman"), executor=Executor([])
            )

    def test_termination_is_id_bound(self) -> None:
        executor = Executor([CommandResult(0, b"")])
        runtime_controller = controller(executor)
        runtime_controller.terminate(CONTAINER)
        self.assertEqual(executor.calls[0], (str(OCI), "rm", "--force", CONTAINER))
        with self.assertRaises(WorkerRuntimeError):
            runtime_controller.terminate("not-a-container")


if __name__ == "__main__":
    unittest.main()
