from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Protocol

from pentai_core.managed_gateway_network import normalize_oci_image_digest
from pentai_core.oci_runtime_command import oci_run_command
from pentai_core.runtime_snapshot_collector import (
    BoundedCommandExecutor,
    SnapshotCollectionError,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_CONTAINER_ID = re.compile(r"^[a-f0-9]{12,64}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_EMPTY_NETWORK_TEXT_FIELDS = frozenset(
    {
        "Bridge",
        "EndpointID",
        "Gateway",
        "GlobalIPv6Address",
        "IPAddress",
        "IPv6Gateway",
        "LinkLocalIPv6Address",
        "MacAddress",
        "SandboxID",
        "SandboxKey",
    }
)
_EMPTY_NETWORK_PREFIX_FIELDS = frozenset(
    {"GlobalIPv6PrefixLen", "GwPriority", "IPPrefixLen", "LinkLocalIPv6PrefixLen"}
)
_EMPTY_NETWORK_COLLECTION_FIELDS = frozenset(
    {
        "Aliases",
        "DNSNames",
        "DriverOpts",
        "IPAMConfig",
        "Links",
        "Options",
        "SecondaryIPAddresses",
        "SecondaryIPv6Addresses",
    }
)
_FALSE_NETWORK_FIELDS = frozenset({"HairpinMode"})


def _has_no_connectivity(
    values: dict[str, object], *, allow_network_identity: bool = False
) -> bool:
    allowed = (
        _EMPTY_NETWORK_TEXT_FIELDS
        | _EMPTY_NETWORK_PREFIX_FIELDS
        | _EMPTY_NETWORK_COLLECTION_FIELDS
        | _FALSE_NETWORK_FIELDS
        | {"Networks", "Ports"}
    )
    if allow_network_identity:
        allowed = allowed | {"NetworkID"}
    return (
        not (values.keys() - allowed)
        and all(values.get(key) in (None, "") for key in _EMPTY_NETWORK_TEXT_FIELDS)
        and all(values.get(key) in (None, 0) for key in _EMPTY_NETWORK_PREFIX_FIELDS)
        and all(values.get(key) in (None, [], {}) for key in _EMPTY_NETWORK_COLLECTION_FIELDS)
        and all(values.get(key) in (None, False) for key in _FALSE_NETWORK_FIELDS)
        and values.get("Ports") in (None, {})
    )


def _has_no_network_attachment(runtime: str, host: dict[str, object], network: object) -> bool:
    if not isinstance(network, dict) or not _has_no_connectivity(network):
        return False
    if host.get("PortBindings") not in (None, {}) or host.get("PublishAllPorts") not in (
        None,
        False,
    ):
        return False
    networks = network.get("Networks")
    if not isinstance(networks, dict):
        return False
    if runtime == "docker":
        return not networks
    if set(networks) != {"none"}:
        return False
    none_network = networks["none"]
    return (
        isinstance(none_network, dict)
        and _has_no_connectivity(none_network, allow_network_identity=True)
        and none_network.get("NetworkID") in (None, "", "none")
        and "Networks" not in none_network
        and "Ports" not in none_network
    )


class WorkerRuntimeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CapabilityMonitor(Protocol):
    def all_dropped(self, pid: int) -> bool: ...


class OciWorkerIsolationController:
    """Launch and verify a non-executing worker with no network attachment."""

    def __init__(
        self,
        *,
        runtime: str,
        executable: Path,
        executor: BoundedCommandExecutor,
        capability_monitor: CapabilityMonitor | None = None,
    ) -> None:
        if runtime not in {"docker", "podman"}:
            raise WorkerRuntimeError("WORKER_RUNTIME_UNSUPPORTED", "runtime is unsupported")
        if not executable.is_absolute():
            raise WorkerRuntimeError("WORKER_RUNTIME_UNTRUSTED", "runtime is untrusted")
        if runtime == "podman" and capability_monitor is None:
            raise WorkerRuntimeError(
                "WORKER_CAPABILITY_MONITOR_REQUIRED", "capability monitor is required"
            )
        self._runtime = runtime
        self._executable = str(executable)
        self._executor = executor
        self._capability_monitor = capability_monitor

    def launch(self, worker_id: str, image_digest: str) -> str:
        self._validate(worker_id, image_digest)
        result = self._executor.execute(
            oci_run_command(
                self._executable,
                "--detach",
                "--network=none",
                "--read-only",
                "--cap-drop=all",
                "--security-opt=no-new-privileges",
                "--pid=private",
                "--ipc=private",
                "--pids-limit=16",
                "--memory=32m",
                "--cpus=0.25",
                "--label=com.pentai.managed=true",
                "--label=com.pentai.runtime-role=worker-isolation",
                f"--label=com.pentai.worker-id={worker_id}",
                "--entrypoint=/pentai-network-probe",
                image_digest,
                "--mode=sentinel",
                f"--runtime-id={worker_id}",
            ),
            timeout_seconds=10,
            max_output_bytes=4096,
        )
        try:
            container_id = result.stdout.decode(errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise WorkerRuntimeError(
                "WORKER_LAUNCH_FAILED", "worker isolation launch failed"
            ) from exc
        if result.returncode != 0 or not _CONTAINER_ID.fullmatch(container_id):
            raise WorkerRuntimeError("WORKER_LAUNCH_FAILED", "worker isolation launch failed")
        return container_id

    def verify(self, worker_id: str, container_id: str, image_digest: str) -> None:
        self._validate(worker_id, image_digest)
        if not _CONTAINER_ID.fullmatch(container_id):
            raise WorkerRuntimeError("WORKER_RUNTIME_INVALID", "worker identity is invalid")
        result = self._executor.execute(
            (self._executable, "inspect", "--format", "{{json .}}", container_id),
            timeout_seconds=5,
            max_output_bytes=262_144,
        )
        if result.returncode != 0 or len(result.stdout) > 262_144:
            raise WorkerRuntimeError("WORKER_INSPECTION_FAILED", "worker inspection failed")
        try:
            document = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkerRuntimeError(
                "WORKER_INSPECTION_FAILED", "worker inspection failed"
            ) from exc
        if isinstance(document, list) and len(document) == 1:
            document = document[0]
        if not isinstance(document, dict):
            raise WorkerRuntimeError("WORKER_INSPECTION_FAILED", "worker inspection failed")
        state, config, host, network = (
            document.get(key) for key in ("State", "Config", "HostConfig", "NetworkSettings")
        )
        config_doc = config if isinstance(config, dict) else {}
        host_doc = host if isinstance(host, dict) else {}
        labels, security, cap_drop = (
            config_doc.get("Labels"),
            host_doc.get("SecurityOpt"),
            host_doc.get("CapDrop"),
        )
        cpu_quota, cpu_period = host_doc.get("CpuQuota"), host_doc.get("CpuPeriod")
        cpu_limited = host_doc.get("NanoCpus") == 250_000_000 or (
            type(cpu_quota) is int
            and type(cpu_period) is int
            and cpu_quota > 0
            and cpu_period > 0
            and cpu_quota * 4 <= cpu_period
        )
        podman = self._runtime == "podman"
        capabilities_dropped = (
            isinstance(state, dict)
            and type(state.get("Pid")) is int
            and self._capability_monitor is not None
            and self._capability_monitor.all_dropped(state["Pid"])
            if podman
            else isinstance(cap_drop, list) and any(str(v).lower() == "all" for v in cap_drop)
        )
        observed_image = document.get("Image")
        try:
            image_identity = (
                isinstance(observed_image, str)
                and normalize_oci_image_digest(observed_image) == image_digest
            )
        except SnapshotCollectionError:
            image_identity = False
        checks = {
            "container_identity": document.get("Id") == container_id,
            "running": isinstance(state, dict) and state.get("Running") is True,
            "image_identity": image_identity,
            "network_mode": host_doc.get("NetworkMode") == "none",
            "network_attachments": _has_no_network_attachment(self._runtime, host_doc, network),
            "read_only_root": host_doc.get("ReadonlyRootfs") is True,
            "non_privileged": host_doc.get("Privileged") is False,
            "private_pid": host_doc.get("PidMode") in ("", "private", None),
            "private_ipc": host_doc.get("IpcMode") in ("", "private", None),
            "pid_limit": host_doc.get("PidsLimit") == 16,
            "memory_limit": host_doc.get("Memory") == 33_554_432,
            "cpu_limit": cpu_limited,
            "capabilities_dropped": capabilities_dropped,
            "no_new_privileges": isinstance(security, list)
            and any("no-new-privileges" in str(v).lower() for v in security),
            "no_binds": host_doc.get("Binds") in (None, []),
            "ownership_labels": isinstance(labels, dict)
            and labels.get("com.pentai.managed") == "true"
            and labels.get("com.pentai.runtime-role") == "worker-isolation"
            and labels.get("com.pentai.worker-id") == worker_id,
        }
        failed = sorted(name for name, passed in checks.items() if not passed)
        if failed:
            raise WorkerRuntimeError(
                "WORKER_CONTAINMENT_INVALID",
                "worker containment changed: " + ",".join(failed),
            )

    def terminate(self, container_id: str) -> None:
        if not _CONTAINER_ID.fullmatch(container_id):
            raise WorkerRuntimeError("WORKER_RUNTIME_INVALID", "worker identity is invalid")
        command = [self._executable, "rm", "--force"]
        if self._runtime == "podman":
            command.append("--time=0")
        command.append(container_id)
        result = self._executor.execute(
            tuple(command),
            timeout_seconds=5,
            max_output_bytes=4096,
        )
        if result.returncode != 0:
            raise WorkerRuntimeError("WORKER_TERMINATION_FAILED", "worker termination failed")

    @staticmethod
    def _validate(worker_id: str, image_digest: str) -> None:
        if not _IDENTIFIER.fullmatch(worker_id) or not _DIGEST.fullmatch(image_digest):
            raise WorkerRuntimeError("WORKER_RUNTIME_INVALID", "worker identity is invalid")
