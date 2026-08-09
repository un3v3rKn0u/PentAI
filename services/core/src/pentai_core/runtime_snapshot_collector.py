from __future__ import annotations

import json
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from typing import BinaryIO, Protocol

from pentai_core.runtime_containment import GatewayNetworkSnapshot, RuntimeSnapshot


class SnapshotCollectionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes


class BoundedCommandExecutor(Protocol):
    def execute(
        self, argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
    ) -> CommandResult: ...


@dataclass(frozen=True)
class NetworkConformanceResult:
    network_id: str
    direct_egress_blocked: bool
    external_dns_blocked: bool
    ipv6_blocked: bool
    runtime_socket_blocked: bool
    host_mounts_blocked: bool
    host_namespaces_blocked: bool
    resource_limits_enforced: bool


class NetworkConformanceVerifier(Protocol):
    def verify(self, network_id: str) -> NetworkConformanceResult: ...


class LocalBoundedCommandExecutor:
    def __init__(self, executable: Path) -> None:
        resolved = executable.resolve(strict=True)
        mode = resolved.stat().st_mode
        if not executable.is_absolute() or not stat.S_ISREG(mode) or mode & 0o022:
            raise SnapshotCollectionError(
                "RUNTIME_EXECUTABLE_UNTRUSTED",
                "runtime executable must be an absolute, non-writable regular file",
            )
        self._executable = str(resolved)

    def execute(
        self, argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
    ) -> CommandResult:
        if (
            not argv
            or str(Path(argv[0]).resolve()) != self._executable
            or len(argv) > 32
            or any(not item or len(item) > 256 or "\x00" in item for item in argv)
        ):
            raise SnapshotCollectionError("RUNTIME_COMMAND_INVALID", "runtime command is invalid")
        if not 0 < timeout_seconds <= 10 or not 1 <= max_output_bytes <= 1_048_576:
            raise SnapshotCollectionError("RUNTIME_COMMAND_INVALID", "runtime bounds are invalid")

        try:
            process = subprocess.Popen(  # noqa: S603
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd="/",
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except OSError as exc:
            raise SnapshotCollectionError(
                "RUNTIME_COMMAND_FAILED", "runtime inspection could not start"
            ) from exc
        if process.stdout is None:
            process.kill()
            raise SnapshotCollectionError("RUNTIME_COMMAND_FAILED", "runtime output is unavailable")

        output: list[bytes] = []

        def read_output(stream: BinaryIO) -> None:
            output.append(stream.read(max_output_bytes + 1))
            stream.close()

        reader = Thread(target=read_output, args=(process.stdout,), daemon=True)
        reader.start()
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            reader.join(timeout=1)
            raise SnapshotCollectionError(
                "RUNTIME_COMMAND_TIMEOUT", "runtime inspection timed out"
            ) from exc
        reader.join(timeout=1)
        if reader.is_alive() or not output:
            process.kill()
            raise SnapshotCollectionError("RUNTIME_COMMAND_FAILED", "runtime output read failed")
        if len(output[0]) > max_output_bytes:
            raise SnapshotCollectionError(
                "RUNTIME_OUTPUT_TOO_LARGE", "runtime output exceeded limit"
            )
        return CommandResult(returncode, output[0])


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MANAGED_LABELS = {
    "com.pentai.managed": "true",
    "com.pentai.network-role": "worker-gateway",
    "com.pentai.direct-egress": "deny",
    "com.pentai.external-dns": "deny",
}


class OciRuntimeSnapshotCollector:
    def __init__(
        self,
        *,
        runtime: str,
        executable: Path,
        runtime_instance_id: str,
        gateway_network_id: str,
        pentai_instance_id: str,
        executor: BoundedCommandExecutor,
        network_conformance: NetworkConformanceVerifier,
    ) -> None:
        if runtime not in {"docker", "podman"}:
            raise SnapshotCollectionError("RUNTIME_UNSUPPORTED", "runtime is unsupported")
        identities = (runtime_instance_id, gateway_network_id, pentai_instance_id)
        if any(not _IDENTIFIER.fullmatch(value) for value in identities):
            raise SnapshotCollectionError("RUNTIME_IDENTITY_INVALID", "runtime identity is invalid")
        if not executable.is_absolute():
            raise SnapshotCollectionError(
                "RUNTIME_EXECUTABLE_UNTRUSTED", "runtime executable must be absolute"
            )
        self._runtime = runtime
        self._executable = str(executable)
        self._runtime_instance_id = runtime_instance_id
        self._gateway_network_id = gateway_network_id
        self._pentai_instance_id = pentai_instance_id
        self._executor = executor
        self._network_conformance = network_conformance

    def inspect_runtime(self) -> RuntimeSnapshot:
        document = self._run_json(self._info_command())
        if self._runtime == "docker":
            observed_id = document.get("ID")
            version = document.get("ServerVersion")
            security = document.get("SecurityOptions")
            rootless = isinstance(security, list) and any(
                isinstance(item, str) and "rootless" in item.lower() for item in security
            )
            limits = all(document.get(field) is True for field in ("MemoryLimit", "PidsLimit"))
        else:
            host = document.get("host")
            version_document = document.get("version")
            if not isinstance(host, dict):
                raise SnapshotCollectionError(
                    "RUNTIME_OUTPUT_INVALID", "runtime host data is missing"
                )
            observed_id = runtime_instance_identity("podman", document)
            version = (
                version_document.get("Version") if isinstance(version_document, dict) else None
            )
            security = host.get("security")
            rootless = isinstance(security, dict) and security.get("rootless") is True
            limits = rootless
        if observed_id != self._runtime_instance_id:
            raise SnapshotCollectionError("RUNTIME_IDENTITY_MISMATCH", "runtime identity changed")
        minimum = (24, 0) if self._runtime == "docker" else (4, 6)
        if _version_tuple(version) < minimum:
            raise SnapshotCollectionError(
                "RUNTIME_VERSION_UNSUPPORTED", "runtime version is unsupported"
            )
        if not rootless:
            raise SnapshotCollectionError("RUNTIME_ROOTLESS_REQUIRED", "runtime is not rootless")
        if not limits:
            raise SnapshotCollectionError(
                "RUNTIME_LIMITS_UNAVAILABLE", "runtime resource limits are unavailable"
            )

        return RuntimeSnapshot(
            runtime=self._runtime,
            runtime_instance_id=self._runtime_instance_id,
            rootless=rootless,
            read_only_root_supported=True,
            capability_drop_supported=True,
            no_new_privileges_supported=True,
            host_namespace_isolation_supported=True,
            resource_limits_supported=limits,
            temporary_mounts_supported=True,
            runtime_socket_mounted=False,
        )

    def inspect_gateway_network(self) -> GatewayNetworkSnapshot:
        document = self._run_json(self._network_command())
        labels = document.get("Labels") if self._runtime == "docker" else document.get("labels")
        internal = (
            document.get("Internal") if self._runtime == "docker" else document.get("internal")
        )
        ipv6 = (
            document.get("EnableIPv6")
            if self._runtime == "docker"
            else document.get("ipv6_enabled")
        )
        observed_id = document.get("Id") if self._runtime == "docker" else document.get("id")
        if observed_id != self._gateway_network_id:
            raise SnapshotCollectionError("NETWORK_IDENTITY_MISMATCH", "gateway network changed")
        required_labels = {**_MANAGED_LABELS, "com.pentai.instance-id": self._pentai_instance_id}
        labels_invalid = not isinstance(labels, dict) or any(
            labels.get(key) != value for key, value in required_labels.items()
        )
        if labels_invalid:
            raise SnapshotCollectionError(
                "NETWORK_OWNERSHIP_INVALID", "gateway network ownership is invalid"
            )
        safe_network = internal is True and ipv6 is False
        if not safe_network:
            raise SnapshotCollectionError(
                "NETWORK_ISOLATION_INVALID", "gateway network isolation is invalid"
            )
        try:
            conformance = self._network_conformance.verify(self._gateway_network_id)
        except Exception as exc:
            raise SnapshotCollectionError(
                "NETWORK_CONFORMANCE_FAILED", "gateway network conformance failed"
            ) from exc
        if conformance.network_id != self._gateway_network_id:
            raise SnapshotCollectionError(
                "NETWORK_CONFORMANCE_MISMATCH", "gateway network conformance identity changed"
            )
        if not all(
            value is True
            for value in (
                conformance.direct_egress_blocked,
                conformance.external_dns_blocked,
                conformance.ipv6_blocked,
                conformance.runtime_socket_blocked,
                conformance.host_mounts_blocked,
                conformance.host_namespaces_blocked,
                conformance.resource_limits_enforced,
            )
        ):
            raise SnapshotCollectionError(
                "NETWORK_CONFORMANCE_UNSAFE", "gateway network bypass probe failed"
            )
        return GatewayNetworkSnapshot(
            network_id=self._gateway_network_id,
            internal=True,
            gateway_is_only_egress=True,
            external_dns_disabled=True,
            ipv6_disabled=True,
        )

    def _info_command(self) -> tuple[str, ...]:
        if self._runtime == "docker":
            return (self._executable, "info", "--format", "{{json .}}")
        return (self._executable, "info", "--format", "json")

    def _network_command(self) -> tuple[str, ...]:
        template = "{{json .}}" if self._runtime == "docker" else "json"
        return (
            self._executable,
            "network",
            "inspect",
            "--format",
            template,
            self._gateway_network_id,
        )

    def _run_json(self, argv: tuple[str, ...]) -> dict[str, object]:
        try:
            result = self._executor.execute(argv, timeout_seconds=5, max_output_bytes=262_144)
        except SnapshotCollectionError:
            raise
        except Exception as exc:
            raise SnapshotCollectionError(
                "RUNTIME_INSPECTION_FAILED", "runtime inspection failed"
            ) from exc
        if result.returncode != 0:
            raise SnapshotCollectionError("RUNTIME_INSPECTION_FAILED", "runtime inspection failed")
        if len(result.stdout) > 262_144:
            raise SnapshotCollectionError(
                "RUNTIME_OUTPUT_TOO_LARGE", "runtime output exceeded limit"
            )
        try:
            decoded = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SnapshotCollectionError(
                "RUNTIME_OUTPUT_INVALID", "runtime output is invalid"
            ) from exc
        if isinstance(decoded, list) and len(decoded) == 1:
            decoded = decoded[0]
        if not isinstance(decoded, dict):
            raise SnapshotCollectionError("RUNTIME_OUTPUT_INVALID", "runtime output is invalid")
        return decoded


def _version_tuple(value: object) -> tuple[int, int]:
    if not isinstance(value, str):
        return (0, 0)
    match = re.match(r"^(\d+)\.(\d+)(?:\.|$)", value)
    if match is None:
        return (0, 0)
    return (int(match.group(1)), int(match.group(2)))


def runtime_instance_identity(runtime: str, document: dict[str, object]) -> str:
    if runtime == "docker":
        identity = document.get("ID")
    elif runtime == "podman":
        host = document.get("host")
        if not isinstance(host, dict):
            raise SnapshotCollectionError(
                "RUNTIME_OUTPUT_INVALID", "runtime host data is missing"
            )
        identity = host.get("machineId") or host.get("hostname")
    else:
        raise SnapshotCollectionError("RUNTIME_UNSUPPORTED", "runtime is unsupported")
    if not isinstance(identity, str) or not _IDENTIFIER.fullmatch(identity):
        raise SnapshotCollectionError(
            "RUNTIME_IDENTITY_INVALID", "runtime identity is unavailable"
        )
    return identity
