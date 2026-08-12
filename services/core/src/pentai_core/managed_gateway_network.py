from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import sleep
from typing import cast

from pentai_core.runtime_snapshot_collector import (
    BoundedCommandExecutor,
    NetworkConformanceResult,
    SnapshotCollectionError,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_RAW_SHA256 = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class ManagedNetworkResult:
    network_id: str
    created: bool


def normalize_oci_image_digest(value: str) -> str:
    if _DIGEST.fullmatch(value):
        return value
    if _RAW_SHA256.fullmatch(value):
        return f"sha256:{value}"
    raise SnapshotCollectionError("PROBE_DIGEST_INVALID", "image digest is invalid")


def require_rootless_runtime(
    *, runtime: str, executable: Path, executor: BoundedCommandExecutor
) -> None:
    if runtime not in {"docker", "podman"} or not executable.is_absolute():
        raise SnapshotCollectionError("RUNTIME_UNSUPPORTED", "runtime is unsupported")
    template = "{{json .}}" if runtime == "docker" else "json"
    result = executor.execute(
        (str(executable), "info", "--format", template),
        timeout_seconds=10,
        max_output_bytes=262_144,
    )
    if result.returncode != 0:
        raise SnapshotCollectionError("RUNTIME_INSPECTION_FAILED", "runtime inspection failed")
    try:
        document = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotCollectionError(
            "RUNTIME_OUTPUT_INVALID", "runtime output is invalid"
        ) from exc
    if not isinstance(document, dict):
        raise SnapshotCollectionError("RUNTIME_OUTPUT_INVALID", "runtime output is invalid")
    if runtime == "docker":
        security = document.get("SecurityOptions")
        rootless = isinstance(security, list) and any(
            isinstance(item, str) and "rootless" in item.lower() for item in security
        )
    else:
        host = document.get("host")
        security = host.get("security") if isinstance(host, dict) else None
        rootless = isinstance(security, dict) and security.get("rootless") is True
    if not rootless:
        raise SnapshotCollectionError("RUNTIME_ROOTLESS_REQUIRED", "runtime is not rootless")


class ManagedGatewayNetworkProvisioner:
    def __init__(
        self,
        *,
        runtime: str,
        executable: Path,
        network_name: str,
        pentai_instance_id: str,
        executor: BoundedCommandExecutor,
        fixture_subnet: str | None = None,
    ) -> None:
        if runtime not in {"docker", "podman"}:
            raise SnapshotCollectionError("RUNTIME_UNSUPPORTED", "runtime is unsupported")
        if not executable.is_absolute():
            raise SnapshotCollectionError(
                "RUNTIME_EXECUTABLE_UNTRUSTED", "runtime executable must be absolute"
            )
        if any(not _IDENTIFIER.fullmatch(value) for value in (network_name, pentai_instance_id)):
            raise SnapshotCollectionError("NETWORK_IDENTITY_INVALID", "network identity is invalid")
        self._runtime = runtime
        self._executable = str(executable)
        self._network_name = network_name
        self._pentai_instance_id = pentai_instance_id
        self._executor = executor
        if fixture_subnet not in {None, "192.0.2.0/24"}:
            raise SnapshotCollectionError(
                "NETWORK_FIXTURE_SUBNET_INVALID", "fixture subnet is invalid"
            )
        self._fixture_subnet = fixture_subnet

    def ensure(self) -> ManagedNetworkResult:
        existing = self._list_networks()
        if len(existing) > 1:
            raise SnapshotCollectionError(
                "NETWORK_IDENTITY_AMBIGUOUS", "network identity is ambiguous"
            )
        if existing:
            self._verify_network(existing[0])
            return ManagedNetworkResult(existing[0], False)

        result = self._executor.execute(
            self._create_command(), timeout_seconds=10, max_output_bytes=4096
        )
        if result.returncode != 0 or len(result.stdout) > 4096:
            raise SnapshotCollectionError(
                "NETWORK_CREATE_FAILED", "managed network creation failed"
            )
        created_identity = result.stdout.decode(errors="strict").strip()
        if not _IDENTIFIER.fullmatch(created_identity):
            raise SnapshotCollectionError(
                "NETWORK_CREATE_INVALID", "runtime returned an invalid network"
            )
        observed = self._list_networks()
        expected_create_output = (
            self._network_name if self._runtime == "podman" else observed[0] if observed else ""
        )
        if len(observed) != 1 or created_identity != expected_create_output:
            raise SnapshotCollectionError(
                "NETWORK_CREATE_UNVERIFIED", "created network was not verified"
            )
        network_id = observed[0]
        self._verify_network(network_id)
        return ManagedNetworkResult(network_id, True)

    def _verify_network(self, network_id: str) -> None:
        template = "{{json .}}" if self._runtime == "docker" else "json"
        result = self._executor.execute(
            (
                self._executable,
                "network",
                "inspect",
                "--format",
                template,
                network_id,
            ),
            timeout_seconds=5,
            max_output_bytes=65_536,
        )
        if result.returncode != 0 or len(result.stdout) > 65_536:
            raise SnapshotCollectionError("NETWORK_INSPECTION_FAILED", "network inspection failed")
        try:
            document = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SnapshotCollectionError(
                "NETWORK_OUTPUT_INVALID", "network inspection is invalid"
            ) from exc
        if isinstance(document, list) and len(document) == 1:
            document = document[0]
        if not isinstance(document, dict):
            raise SnapshotCollectionError("NETWORK_OUTPUT_INVALID", "network inspection is invalid")
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
        observed_name = document.get("Name") if self._runtime == "docker" else document.get("name")
        required_labels = {
            "com.pentai.managed": "true",
            "com.pentai.network-role": "worker-gateway",
            "com.pentai.direct-egress": "deny",
            "com.pentai.external-dns": "deny",
            "com.pentai.instance-id": self._pentai_instance_id,
        }
        if (
            observed_id != network_id
            or observed_name != self._network_name
            or internal is not True
            or ipv6 is not False
            or not isinstance(labels, dict)
            or any(labels.get(key) != value for key, value in required_labels.items())
        ):
            raise SnapshotCollectionError(
                "NETWORK_OWNERSHIP_INVALID", "managed network verification failed"
            )

    def _list_networks(self) -> list[str]:
        template = "{{json .}}" if self._runtime == "docker" else "json"
        result = self._executor.execute(
            (
                self._executable,
                "network",
                "ls",
                "--filter",
                (
                    f"name=^{self._network_name}$"
                    if self._runtime == "docker"
                    else f"name={self._network_name}"
                ),
                "--format",
                template,
            ),
            timeout_seconds=5,
            max_output_bytes=65_536,
        )
        if result.returncode != 0 or len(result.stdout) > 65_536:
            raise SnapshotCollectionError("NETWORK_INSPECTION_FAILED", "network listing failed")
        documents: list[object] = []
        raw = result.stdout.strip()
        if raw:
            try:
                decoded = json.loads(raw)
                documents = decoded if isinstance(decoded, list) else [decoded]
            except json.JSONDecodeError:
                try:
                    documents = [json.loads(line) for line in raw.splitlines()]
                except json.JSONDecodeError as exc:
                    raise SnapshotCollectionError(
                        "NETWORK_OUTPUT_INVALID", "network listing is invalid"
                    ) from exc
        identifiers: list[str] = []
        for document in documents:
            if not isinstance(document, dict):
                raise SnapshotCollectionError(
                    "NETWORK_OUTPUT_INVALID", "network listing is invalid"
                )
            name = document.get("Name") if self._runtime == "docker" else document.get("name")
            network_id = document.get("ID") if self._runtime == "docker" else document.get("id")
            if name != self._network_name or not isinstance(network_id, str):
                raise SnapshotCollectionError(
                    "NETWORK_IDENTITY_MISMATCH", "network identity changed"
                )
            identifiers.append(network_id)
        return identifiers

    def _create_command(self) -> tuple[str, ...]:
        labels = (
            "com.pentai.managed=true",
            "com.pentai.network-role=worker-gateway",
            "com.pentai.direct-egress=deny",
            "com.pentai.external-dns=deny",
            f"com.pentai.instance-id={self._pentai_instance_id}",
        )
        command = [
            self._executable,
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--ipv6=false",
        ]
        if self._runtime == "podman":
            command.append("--disable-dns")
        else:
            command.extend(("--opt", "com.docker.network.bridge.enable_ip_masquerade=false"))
        if self._fixture_subnet is not None:
            command.extend(("--subnet", self._fixture_subnet))
        for label in labels:
            command.extend(("--label", label))
        command.append(self._network_name)
        return tuple(command)


class OciNetworkConformanceProbe:
    def __init__(
        self,
        *,
        executable: Path,
        probe_image_digest: str,
        executor: BoundedCommandExecutor,
        startup_attempts: int = 3,
        startup_retry_seconds: float = 0.25,
        sleeper: Callable[[float], None] = sleep,
    ) -> None:
        if (
            not executable.is_absolute()
            or not _DIGEST.fullmatch(probe_image_digest)
            or not 1 <= startup_attempts <= 5
            or not 0 <= startup_retry_seconds <= 1
        ):
            raise SnapshotCollectionError("NETWORK_PROBE_INVALID", "network probe is invalid")
        self._executable = str(executable)
        self._probe_image_digest = probe_image_digest
        self._executor = executor
        self._startup_attempts = startup_attempts
        self._startup_retry_seconds = startup_retry_seconds
        self._sleeper = sleeper

    def verify(self, network_id: str) -> NetworkConformanceResult:
        if not _IDENTIFIER.fullmatch(network_id):
            raise SnapshotCollectionError("NETWORK_IDENTITY_INVALID", "network identity is invalid")
        command = (
            self._executable,
            "run",
            "--rm",
            "--network",
            network_id,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=16",
            "--memory=32m",
            "--cpus=0.25",
            "--entrypoint=/pentai-network-probe",
            self._probe_image_digest,
            "--format=json",
            f"--network-id={network_id}",
            "--direct-ip=192.0.2.1",
            "--dns-ip=192.0.2.53",
            "--ipv6=2001:db8::1",
        )
        result = None
        for attempt in range(1, self._startup_attempts + 1):
            result = self._executor.execute(
                command,
                timeout_seconds=10,
                max_output_bytes=4096,
            )
            if result.returncode != 125:
                break
            if attempt < self._startup_attempts:
                self._sleeper(self._startup_retry_seconds)
        assert result is not None
        if result.returncode == 125:
            raise SnapshotCollectionError(
                "NETWORK_PROBE_STARTUP_FAILED",
                f"network probe did not start after {self._startup_attempts} bounded attempts",
            )
        if result.returncode != 0:
            raise SnapshotCollectionError("NETWORK_PROBE_FAILED", "network probe failed")
        if len(result.stdout) > 4096:
            raise SnapshotCollectionError(
                "NETWORK_PROBE_INVALID", "network probe output is invalid"
            )
        try:
            document = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SnapshotCollectionError(
                "NETWORK_PROBE_INVALID", "network probe output is invalid"
            ) from exc
        if not isinstance(document, dict) or set(document) != {
            "network_id",
            "direct_egress_blocked",
            "external_dns_blocked",
            "ipv6_blocked",
            "runtime_socket_blocked",
            "host_mounts_blocked",
            "host_namespaces_blocked",
            "resource_limits_enforced",
        }:
            raise SnapshotCollectionError(
                "NETWORK_PROBE_INVALID", "network probe output is invalid"
            )
        if document.get("network_id") != network_id:
            raise SnapshotCollectionError(
                "NETWORK_PROBE_MISMATCH", "network probe identity changed"
            )
        values = tuple(
            document.get(field)
            for field in (
                "direct_egress_blocked",
                "external_dns_blocked",
                "ipv6_blocked",
                "runtime_socket_blocked",
                "host_mounts_blocked",
                "host_namespaces_blocked",
                "resource_limits_enforced",
            )
        )
        if any(type(value) is not bool for value in values):
            raise SnapshotCollectionError(
                "NETWORK_PROBE_INVALID", "network probe output is invalid"
            )
        return NetworkConformanceResult(
            network_id,
            cast(bool, values[0]),
            cast(bool, values[1]),
            cast(bool, values[2]),
            cast(bool, values[3]),
            cast(bool, values[4]),
            cast(bool, values[5]),
            cast(bool, values[6]),
        )
