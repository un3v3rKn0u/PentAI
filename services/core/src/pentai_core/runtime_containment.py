from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from pentai_core.worker_containment import (
    ContainmentError,
    validate_containment_attestation,
    validate_worker_containment_attestation,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


@dataclass(frozen=True)
class RuntimeSnapshot:
    runtime: str
    runtime_instance_id: str
    rootless: bool
    read_only_root_supported: bool
    capability_drop_supported: bool
    no_new_privileges_supported: bool
    host_namespace_isolation_supported: bool
    resource_limits_supported: bool
    temporary_mounts_supported: bool
    runtime_socket_mounted: bool


@dataclass(frozen=True)
class GatewayNetworkSnapshot:
    network_id: str
    internal: bool
    gateway_is_only_egress: bool
    external_dns_disabled: bool
    ipv6_disabled: bool


@dataclass(frozen=True)
class WorkerGatewayNetworkSnapshot:
    network_id: str
    gateway_container_id: str
    internal: bool
    gateway_is_only_peer: bool
    direct_egress_disabled: bool
    external_dns_disabled: bool
    ipv6_disabled: bool


class RuntimeInspector(Protocol):
    def inspect_runtime(self) -> RuntimeSnapshot: ...

    def inspect_gateway_network(self) -> GatewayNetworkSnapshot: ...


class WorkerRuntimeInspector(Protocol):
    def inspect_runtime(self) -> RuntimeSnapshot: ...

    def inspect_worker_gateway_network(self) -> WorkerGatewayNetworkSnapshot: ...


class WorkerGatewayPeerEvidence(Protocol):
    @property
    def network_id(self) -> str: ...

    @property
    def gateway_container_id(self) -> str: ...


class WorkerGatewayPeerVerifier(Protocol):
    def verify(
        self, *, network_id: str, gateway_container_id: str
    ) -> WorkerGatewayPeerEvidence: ...


class ComposedWorkerRuntimeInspector:
    """Combine existing runtime/network conformance with exact live peer evidence."""

    def __init__(
        self,
        *,
        runtime_inspector: RuntimeInspector,
        peer_verifier: WorkerGatewayPeerVerifier,
        worker_gateway_network_id: str,
        gateway_container_id: str,
    ) -> None:
        if any(
            not _IDENTIFIER.fullmatch(value)
            for value in (worker_gateway_network_id, gateway_container_id)
        ):
            raise ContainmentError(
                "CONTAINMENT_IDENTITY_INVALID", "worker network identity is invalid"
            )
        self._runtime_inspector = runtime_inspector
        self._peer_verifier = peer_verifier
        self._worker_gateway_network_id = worker_gateway_network_id
        self._gateway_container_id = gateway_container_id

    def inspect_runtime(self) -> RuntimeSnapshot:
        return self._runtime_inspector.inspect_runtime()

    def inspect_worker_gateway_network(self) -> WorkerGatewayNetworkSnapshot:
        network = self._runtime_inspector.inspect_gateway_network()
        peer = self._peer_verifier.verify(
            network_id=self._worker_gateway_network_id,
            gateway_container_id=self._gateway_container_id,
        )
        if (
            network.network_id != self._worker_gateway_network_id
            or peer.network_id != self._worker_gateway_network_id
            or peer.gateway_container_id != self._gateway_container_id
        ):
            raise ContainmentError(
                "CONTAINMENT_IDENTITY_INVALID", "worker network identity changed"
            )
        return WorkerGatewayNetworkSnapshot(
            network_id=network.network_id,
            gateway_container_id=peer.gateway_container_id,
            internal=network.internal,
            gateway_is_only_peer=True,
            direct_egress_disabled=network.gateway_is_only_egress,
            external_dns_disabled=network.external_dns_disabled,
            ipv6_disabled=network.ipv6_disabled,
        )


def _validate_runtime_controls(runtime: RuntimeSnapshot) -> None:
    if not all(
        value is True
        for value in (
            runtime.rootless,
            runtime.read_only_root_supported,
            runtime.capability_drop_supported,
            runtime.no_new_privileges_supported,
            runtime.host_namespace_isolation_supported,
            runtime.resource_limits_supported,
            runtime.temporary_mounts_supported,
        )
    ):
        raise ContainmentError(
            "CONTAINMENT_RUNTIME_UNSAFE", "runtime cannot enforce required containment"
        )
    if runtime.runtime_socket_mounted is not False:
        raise ContainmentError(
            "CONTAINMENT_RUNTIME_SOCKET", "runtime socket access is denied"
        )


class RuntimeContainmentAttestor:
    def __init__(self, inspector: RuntimeInspector, *, lifetime_seconds: int = 30) -> None:
        if not 1 <= lifetime_seconds <= 60:
            raise ContainmentError(
                "CONTAINMENT_LIFETIME_INVALID",
                "containment attestation lifetime must be 1–60 seconds",
            )
        self._inspector = inspector
        self._lifetime_seconds = lifetime_seconds

    def measure(self, *, now: datetime | None = None) -> dict[str, object]:
        observed_at = now or datetime.now(UTC)
        try:
            runtime = self._inspector.inspect_runtime()
            network = self._inspector.inspect_gateway_network()
        except Exception as exc:
            raise ContainmentError(
                "CONTAINMENT_INSPECTION_FAILED", "runtime containment inspection failed"
            ) from exc

        if runtime.runtime not in {"docker", "podman"}:
            raise ContainmentError("CONTAINMENT_RUNTIME_INVALID", "runtime is unsupported")
        if not runtime.runtime_instance_id.strip() or not network.network_id.strip():
            raise ContainmentError(
                "CONTAINMENT_IDENTITY_INVALID", "runtime or network identity is missing"
            )
        _validate_runtime_controls(runtime)
        if not all(
            value is True
            for value in (
                network.internal,
                network.gateway_is_only_egress,
                network.external_dns_disabled,
                network.ipv6_disabled,
            )
        ):
            raise ContainmentError(
                "CONTAINMENT_NETWORK_UNSAFE", "gateway-only worker network is unavailable"
            )

        document: dict[str, object] = {
            "schema_version": "1.0.0",
            "attestation_id": str(uuid4()),
            "runtime": runtime.runtime,
            "runtime_instance_id": runtime.runtime_instance_id.strip(),
            "rootless": True,
            "read_only_root": True,
            "capabilities_dropped": True,
            "no_new_privileges": True,
            "host_pid_disabled": True,
            "host_ipc_disabled": True,
            "host_network_disabled": True,
            "runtime_socket_mounted": False,
            "resource_limits_supported": True,
            "temporary_mounts_only": True,
            "gateway_network_id": network.network_id.strip(),
            "direct_egress_disabled": True,
            "external_dns_disabled": True,
            "ipv6_disabled": True,
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            "expires_at": (observed_at + timedelta(seconds=self._lifetime_seconds))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        validate_containment_attestation(document, now=observed_at)
        return document


class WorkerContainmentAttestor:
    """Issue v2 worker attestations from exact runtime and sole-gateway evidence."""

    def __init__(
        self,
        inspector: WorkerRuntimeInspector,
        *,
        worker_gateway_network_id: str,
        gateway_container_id: str,
        lifetime_seconds: int = 30,
    ) -> None:
        if any(
            not _IDENTIFIER.fullmatch(value)
            for value in (worker_gateway_network_id, gateway_container_id)
        ):
            raise ContainmentError(
                "CONTAINMENT_IDENTITY_INVALID", "worker network identity is invalid"
            )
        if not 1 <= lifetime_seconds <= 60:
            raise ContainmentError(
                "CONTAINMENT_LIFETIME_INVALID",
                "containment attestation lifetime must be 1–60 seconds",
            )
        self._inspector = inspector
        self._worker_gateway_network_id = worker_gateway_network_id
        self._gateway_container_id = gateway_container_id
        self._lifetime_seconds = lifetime_seconds

    def measure(self, *, now: datetime | None = None) -> dict[str, object]:
        try:
            runtime = self._inspector.inspect_runtime()
            network = self._inspector.inspect_worker_gateway_network()
        except ContainmentError:
            raise
        except Exception as exc:
            raise ContainmentError(
                "CONTAINMENT_INSPECTION_FAILED", "runtime containment inspection failed"
            ) from exc

        # Production measurements are timestamped only after every live inspection
        # completes so downstream launch planning does not inherit inspection time.
        observed_at = now or datetime.now(UTC)

        if runtime.runtime not in {"docker", "podman"}:
            raise ContainmentError("CONTAINMENT_RUNTIME_INVALID", "runtime is unsupported")
        if not _IDENTIFIER.fullmatch(runtime.runtime_instance_id):
            raise ContainmentError(
                "CONTAINMENT_IDENTITY_INVALID", "runtime identity is missing or invalid"
            )
        _validate_runtime_controls(runtime)
        if (
            network.network_id != self._worker_gateway_network_id
            or network.gateway_container_id != self._gateway_container_id
        ):
            raise ContainmentError(
                "CONTAINMENT_IDENTITY_INVALID", "worker network identity changed"
            )
        if not all(
            value is True
            for value in (
                network.internal,
                network.gateway_is_only_peer,
                network.direct_egress_disabled,
                network.external_dns_disabled,
                network.ipv6_disabled,
            )
        ):
            raise ContainmentError(
                "CONTAINMENT_NETWORK_UNSAFE", "worker gateway network is unavailable"
            )

        document: dict[str, object] = {
            "schema_version": "2.0.0",
            "attestation_id": str(uuid4()),
            "runtime": runtime.runtime,
            "runtime_instance_id": runtime.runtime_instance_id,
            "network_role": "worker_gateway",
            "rootless": True,
            "read_only_root": True,
            "capabilities_dropped": True,
            "no_new_privileges": True,
            "host_pid_disabled": True,
            "host_ipc_disabled": True,
            "host_network_disabled": True,
            "runtime_socket_mounted": False,
            "resource_limits_supported": True,
            "temporary_mounts_only": True,
            "worker_gateway_network_id": network.network_id,
            "direct_egress_disabled": True,
            "external_dns_disabled": True,
            "ipv6_disabled": True,
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            "expires_at": (observed_at + timedelta(seconds=self._lifetime_seconds))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        validate_worker_containment_attestation(document, now=observed_at)
        return document
