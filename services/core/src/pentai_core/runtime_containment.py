from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from pentai_core.worker_containment import ContainmentError, validate_containment_attestation


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


class RuntimeInspector(Protocol):
    def inspect_runtime(self) -> RuntimeSnapshot: ...

    def inspect_gateway_network(self) -> GatewayNetworkSnapshot: ...


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

        required_runtime_controls = (
            runtime.rootless,
            runtime.read_only_root_supported,
            runtime.capability_drop_supported,
            runtime.no_new_privileges_supported,
            runtime.host_namespace_isolation_supported,
            runtime.resource_limits_supported,
            runtime.temporary_mounts_supported,
        )
        if not all(value is True for value in required_runtime_controls):
            raise ContainmentError(
                "CONTAINMENT_RUNTIME_UNSAFE", "runtime cannot enforce required containment"
            )
        if runtime.runtime_socket_mounted is not False:
            raise ContainmentError(
                "CONTAINMENT_RUNTIME_SOCKET", "runtime socket access is denied"
            )
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
