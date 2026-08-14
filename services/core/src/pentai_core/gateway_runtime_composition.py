from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from pentai_core.config import Settings
from pentai_core.gateway_http_fixture import GatewayFixtureCleanupRecovery
from pentai_core.gateway_runtime_lifecycle import (
    AssessmentSafetyControl,
    AuthorizationSafetyHandler,
    GatewayRuntimeLifecycle,
    LinuxProcCapabilityMonitor,
    OciGatewayFixtureController,
    RuntimeController,
)
from pentai_core.gateway_runtime_supervisor import (
    GatewayRuntimeLifecycleControl,
    GatewayRuntimeSupervisor,
    RuntimeSupervisorControl,
    SupervisorSnapshot,
    UnconfiguredGatewayRuntimeSupervisor,
)
from pentai_core.managed_gateway_network import OciNetworkConformanceProbe
from pentai_core.runtime_containment import RuntimeContainmentAttestor
from pentai_core.runtime_snapshot_collector import (
    BoundedCommandExecutor,
    LocalBoundedCommandExecutor,
    OciRuntimeSnapshotCollector,
)


class RuntimeAttestor(Protocol):
    def measure(self) -> dict[str, object]: ...


class FixtureCleanupControl(Protocol):
    def recover(self) -> int: ...


class RuntimeSafetyControl(AssessmentSafetyControl, Protocol):
    def set_global_safety(
        self, *, status: str, reason: str, actor_id: str
    ) -> dict[str, Any]: ...


class VerifiedGatewayRuntimeLifecycle:
    """Revalidate configured containment even when no sentinel is currently running."""

    def __init__(
        self,
        *,
        lifecycle: GatewayRuntimeLifecycleControl,
        attestor: RuntimeAttestor,
        fixture_cleanup: FixtureCleanupControl,
    ) -> None:
        self._lifecycle = lifecycle
        self._attestor = attestor
        self._fixture_cleanup = fixture_cleanup

    def recover(self) -> int:
        self._fixture_cleanup.recover()
        recovered = self._lifecycle.recover()
        self._attestor.measure()
        return recovered

    def check_all(self) -> int:
        self._attestor.measure()
        return self._lifecycle.check_all()


class UnavailableConfiguredRuntimeSupervisor:
    def __init__(self, *, pause_safety: Callable[[str], Any]) -> None:
        self._pause_safety = pause_safety
        self._snapshot = SupervisorSnapshot("stopped", None, 0, False)

    def start(self) -> None:
        reason = "GATEWAY_RUNTIME_COMPOSITION_FAILED"
        try:
            self._pause_safety(reason)
        except Exception:
            reason = "GATEWAY_SAFETY_PAUSE_FAILED"
        self._snapshot = SupervisorSnapshot("degraded", reason, 0, False)

    def stop(self) -> None:
        return

    def status(self) -> dict[str, object]:
        return self._snapshot.document()


def compose_gateway_runtime_supervisor(
    *,
    settings: Settings,
    safety_control: RuntimeSafetyControl,
    executor: BoundedCommandExecutor | None = None,
    attestor: RuntimeAttestor | None = None,
    controller: RuntimeController | None = None,
) -> RuntimeSupervisorControl:
    def pause_safety(reason: str) -> dict[str, Any]:
        return safety_control.set_global_safety(
            status="paused", reason=reason, actor_id="gateway-runtime-supervisor"
        )

    if not settings.gateway_runtime_enabled:
        return UnconfiguredGatewayRuntimeSupervisor(
            database_path=settings.database_path, pause_safety=pause_safety
        )
    try:
        runtime = _required(settings.gateway_runtime)
        executable = settings.gateway_runtime_executable
        runtime_instance_id = _required(settings.gateway_runtime_instance_id)
        network_id = _required(settings.gateway_network_id)
        probe_digest = _required(settings.gateway_probe_image_digest)
        instance_id = _required(settings.gateway_instance_id)
        if executable is None:
            raise ValueError("runtime executable is unavailable")
        command_executor = executor or LocalBoundedCommandExecutor(executable)
        runtime_attestor = attestor or _build_attestor(
            runtime=runtime,
            executable=executable,
            runtime_instance_id=runtime_instance_id,
            network_id=network_id,
            probe_digest=probe_digest,
            instance_id=instance_id,
            executor=command_executor,
        )
        runtime_controller = controller or OciGatewayFixtureController(
            runtime=runtime,
            executable=executable,
            executor=command_executor,
            capability_monitor=(
                LinuxProcCapabilityMonitor() if runtime == "podman" else None
            ),
        )
        lifecycle = GatewayRuntimeLifecycle(
            database_path=settings.database_path,
            controller=runtime_controller,
            monitor=runtime_attestor,
            safety=AuthorizationSafetyHandler(
                database_path=settings.database_path, safety_control=safety_control
            ),
        )
        verified = VerifiedGatewayRuntimeLifecycle(
            lifecycle=lifecycle,
            attestor=runtime_attestor,
            fixture_cleanup=GatewayFixtureCleanupRecovery(
                database_path=settings.database_path,
                executable=executable,
                executor=command_executor,
                pause_safety=pause_safety,
            ),
        )
        return GatewayRuntimeSupervisor(
            lifecycle=verified,
            pause_safety=pause_safety,
            interval_seconds=settings.gateway_watchdog_interval_seconds,
        )
    except Exception:
        return UnavailableConfiguredRuntimeSupervisor(pause_safety=pause_safety)


def _build_attestor(
    *,
    runtime: str,
    executable: Path,
    runtime_instance_id: str,
    network_id: str,
    probe_digest: str,
    instance_id: str,
    executor: BoundedCommandExecutor,
) -> RuntimeContainmentAttestor:
    probe = OciNetworkConformanceProbe(
        executable=executable,
        probe_image_digest=probe_digest,
        executor=executor,
    )
    collector = OciRuntimeSnapshotCollector(
        runtime=runtime,
        executable=executable,
        runtime_instance_id=runtime_instance_id,
        gateway_network_id=network_id,
        pentai_instance_id=instance_id,
        executor=executor,
        network_conformance=probe,
    )
    return RuntimeContainmentAttestor(collector)


def _required(value: str | None) -> str:
    if value is None:
        raise ValueError("runtime configuration is incomplete")
    return value
