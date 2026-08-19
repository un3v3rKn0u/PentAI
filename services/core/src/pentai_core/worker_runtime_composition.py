from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from pentai_core.config import Settings
from pentai_core.gateway_runtime_lifecycle import LinuxProcCapabilityMonitor
from pentai_core.managed_gateway_network import (
    OciNetworkConformanceProbe,
    WorkerGatewayAttachmentInspector,
    WorkerGatewayPeerInspector,
)
from pentai_core.runtime_containment import (
    ComposedWorkerRuntimeInspector,
    WorkerContainmentAttestor,
)
from pentai_core.runtime_snapshot_collector import (
    BoundedCommandExecutor,
    LocalBoundedCommandExecutor,
    OciRuntimeSnapshotCollector,
)
from pentai_core.worker_attachment_recovery import WorkerAttachmentRecovery
from pentai_core.worker_attachment_registry import DurableWorkerAttachmentRegistry
from pentai_core.worker_containment_supervisor import (
    AttachmentAwareWorkerContainmentMonitor,
    UnconfiguredWorkerContainmentSupervisor,
    WorkerContainmentBinding,
    WorkerContainmentMonitor,
    WorkerContainmentSupervisor,
    WorkerSupervisionBinding,
    WorkerSupervisorControl,
)
from pentai_core.worker_fixture_execution import (
    DurableWorkerFixtureExecutionRegistry,
    WorkerFixtureExecutionRecovery,
)
from pentai_core.worker_runtime import OciWorkerIsolationController
from pentai_core.worker_runtime_recovery import WorkerRuntimeRecovery
from pentai_core.worker_runtime_registry import DurableWorkerRuntimeRegistry


class WorkerAttestor(Protocol):
    def measure(self) -> dict[str, object]: ...


class WorkerSafetyControl(Protocol):
    def set_global_safety(
        self, *, status: str, reason: str, actor_id: str
    ) -> dict[str, Any]: ...


class UnavailableConfiguredWorkerSupervisor:
    def __init__(self, *, pause_safety: Callable[[str], object]) -> None:
        self._pause_safety = pause_safety
        self._status = {
            "status": "stopped",
            "reason_code": None,
            "monitored_workers": 0,
            "watchdog_running": False,
            "execution_enabled": False,
        }

    def start(self) -> None:
        reason = "WORKER_SUPERVISION_COMPOSITION_FAILED"
        try:
            self._pause_safety(reason)
        except Exception:
            reason = "WORKER_SAFETY_PAUSE_FAILED"
        self._status = {**self._status, "status": "degraded", "reason_code": reason}

    def stop(self) -> None:
        return

    def status(self) -> dict[str, object]:
        return dict(self._status)


def compose_worker_runtime_supervisor(
    *,
    settings: Settings,
    safety_control: WorkerSafetyControl,
    executor: BoundedCommandExecutor | None = None,
    baseline_attestor: WorkerAttestor | None = None,
    monitor: WorkerContainmentMonitor | None = None,
) -> WorkerSupervisorControl:
    def pause_safety(reason: str) -> object:
        return safety_control.set_global_safety(
            status="paused", reason=reason, actor_id="worker-runtime-supervisor"
        )

    if not settings.worker_supervision_enabled:
        return UnconfiguredWorkerContainmentSupervisor(
            database_path=settings.database_path, pause_safety=pause_safety
        )
    try:
        runtime = _required(settings.gateway_runtime)
        executable = settings.gateway_runtime_executable
        runtime_instance_id = _required(settings.gateway_runtime_instance_id)
        probe_digest = _required(settings.gateway_probe_image_digest)
        instance_id = _required(settings.gateway_instance_id)
        worker_network_id = _required(settings.worker_gateway_network_id)
        network_name = _required(settings.worker_gateway_network_name)
        gateway_container_id = _required(settings.worker_gateway_container_id)
        gateway_container_name = _required(settings.worker_gateway_container_name)
        if executable is None:
            raise ValueError("worker runtime executable is unavailable")
        command_executor = executor or LocalBoundedCommandExecutor(executable)
        registry = DurableWorkerRuntimeRegistry(database_path=settings.database_path)
        controller = OciWorkerIsolationController(
            runtime=runtime,
            executable=executable,
            executor=command_executor,
            capability_monitor=(LinuxProcCapabilityMonitor() if runtime == "podman" else None),
            container_name=settings.worker_container_name,
        )

        def controller_for(candidate_runtime: str) -> OciWorkerIsolationController:
            if candidate_runtime != runtime:
                raise ValueError("worker runtime identity changed")
            return controller

        recovery = WorkerRuntimeRecovery(
            registry=registry,
            controller_for=controller_for,
        )

        def attestor_for(binding: WorkerContainmentBinding) -> WorkerContainmentAttestor:
            collector = OciRuntimeSnapshotCollector(
                runtime=runtime,
                executable=executable,
                runtime_instance_id=runtime_instance_id,
                gateway_network_id=binding.worker_gateway_network_id,
                pentai_instance_id=instance_id,
                executor=command_executor,
                network_conformance=OciNetworkConformanceProbe(
                    executable=executable,
                    probe_image_digest=probe_digest,
                    executor=command_executor,
                ),
            )
            inspector = ComposedWorkerRuntimeInspector(
                runtime_inspector=collector,
                peer_verifier=WorkerGatewayPeerInspector(
                    runtime=runtime,
                    executable=executable,
                    network_name=network_name,
                    gateway_container_name=gateway_container_name,
                    executor=command_executor,
                ),
                worker_gateway_network_id=binding.worker_gateway_network_id,
                gateway_container_id=gateway_container_id,
            )
            return WorkerContainmentAttestor(
                inspector,
                worker_gateway_network_id=binding.worker_gateway_network_id,
                gateway_container_id=gateway_container_id,
            )

        attachment_registry = DurableWorkerAttachmentRegistry(
            database_path=settings.database_path
        )
        attachment_recovery = WorkerAttachmentRecovery(
            registry=attachment_registry, runtime_recovery=recovery
        )
        fixture_recovery = WorkerFixtureExecutionRecovery(
            registry=DurableWorkerFixtureExecutionRegistry(
                database_path=settings.database_path
            ),
            terminate_worker=recovery.terminate_worker,
        )

        def pre_attachment_attestor_for(
            binding: WorkerSupervisionBinding,
        ) -> WorkerContainmentAttestor:
            return attestor_for(
                WorkerContainmentBinding(
                    binding.worker_id,
                    binding.runtime_instance_id,
                    binding.worker_gateway_network_id,
                )
            )

        attachment_inspector = WorkerGatewayAttachmentInspector(
            runtime=runtime,
            executable=executable,
            network_name=network_name,
            gateway_container_name=gateway_container_name,
            worker_container_name=settings.worker_container_name,
            executor=command_executor,
        )

        def verify_worker(binding: WorkerSupervisionBinding) -> None:
            if binding.attachment_status == "attached":
                controller.verify_attached(
                    binding.worker_id,
                    binding.container_id,
                    binding.image_digest,
                    network_name=network_name,
                    network_id=binding.worker_gateway_network_id,
                )
            else:
                controller.verify(
                    binding.worker_id, binding.container_id, binding.image_digest
                )

        def verify_attachment(binding: WorkerSupervisionBinding) -> object:
            if binding.gateway_container_id is None:
                raise ValueError("worker gateway identity is missing")
            return attachment_inspector.verify_attached(
                network_id=binding.worker_gateway_network_id,
                gateway_container_id=binding.gateway_container_id,
                worker_container_id=binding.container_id,
            )

        containment_monitor = monitor or AttachmentAwareWorkerContainmentMonitor(
            bindings=registry.supervision_bindings,
            pre_attachment_attestor_for=pre_attachment_attestor_for,
            verify_worker=verify_worker,
            verify_attachment=verify_attachment,
        )
        startup_attestor = baseline_attestor or attestor_for(
            WorkerContainmentBinding(
                "worker-supervision-baseline",
                runtime_instance_id,
                worker_network_id,
            )
        )

        def recover_and_revalidate() -> int:
            recovered = fixture_recovery.recover_all()
            recovered += attachment_recovery.recover_all()
            recovered += recovery.recover_all()
            startup_attestor.measure()
            return recovered

        return WorkerContainmentSupervisor(
            monitor=containment_monitor,
            pause_safety=pause_safety,
            terminate_workers=recovery.terminate_all,
            recover_workers=recover_and_revalidate,
            interval_seconds=settings.worker_watchdog_interval_seconds,
        )
    except Exception:
        return UnavailableConfiguredWorkerSupervisor(pause_safety=pause_safety)


def _required(value: str | None) -> str:
    if value is None:
        raise ValueError("worker runtime configuration is incomplete")
    return value
