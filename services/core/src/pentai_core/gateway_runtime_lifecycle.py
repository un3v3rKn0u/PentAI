from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any, Protocol
from uuid import uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues

from pentai_core.database import transaction
from pentai_core.runtime_snapshot_collector import BoundedCommandExecutor
from pentai_core.worker_containment import validate_containment_attestation

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_CONTAINER_ID = re.compile(r"^[a-f0-9]{12,64}$")


class GatewayRuntimeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RuntimeController(Protocol):
    def launch(self, runtime_id: str, network_id: str, image_digest: str) -> str: ...

    def verify(self, runtime_id: str, container_id: str, network_id: str) -> None: ...

    def terminate(self, runtime_id: str, container_id: str | None) -> None: ...


class CapabilityMonitor(Protocol):
    def all_dropped(self, pid: int) -> bool: ...


class LinuxProcCapabilityMonitor:
    def __init__(self, proc_root: Path = Path("/proc")) -> None:
        if not proc_root.is_absolute():
            raise GatewayRuntimeError("PROC_ROOT_INVALID", "proc root is invalid")
        self._proc_root = proc_root

    def all_dropped(self, pid: int) -> bool:
        if not 1 <= pid <= 2_147_483_647:
            return False
        try:
            with (self._proc_root / str(pid) / "status").open("rb") as status_file:
                raw = status_file.read(65_537)
        except OSError:
            return False
        if len(raw) > 65_536:
            return False
        try:
            fields = dict(
                line.split(":", 1)
                for line in raw.decode("ascii").splitlines()
                if ":" in line
            )
        except UnicodeDecodeError:
            return False
        required = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        return all(
            re.fullmatch(r"\s*[0-9a-fA-F]{16}\s*", fields.get(name, "")) is not None
            and int(fields[name].strip(), 16) == 0
            for name in required
        )


class ContainmentMonitor(Protocol):
    def measure(self) -> dict[str, object]: ...


class SafetyHandler(Protocol):
    def halt(self, session_id: str, reason: str) -> None: ...


class AssessmentSafetyControl(Protocol):
    def set_assessment_safety(
        self, engagement_id: str, *, status: str, reason: str, actor_id: str
    ) -> dict[str, Any]: ...


class AuthorizationSafetyHandler:
    def __init__(self, *, database_path: Path, safety_control: AssessmentSafetyControl) -> None:
        self._database_path = database_path
        self._safety_control = safety_control

    def halt(self, session_id: str, reason: str) -> None:
        with transaction(self._database_path) as connection:
            row = connection.execute(
                """SELECT br.engagement_id FROM gateway_sessions gs
                JOIN budget_reservations br ON br.reservation_id = gs.reservation_id
                WHERE gs.session_id = ?""",
                (session_id,),
            ).fetchone()
        if row is None:
            raise GatewayRuntimeError("GATEWAY_SESSION_NOT_FOUND", "session does not exist")
        self._safety_control.set_assessment_safety(
            str(row["engagement_id"]),
            status="paused",
            reason=reason,
            actor_id="gateway-runtime-monitor",
        )


class OciGatewayFixtureController:
    def __init__(
        self,
        *,
        runtime: str,
        executable: Path,
        executor: BoundedCommandExecutor,
        capability_monitor: CapabilityMonitor | None = None,
    ) -> None:
        if runtime not in {"docker", "podman"}:
            raise GatewayRuntimeError("RUNTIME_UNSUPPORTED", "runtime is unsupported")
        if not executable.is_absolute():
            raise GatewayRuntimeError("RUNTIME_EXECUTABLE_UNTRUSTED", "runtime is untrusted")
        self._executable = str(executable)
        self._runtime = runtime
        self._executor = executor
        self._capability_monitor = capability_monitor
        if runtime == "podman" and capability_monitor is None:
            raise GatewayRuntimeError(
                "CAPABILITY_MONITOR_REQUIRED", "capability monitor is required"
            )

    def launch(self, runtime_id: str, network_id: str, image_digest: str) -> str:
        self._validate(runtime_id, network_id, image_digest)
        result = self._executor.execute(
            (
                self._executable,
                "run",
                "--detach",
                "--network",
                network_id,
                "--read-only",
                "--cap-drop=all",
                "--security-opt=no-new-privileges",
                "--pid=private",
                "--ipc=private",
                "--pids-limit=16",
                "--memory=32m",
                "--cpus=0.25",
                "--label",
                "com.pentai.managed=true",
                "--label",
                "com.pentai.runtime-role=gateway-fixture",
                "--label",
                f"com.pentai.runtime-id={runtime_id}",
                "--entrypoint=/pentai-network-probe",
                image_digest,
                "--mode=sentinel",
                f"--runtime-id={runtime_id}",
            ),
            timeout_seconds=10,
            max_output_bytes=4096,
        )
        container_id = result.stdout.decode(errors="strict").strip()
        if result.returncode != 0 or not _CONTAINER_ID.fullmatch(container_id):
            raise GatewayRuntimeError("GATEWAY_LAUNCH_FAILED", "gateway fixture launch failed")
        return container_id

    def verify(self, runtime_id: str, container_id: str, network_id: str) -> None:
        if not _IDENTIFIER.fullmatch(runtime_id) or not _CONTAINER_ID.fullmatch(container_id):
            raise GatewayRuntimeError("GATEWAY_RUNTIME_INVALID", "runtime identity is invalid")
        result = self._executor.execute(
            (self._executable, "inspect", "--format", "{{json .}}", container_id),
            timeout_seconds=5,
            max_output_bytes=262_144,
        )
        if result.returncode != 0:
            raise GatewayRuntimeError("GATEWAY_INSPECTION_FAILED", "gateway inspection failed")
        import json

        try:
            document = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayRuntimeError(
                "GATEWAY_INSPECTION_FAILED", "gateway inspection failed"
            ) from exc
        if isinstance(document, list) and len(document) == 1:
            document = document[0]
        if not isinstance(document, dict):
            raise GatewayRuntimeError("GATEWAY_INSPECTION_FAILED", "gateway inspection failed")
        state = document.get("State")
        config = document.get("Config")
        host = document.get("HostConfig")
        host_document = host if isinstance(host, dict) else {}
        config_document = config if isinstance(config, dict) else {}
        labels = config_document.get("Labels")
        cap_drop = host_document.get("CapDrop")
        security_options = host_document.get("SecurityOpt")
        binds = host_document.get("Binds")
        network_settings = document.get("NetworkSettings")
        networks = (
            network_settings.get("Networks") if isinstance(network_settings, dict) else None
        )
        network_ids = (
            {
                value.get("NetworkID")
                for value in networks.values()
                if isinstance(value, dict)
            }
            if isinstance(networks, dict)
            else set()
        )
        expected_network_names: set[str] | None = None
        if self._runtime == "podman":
            network_result = self._executor.execute(
                (self._executable, "network", "inspect", "--format", "json", network_id),
                timeout_seconds=5,
                max_output_bytes=65_536,
            )
            try:
                network_document = json.loads(network_result.stdout)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise GatewayRuntimeError(
                    "GATEWAY_INSPECTION_FAILED", "gateway network inspection failed"
                ) from exc
            if isinstance(network_document, list) and len(network_document) == 1:
                network_document = network_document[0]
            if (
                network_result.returncode != 0
                or not isinstance(network_document, dict)
                or network_document.get("id") != network_id
                or not isinstance(network_document.get("name"), str)
            ):
                raise GatewayRuntimeError(
                    "GATEWAY_INSPECTION_FAILED", "gateway network inspection failed"
                )
            expected_network_names = {str(network_document["name"])}
        nano_cpus = host_document.get("NanoCpus")
        cpu_quota = host_document.get("CpuQuota")
        cpu_period = host_document.get("CpuPeriod")
        cpu_limited = nano_cpus == 250_000_000 or (
            isinstance(cpu_quota, int)
            and isinstance(cpu_period, int)
            and cpu_quota > 0
            and cpu_period > 0
            and cpu_quota * 4 <= cpu_period
        )
        podman = self._runtime == "podman"
        podman_process_caps_empty = (
            isinstance(state, dict)
            and type(state.get("Pid")) is int
            and self._capability_monitor is not None
            and self._capability_monitor.all_dropped(state["Pid"])
        )
        capabilities_dropped = (
            podman_process_caps_empty
            if podman
            else isinstance(cap_drop, list)
            and any(str(item).lower() == "all" for item in cap_drop)
        )
        podman_network_single = isinstance(networks, dict) and len(networks) == 1
        podman_network_name = isinstance(networks, dict) and set(networks) == expected_network_names
        network_identity = (
            podman_network_single
            and podman_network_name
            if podman
            else network_ids == {network_id}
        )
        checks = {
            "container_identity": document.get("Id") == container_id,
            "running": isinstance(state, dict) and state.get("Running") is True,
            "host_config": isinstance(host, dict),
            "network_identity": network_identity,
            "read_only_root": host_document.get("ReadonlyRootfs") is True,
            "non_privileged": host_document.get("Privileged") is False,
            "private_pid": host_document.get("PidMode") in ("", "private", None),
            "private_ipc": host_document.get("IpcMode") in ("", "private", None),
            "pid_limit": host_document.get("PidsLimit") == 16,
            "memory_limit": host_document.get("Memory") == 33_554_432,
            "cpu_limit": cpu_limited,
            "capabilities_dropped": capabilities_dropped,
            "no_new_privileges": isinstance(security_options, list)
            and any("no-new-privileges" in str(item) for item in security_options),
            "no_binds": binds in (None, []),
            "config": isinstance(config, dict),
            "non_root_user": config_document.get("User") in ("65532", "65532:65532"),
            "labels": isinstance(labels, dict)
            and labels.get("com.pentai.managed") == "true"
            and labels.get("com.pentai.runtime-role") == "gateway-fixture"
            and labels.get("com.pentai.runtime-id") == runtime_id,
        }
        failed = sorted(name for name, passed in checks.items() if not passed)
        if podman and not capabilities_dropped:
            failed.append("podman_process_caps_empty")
        if podman and not network_identity:
            if not podman_network_single:
                failed.append("podman_network_single")
            if not podman_network_name:
                failed.append("podman_network_name")
        if failed:
            raise GatewayRuntimeError(
                "GATEWAY_RUNTIME_DRIFT",
                "gateway containment changed: " + ",".join(failed),
            )

    def terminate(self, runtime_id: str, container_id: str | None) -> None:
        if not _IDENTIFIER.fullmatch(runtime_id):
            raise GatewayRuntimeError("GATEWAY_RUNTIME_INVALID", "runtime identity is invalid")
        if container_id is None:
            return
        if not _CONTAINER_ID.fullmatch(container_id):
            raise GatewayRuntimeError("GATEWAY_RUNTIME_INVALID", "container identity is invalid")
        command = [self._executable, "rm", "--force"]
        if self._runtime == "podman":
            command.append("--time=0")
        command.append(container_id)
        result = self._executor.execute(
            tuple(command),
            timeout_seconds=10,
            max_output_bytes=4096,
        )
        if result.returncode != 0:
            raise GatewayRuntimeError("GATEWAY_TERMINATION_FAILED", "gateway termination failed")

    @staticmethod
    def _validate(runtime_id: str, network_id: str, image_digest: str) -> None:
        if (
            not _IDENTIFIER.fullmatch(runtime_id)
            or not _IDENTIFIER.fullmatch(network_id)
            or not _DIGEST.fullmatch(image_digest)
        ):
            raise GatewayRuntimeError("GATEWAY_RUNTIME_INVALID", "runtime configuration is invalid")


class GatewayRuntimeLifecycle:
    def __init__(
        self,
        *,
        database_path: Path,
        controller: RuntimeController,
        monitor: ContainmentMonitor,
        safety: SafetyHandler,
    ) -> None:
        self._database_path = database_path
        self._controller = controller
        self._monitor = monitor
        self._safety = safety

    def launch(
        self,
        *,
        session: dict[str, Any],
        containment: dict[str, Any],
        image_digest: str,
    ) -> dict[str, Any]:
        try:
            validate_containment_attestation(containment)
        except Exception as exc:
            raise GatewayRuntimeError(
                "GATEWAY_RUNTIME_DENIED", "containment evidence is invalid"
            ) from exc
        if (
            contract_issues(session, "gateway-session-v1.schema.json")
            or session.get("status") != "prepared"
            or session.get("execution_enabled") is not False
            or not _DIGEST.fullmatch(image_digest)
        ):
            raise GatewayRuntimeError("GATEWAY_RUNTIME_DENIED", "gateway runtime is denied")
        runtime_id = str(uuid4())
        created_at = _timestamp()
        document: dict[str, Any] = {
            "schema_version": "1.0.0",
            "runtime_id": runtime_id,
            "session_id": session["session_id"],
            "containment_attestation_id": containment["attestation_id"],
            "oci_runtime": containment["runtime"],
            "oci_runtime_instance_id": containment["runtime_instance_id"],
            "gateway_network_id": containment["gateway_network_id"],
            "image_digest": image_digest,
            "status": "launching",
            "created_at": created_at,
            "execution_enabled": False,
        }
        if contract_issues(document, "gateway-runtime-instance-v1.schema.json"):
            raise GatewayRuntimeError("GATEWAY_RUNTIME_DENIED", "runtime record is invalid")
        with transaction(self._database_path) as connection:
            row = connection.execute(
                "SELECT status FROM gateway_sessions WHERE session_id = ?",
                (session["session_id"],),
            ).fetchone()
            if row is None or row["status"] != "prepared":
                raise GatewayRuntimeError("GATEWAY_RUNTIME_DENIED", "session is inactive")
            try:
                connection.execute(
                    """INSERT INTO gateway_runtime_instances(
                    runtime_id, session_id, containment_attestation_id, oci_runtime,
                    oci_runtime_instance_id, gateway_network_id, image_digest, status,
                    created_at, execution_enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'launching', ?, 0)""",
                    (
                        runtime_id, session["session_id"], containment["attestation_id"],
                        containment["runtime"], containment["runtime_instance_id"],
                        containment["gateway_network_id"], image_digest, created_at,
                    ),
                )
                _audit(
                    connection,
                    action="gateway.runtime_launching",
                    runtime_id=runtime_id,
                    data={
                        "session_id": session["session_id"],
                        "containment_attestation_id": containment["attestation_id"],
                        "gateway_network_id": containment["gateway_network_id"],
                        "image_digest": image_digest,
                        "execution_enabled": False,
                    },
                    occurred_at=created_at,
                )
            except Exception as exc:
                raise GatewayRuntimeError(
                    "GATEWAY_RUNTIME_REPLAYED", "runtime already exists"
                ) from exc
        container_id: str | None = None
        try:
            container_id = self._controller.launch(
                runtime_id, str(containment["gateway_network_id"]), image_digest
            )
            with transaction(self._database_path) as connection:
                connection.execute(
                    """UPDATE gateway_runtime_instances SET container_id = ?
                    WHERE runtime_id = ? AND status = 'launching' AND container_id IS NULL""",
                    (container_id, runtime_id),
                )
            self._controller.verify(
                runtime_id, container_id, str(containment["gateway_network_id"])
            )
        except Exception as exc:
            cleanup_failed = False
            if container_id is not None:
                try:
                    self._controller.terminate(runtime_id, container_id)
                except Exception:
                    cleanup_failed = True
            final_status = "failed" if cleanup_failed or container_id is None else "terminated"
            self._finalize(runtime_id, final_status, "launch verification failed")
            self._safety.halt(str(session["session_id"]), "gateway launch verification failed")
            if cleanup_failed:
                raise GatewayRuntimeError(
                    "GATEWAY_TERMINATION_FAILED", "failed gateway launch could not be terminated"
                ) from exc
            raise GatewayRuntimeError("GATEWAY_LAUNCH_FAILED", "gateway launch failed") from exc
        checked_at = _timestamp()
        try:
            with transaction(self._database_path) as connection:
                transitioned = connection.execute(
                    """UPDATE gateway_runtime_instances SET status = 'running',
                    last_checked_at = ? WHERE runtime_id = ? AND status = 'launching'""",
                    (checked_at, runtime_id),
                )
                if transitioned.rowcount != 1:
                    raise GatewayRuntimeError(
                        "GATEWAY_RUNTIME_RACE", "runtime state changed during launch"
                    )
                _audit(
                    connection,
                    action="gateway.runtime_started",
                    runtime_id=runtime_id,
                    data={"container_id": container_id, "execution_enabled": False},
                    occurred_at=checked_at,
                )
        except Exception as exc:
            cleanup_failed = False
            try:
                self._controller.terminate(runtime_id, container_id)
            except Exception:
                cleanup_failed = True
            self._finalize(
                runtime_id,
                "failed" if cleanup_failed else "terminated",
                "runtime persistence failed",
            )
            self._safety.halt(str(session["session_id"]), "runtime persistence failed")
            raise GatewayRuntimeError(
                "GATEWAY_RUNTIME_PERSISTENCE_FAILED", "runtime state could not be committed"
            ) from exc
        return {
            **document,
            "container_id": container_id,
            "status": "running",
            "last_checked_at": checked_at,
        }

    def check(self, runtime_id: str) -> dict[str, Any]:
        row = self._load_running(runtime_id)
        try:
            containment = self._monitor.measure()
            validate_containment_attestation(containment)
            if (
                containment.get("runtime") != row["oci_runtime"]
                or containment.get("runtime_instance_id") != row["oci_runtime_instance_id"]
                or containment.get("gateway_network_id") != row["gateway_network_id"]
            ):
                raise GatewayRuntimeError("GATEWAY_CONTAINMENT_CHANGED", "containment changed")
            self._controller.verify(
                runtime_id, str(row["container_id"]), str(row["gateway_network_id"])
            )
        except Exception as exc:
            self._terminate_row(row, "containment monitor failure")
            raise GatewayRuntimeError("GATEWAY_MONITOR_FAILED", "gateway monitor failed") from exc
        checked_at = _timestamp()
        try:
            with transaction(self._database_path) as connection:
                refreshed = connection.execute(
                    """UPDATE gateway_runtime_instances SET last_checked_at = ?
                    WHERE runtime_id = ? AND status = 'running'""",
                    (checked_at, runtime_id),
                )
                if refreshed.rowcount != 1:
                    raise GatewayRuntimeError(
                        "GATEWAY_RUNTIME_RACE", "runtime state changed during monitoring"
                    )
        except Exception as exc:
            self._terminate_row(row, "monitor checkpoint persistence failure")
            raise GatewayRuntimeError(
                "GATEWAY_MONITOR_FAILED", "monitor checkpoint could not be committed"
            ) from exc
        return {
            "runtime_id": runtime_id,
            "status": "running",
            "last_checked_at": checked_at,
            "execution_enabled": False,
        }

    def terminate(self, runtime_id: str, *, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise GatewayRuntimeError("GATEWAY_REASON_REQUIRED", "termination reason is required")
        row = self._load_running(runtime_id)
        self._terminate_row(row, reason.strip())
        return {"runtime_id": runtime_id, "status": "terminated", "execution_enabled": False}

    def recover(self) -> int:
        with transaction(self._database_path) as connection:
            rows = connection.execute(
                """SELECT * FROM gateway_runtime_instances
                WHERE status IN ('launching', 'running')
                   OR (status = 'failed' AND container_id IS NOT NULL)"""
            ).fetchall()
        for row in rows:
            self._terminate_row(row, "startup recovery")
        return len(rows)

    def check_all(self) -> int:
        with transaction(self._database_path) as connection:
            runtime_ids = [
                str(row["runtime_id"])
                for row in connection.execute(
                    "SELECT runtime_id FROM gateway_runtime_instances WHERE status = 'running'"
                )
            ]
        for runtime_id in runtime_ids:
            try:
                self.check(runtime_id)
            except GatewayRuntimeError:
                continue
        return len(runtime_ids)

    def _load_running(self, runtime_id: str) -> Any:
        with transaction(self._database_path) as connection:
            row = connection.execute(
                "SELECT * FROM gateway_runtime_instances WHERE runtime_id = ?", (runtime_id,)
            ).fetchone()
        if row is None or row["status"] != "running" or row["container_id"] is None:
            raise GatewayRuntimeError("GATEWAY_RUNTIME_INACTIVE", "gateway runtime is inactive")
        return row

    def _terminate_row(self, row: Any, reason: str) -> None:
        termination_failed = False
        try:
            self._controller.terminate(str(row["runtime_id"]), row["container_id"])
        except Exception:
            termination_failed = True
        self._finalize(
            str(row["runtime_id"]),
            "failed" if termination_failed else "terminated",
            reason,
        )
        self._safety.halt(str(row["session_id"]), reason)
        if termination_failed:
            raise GatewayRuntimeError("GATEWAY_TERMINATION_FAILED", "gateway termination failed")

    def _finalize(self, runtime_id: str, status: str, reason: str) -> None:
        finalized_at = _timestamp()
        with transaction(self._database_path) as connection:
            finalized = connection.execute(
                """UPDATE gateway_runtime_instances SET status = ?, finalized_at = ?,
                termination_reason = ? WHERE runtime_id = ?
                AND status IN ('launching', 'running', 'failed')""",
                (status, finalized_at, reason[:256], runtime_id),
            )
            if finalized.rowcount == 1:
                _audit(
                    connection,
                    action="gateway.runtime_finalized",
                    runtime_id=runtime_id,
                    data={"status": status, "reason": reason[:256]},
                    occurred_at=finalized_at,
                )


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class GatewayRuntimeWatchdog:
    def __init__(self, lifecycle: GatewayRuntimeLifecycle, *, interval_seconds: float = 5) -> None:
        if not 0.1 <= interval_seconds <= 10:
            raise GatewayRuntimeError("GATEWAY_MONITOR_INTERVAL_INVALID", "interval is invalid")
        self._lifecycle = lifecycle
        self._interval_seconds = interval_seconds

    def run(self, stop: Event) -> None:
        while not stop.is_set():
            self._lifecycle.check_all()
            stop.wait(self._interval_seconds)


def _audit(
    connection: Any,
    *,
    action: str,
    runtime_id: str,
    data: dict[str, Any],
    occurred_at: str,
) -> None:
    previous = connection.execute(
        "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else None
    event = {
        "event_id": str(uuid4()),
        "occurred_at": occurred_at,
        "actor_type": "service",
        "actor_id": "gateway-runtime-lifecycle",
        "action": action,
        "subject_type": "gateway_runtime",
        "subject_id": runtime_id,
        "data": data,
        "previous_hash": previous_hash,
    }
    event_hash = content_hash(event)
    connection.execute(
        """INSERT INTO audit_events(
        event_id, occurred_at, actor_type, actor_id, action, subject_type,
        subject_id, data_json, previous_hash, event_hash
        ) VALUES (?, ?, 'service', 'gateway-runtime-lifecycle', ?,
                  'gateway_runtime', ?, ?, ?, ?)""",
        (
            event["event_id"],
            occurred_at,
            action,
            runtime_id,
            canonical_json(data),
            previous_hash,
            event_hash,
        ),
    )
