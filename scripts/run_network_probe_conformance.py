#!/usr/bin/env python3
"""Build and execute the TEST-NET-only probe under a verified rootless OCI runtime."""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import secrets
import shutil
import sqlite3
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from owned_fixture_authority import prepare_owned_fixture_session
from pentai_core.config import Settings
from pentai_core.gateway_http_fixture import (
    GatewayHttpFixtureExecution,
    OciGatewayHttpFixtureTransport,
)
from pentai_core.gateway_runtime_composition import compose_gateway_runtime_supervisor
from pentai_core.gateway_runtime_lifecycle import (
    GatewayRuntimeLifecycle,
    LinuxProcCapabilityMonitor,
    OciGatewayFixtureController,
)
from pentai_core.managed_gateway_network import (
    ManagedGatewayNetworkProvisioner,
    NetworkProbeExecutionError,
    OciNetworkConformanceProbe,
    normalize_oci_image_digest,
    require_rootless_runtime,
)
from pentai_core.migrate import migrate
from pentai_core.oci_runtime_command import oci_run_command
from pentai_core.policy_signing import PolicySigner
from pentai_core.runtime_containment import RuntimeContainmentAttestor
from pentai_core.runtime_snapshot_collector import (
    LocalBoundedCommandExecutor,
    OciRuntimeSnapshotCollector,
    SnapshotCollectionError,
    runtime_instance_identity,
)

_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class HarnessSafety:
    calls: list[tuple[str, str]] = field(default_factory=list)
    global_calls: list[tuple[str, str, str]] = field(default_factory=list)

    def halt(self, session_id: str, reason: str) -> None:
        self.calls.append((session_id, reason))

    def set_global_safety(
        self, *, status: str, reason: str, actor_id: str
    ) -> dict[str, Any]:
        self.global_calls.append((status, reason, actor_id))
        return {}

    def set_assessment_safety(
        self, engagement_id: str, *, status: str, reason: str, actor_id: str
    ) -> dict[str, Any]:
        self.calls.append((engagement_id, reason))
        return {}


@dataclass
class HarnessMonitor:
    attestor: RuntimeContainmentAttestor

    def measure(self) -> dict[str, object]:
        return self.attestor.measure()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", choices=("docker", "podman"), required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--probe-binary", type=Path, required=True)
    arguments = parser.parse_args()

    executable = arguments.executable.resolve(strict=True)
    probe_binary = arguments.probe_binary.resolve(strict=True)
    executor = LocalBoundedCommandExecutor(executable)
    require_rootless_runtime(
        runtime=arguments.runtime, executable=executable, executor=executor
    )

    suffix = uuid.uuid4().hex
    policy_signer = PolicySigner(secrets.token_bytes(32))
    image_tag = f"pentai-network-probe:{suffix}"
    network_name = f"pentai-probe-{suffix}"
    network_created = False
    image_created = False
    try:
        with tempfile.TemporaryDirectory(prefix="pentai-network-probe-") as temporary:
            context = Path(temporary)
            shutil.copy2(probe_binary, context / "pentai-network-probe")
            shutil.copy2(_ROOT / "tools/network-probe/Containerfile", context / "Containerfile")
            (context / "claim-verifier.pub").write_bytes(
                policy_signer.verifier().public_key_bytes()
            )
            build = executor.execute(
                (
                    str(executable),
                    "build",
                    "--network=none",
                    "--pull=false",
                    "--tag",
                    image_tag,
                    str(context),
                ),
                timeout_seconds=10,
                max_output_bytes=1_048_576,
            )
            if build.returncode != 0:
                raise SnapshotCollectionError("PROBE_BUILD_FAILED", "probe image build failed")
            image_created = True

        digest_result = executor.execute(
            (str(executable), "image", "inspect", "--format", "{{.Id}}", image_tag),
            timeout_seconds=5,
            max_output_bytes=4096,
        )
        if digest_result.returncode != 0:
            raise SnapshotCollectionError(
                "PROBE_DIGEST_INVALID", "runtime did not return an immutable image digest"
            )
        try:
            observed_digest = digest_result.stdout.decode(errors="strict").strip()
            digest = normalize_oci_image_digest(observed_digest)
        except (UnicodeDecodeError, SnapshotCollectionError) as exc:
            raise SnapshotCollectionError(
                "PROBE_DIGEST_INVALID", "runtime did not return an immutable image digest"
            ) from exc

        provisioner = ManagedGatewayNetworkProvisioner(
            runtime=arguments.runtime,
            executable=executable,
            network_name=network_name,
            pentai_instance_id="conformance-fixture",
            executor=executor,
            fixture_subnet="192.0.2.0/24",
        )
        network = provisioner.ensure()
        network_created = network.created
        result = OciNetworkConformanceProbe(
            executable=executable,
            probe_image_digest=digest,
            executor=executor,
        ).verify(network.network_id)
        if not all(
            (
                result.direct_egress_blocked,
                result.external_dns_blocked,
                result.ipv6_blocked,
                result.runtime_socket_blocked,
                result.host_mounts_blocked,
                result.host_namespaces_blocked,
                result.resource_limits_enforced,
            )
        ):
            raise SnapshotCollectionError(
                "NETWORK_CONFORMANCE_UNSAFE", "one or more containment probes failed"
            )
        _run_gateway_lifecycle(
            runtime=arguments.runtime,
            executable=executable,
            executor=executor,
            network_id=network.network_id,
            image_digest=digest,
            policy_signer=policy_signer,
        )
        print(json.dumps({"image_digest": digest, "network_id": network.network_id, "safe": True}))
        return 0
    finally:
        if network_created:
            executor.execute(
                (str(executable), "network", "rm", network_name),
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        if image_created:
            executor.execute(
                (str(executable), "image", "rm", image_tag),
                timeout_seconds=10,
                max_output_bytes=4096,
            )


def _run_http_fixture(
    *,
    runtime: str,
    executable: Path,
    executor: LocalBoundedCommandExecutor,
    network_id: str,
    image_digest: str,
    containment: dict[str, object],
    execution: GatewayHttpFixtureExecution,
    start_id: str,
    expected_outcome: str,
    expected_observed: int,
    expected_retained: int,
) -> dict[str, Any]:
    launched = executor.execute(
        oci_run_command(
            str(executable),
            "--detach",
            "--network",
            network_id,
            "--ip=192.0.2.20",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=16",
            "--memory=32m",
            "--cpus=0.25",
            "--label=com.pentai.managed=true",
            "--label=com.pentai.runtime-role=http-target-fixture",
            "--entrypoint=/pentai-network-probe",
            image_digest,
            "--mode=http-fixture-server",
        ),
        timeout_seconds=10,
        max_output_bytes=4096,
    )
    try:
        container_id = launched.stdout.decode(errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise SnapshotCollectionError(
            "HTTP_FIXTURE_SERVER_FAILED", "fixture server identity is invalid"
        ) from exc
    if (
        launched.returncode != 0
        or not 12 <= len(container_id) <= 64
        or any(character not in "0123456789abcdef" for character in container_id)
    ):
        raise SnapshotCollectionError(
            "HTTP_FIXTURE_SERVER_FAILED", "fixture server launch failed"
        )
    try:
        completed = execution.execute(start_id, containment=containment)
        if (
            completed["outcome"] != expected_outcome
            or completed["observed_response_bytes"] != expected_observed
            or completed["retained_response_bytes"] != expected_retained
        ):
            raise SnapshotCollectionError(
                "HTTP_FIXTURE_REQUEST_FAILED", "bounded fixture request failed"
            )
        return completed
    finally:
        cleanup = [str(executable), "rm", "--force"]
        if runtime == "podman":
            cleanup.append("--time=0")
        cleanup.append(container_id)
        stopped = executor.execute(
            tuple(cleanup),
            timeout_seconds=10,
            max_output_bytes=4096,
        )
        if stopped.returncode != 0:
            raise SnapshotCollectionError(
                "HTTP_FIXTURE_CLEANUP_FAILED", "fixture server cleanup failed"
            )


def _run_authorized_http_fixture(
    *,
    runtime: str,
    executable: Path,
    executor: LocalBoundedCommandExecutor,
    image_digest: str,
    policy_signer: PolicySigner,
    attestor: RuntimeContainmentAttestor,
    controller: OciGatewayFixtureController,
    maximum_response_bytes: int,
    expected_outcome: str,
    expected_observed: int,
    expected_retained: int,
) -> None:
    with tempfile.TemporaryDirectory(prefix="pentai-authorized-fixture-") as temporary:
        root = Path(temporary)
        database = root / "authority.db"
        migrate(database)
        authority, session = prepare_owned_fixture_session(
            database_path=database,
            source_store_path=root / "sources",
            maximum_response_bytes=maximum_response_bytes,
            policy_signer=policy_signer,
        )
        safety = HarnessSafety()
        lifecycle = GatewayRuntimeLifecycle(
            database_path=database,
            controller=controller,
            monitor=HarnessMonitor(attestor),
            safety=safety,
        )
        containment = attestor.measure()
        runtime_record = lifecycle.launch(
            session=session, containment=containment, image_digest=image_digest
        )
        try:
            start = authority.commit_gateway_request_start(str(session["session_id"]))
            result = _run_http_fixture(
                runtime=runtime,
                executable=executable,
                executor=executor,
                network_id=str(containment["gateway_network_id"]),
                image_digest=image_digest,
                containment=containment,
                execution=GatewayHttpFixtureExecution(
                    authority=authority,
                    transport=OciGatewayHttpFixtureTransport(
                        executable=executable,
                        executor=executor,
                        pause_safety=lambda reason: authority.set_global_safety(
                            status="paused",
                            reason=reason,
                            actor_id="gateway-http-fixture",
                        ),
                        claim_verifier=authority.gateway_fixture_execution_claim_verifier(),
                    ),
                ),
                start_id=str(start["start_id"]),
                expected_outcome=expected_outcome,
                expected_observed=expected_observed,
                expected_retained=expected_retained,
            )
        finally:
            lifecycle.terminate(
                str(runtime_record["runtime_id"]), reason="authorized fixture completed"
            )
        events = authority.audit_events()
        actions = [event["action"] for event in events]
        required_actions = {
            "source.imported",
            "policy.approval",
            "policy.activation",
            "policy.evaluation",
            "action_grant.issued",
            "action_grant.consumed",
            "network.attested",
            "network.destination_decided",
            "gateway.session_prepared",
            "gateway.request_start_committed",
            "gateway.runtime_started",
            "gateway.fixture_execution_claimed",
            "gateway.request_finalized",
            "gateway.runtime_finalized",
        }
        audit_verification = authority.verify_audit_chain()
        if not required_actions.issubset(actions) or audit_verification["valid"] is not True:
            raise SnapshotCollectionError(
                "HTTP_FIXTURE_AUDIT_FAILED", "fixture authorization audit is incomplete"
            )
        if result["start_id"] != start["start_id"] or safety.calls != [
            (str(session["session_id"]), "authorized fixture completed")
        ]:
            raise SnapshotCollectionError(
                "HTTP_FIXTURE_LINKAGE_FAILED", "fixture result linkage is invalid"
            )


def _run_gateway_lifecycle(
    *,
    runtime: str,
    executable: Path,
    executor: LocalBoundedCommandExecutor,
    network_id: str,
    image_digest: str,
    policy_signer: PolicySigner,
) -> None:
    info = executor.execute(
        (str(executable), "info", "--format", "json" if runtime == "podman" else "{{json .}}"),
        timeout_seconds=5,
        max_output_bytes=262_144,
    )
    try:
        document = json.loads(info.stdout)
        runtime_instance_id = runtime_instance_identity(runtime, document)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotCollectionError(
            "RUNTIME_IDENTITY_INVALID", "runtime identity is unavailable"
        ) from exc
    probe = OciNetworkConformanceProbe(
        executable=executable, probe_image_digest=image_digest, executor=executor
    )
    collector = OciRuntimeSnapshotCollector(
        runtime=runtime,
        executable=executable,
        runtime_instance_id=runtime_instance_id,
        gateway_network_id=network_id,
        pentai_instance_id="conformance-fixture",
        executor=executor,
        network_conformance=probe,
    )
    attestor = RuntimeContainmentAttestor(collector)
    controller = OciGatewayFixtureController(
        runtime=runtime,
        executable=executable,
        executor=executor,
        capability_monitor=LinuxProcCapabilityMonitor() if runtime == "podman" else None,
    )
    _run_authorized_http_fixture(
        runtime=runtime,
        executable=executable,
        executor=executor,
        image_digest=image_digest,
        policy_signer=policy_signer,
        attestor=attestor,
        controller=controller,
        maximum_response_bytes=32,
        expected_outcome="completed",
        expected_observed=17,
        expected_retained=17,
    )
    _run_authorized_http_fixture(
        runtime=runtime,
        executable=executable,
        executor=executor,
        image_digest=image_digest,
        policy_signer=policy_signer,
        attestor=attestor,
        controller=controller,
        maximum_response_bytes=8,
        expected_outcome="response_limit_exceeded",
        expected_observed=9,
        expected_retained=8,
    )
    safety = HarnessSafety()
    with tempfile.TemporaryDirectory(prefix="pentai-gateway-lifecycle-") as temporary:
        database = Path(temporary) / "lifecycle.db"
        migrate(database)
        sessions = [_insert_fixture_session(database), _insert_fixture_session(database)]
        lifecycle = GatewayRuntimeLifecycle(
            database_path=database,
            controller=controller,
            monitor=HarnessMonitor(attestor),
            safety=safety,
        )
        first = lifecycle.launch(
            session=sessions[0], containment=attestor.measure(), image_digest=image_digest
        )
        lifecycle.check(str(first["runtime_id"]))
        lifecycle.terminate(str(first["runtime_id"]), reason="hosted lifecycle verification")
        crash = multiprocessing.get_context("spawn").Process(
            target=_launch_then_crash,
            args=(
                runtime,
                str(executable),
                str(database),
                runtime_instance_id,
                network_id,
                image_digest,
                sessions[1],
            ),
        )
        crash.start()
        crash.join(30)
        if crash.is_alive():
            crash.terminate()
            crash.join(5)
            raise SnapshotCollectionError(
                "GATEWAY_CRASH_HARNESS_TIMEOUT", "crash fixture did not exit"
            )
        if crash.exitcode != 0:
            raise SnapshotCollectionError(
                "GATEWAY_CRASH_HARNESS_FAILED", "crash fixture failed before restart"
            )
        restart_safety = HarnessSafety()
        supervisor = compose_gateway_runtime_supervisor(
            settings=Settings(
                environment="test",
                database_path=database,
                test_mode=True,
                gateway_runtime_enabled=True,
                gateway_runtime=runtime,
                gateway_runtime_executable=executable,
                gateway_runtime_instance_id=runtime_instance_id,
                gateway_network_id=network_id,
                gateway_probe_image_digest=image_digest,
                gateway_instance_id="conformance-fixture",
                gateway_watchdog_interval_seconds=0.1,
            ),
            safety_control=restart_safety,
        )
        supervisor.start()
        status = supervisor.status()
        if status["status"] != "ready" or status["recovered_instances"] != 1:
            raise SnapshotCollectionError(
                "GATEWAY_RECOVERY_FAILED", "composed startup did not recover crash fixture"
            )
        supervisor.stop()
        if restart_safety.calls != [("conformance-engagement", "startup recovery")]:
            raise SnapshotCollectionError(
                "GATEWAY_SAFETY_FAILED", "recovery did not pause the owning assessment"
            )
        if restart_safety.global_calls:
            raise SnapshotCollectionError(
                "GATEWAY_SAFETY_FAILED", "successful recovery unexpectedly paused globally"
            )
    if len(safety.calls) != 1:
        raise SnapshotCollectionError("GATEWAY_SAFETY_FAILED", "safety handler was not invoked")


def _launch_then_crash(
    runtime: str,
    executable_value: str,
    database_value: str,
    runtime_instance_id: str,
    network_id: str,
    image_digest: str,
    session: dict[str, Any],
) -> None:
    executable = Path(executable_value)
    executor = LocalBoundedCommandExecutor(executable)
    probe = OciNetworkConformanceProbe(
        executable=executable, probe_image_digest=image_digest, executor=executor
    )
    collector = OciRuntimeSnapshotCollector(
        runtime=runtime,
        executable=executable,
        runtime_instance_id=runtime_instance_id,
        gateway_network_id=network_id,
        pentai_instance_id="conformance-fixture",
        executor=executor,
        network_conformance=probe,
    )
    attestor = RuntimeContainmentAttestor(collector)
    lifecycle = GatewayRuntimeLifecycle(
        database_path=Path(database_value),
        controller=OciGatewayFixtureController(
            runtime=runtime,
            executable=executable,
            executor=executor,
            capability_monitor=LinuxProcCapabilityMonitor() if runtime == "podman" else None,
        ),
        monitor=HarnessMonitor(attestor),
        safety=HarnessSafety(),
    )
    lifecycle.launch(session=session, containment=attestor.measure(), image_digest=image_digest)
    os._exit(0)


def _insert_fixture_session(database: Path) -> dict[str, Any]:
    now = datetime.now(UTC)
    session = {
        "schema_version": "1.0.0",
        "session_id": str(uuid.uuid4()),
        "reservation_id": str(uuid.uuid4()),
        "grant_id": str(uuid.uuid4()),
        "attestation_id": str(uuid.uuid4()),
        "destination_authorization_id": str(uuid.uuid4()),
        "status": "prepared",
        "request_count": 1,
        "response_bytes_limit": 4096,
        "prepared_at": (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "execution_enabled": False,
    }
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            """INSERT INTO budget_reservations(
            reservation_id, engagement_id, policy_bundle_id, grant_id,
            destination_authorization_id, request_count, response_bytes_limit,
            status, reserved_at
            ) VALUES (?, 'conformance-engagement', 'conformance-policy', ?, ?,
            1, 4096, 'reserved', ?)""",
            (
                session["reservation_id"],
                session["grant_id"],
                session["destination_authorization_id"],
                session["prepared_at"],
            ),
        )
        connection.execute(
            """INSERT INTO gateway_sessions(
            session_id, reservation_id, grant_id, attestation_id,
            destination_authorization_id, status, prepared_at, execution_enabled
            ) VALUES (?, ?, ?, ?, ?, 'prepared', ?, 0)""",
            (
                session["session_id"], session["reservation_id"], session["grant_id"],
                session["attestation_id"], session["destination_authorization_id"],
                session["prepared_at"],
            ),
        )
        connection.commit()
    finally:
        connection.close()
    return session


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except NetworkProbeExecutionError as exc:
        diagnostic = {
            "code": exc.code,
            "returncode": exc.returncode,
            "stderr": exc.stderr.decode("utf-8", errors="replace"),
        }
        print(
            "PentAI synthetic conformance diagnostic: "
            + json.dumps(diagnostic, ensure_ascii=True),
            file=sys.stderr,
        )
        raise
