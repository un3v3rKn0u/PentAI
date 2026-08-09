#!/usr/bin/env python3
"""Build and execute the TEST-NET-only probe under a verified rootless OCI runtime."""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pentai_core.gateway_runtime_lifecycle import (
    GatewayRuntimeLifecycle,
    OciGatewayFixtureController,
)
from pentai_core.managed_gateway_network import (
    ManagedGatewayNetworkProvisioner,
    OciNetworkConformanceProbe,
    normalize_oci_image_digest,
    require_rootless_runtime,
)
from pentai_core.migrate import migrate
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

    def halt(self, session_id: str, reason: str) -> None:
        self.calls.append((session_id, reason))


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
    image_tag = f"pentai-network-probe:{suffix}"
    network_name = f"pentai-probe-{suffix}"
    network_created = False
    image_created = False
    try:
        with tempfile.TemporaryDirectory(prefix="pentai-network-probe-") as temporary:
            context = Path(temporary)
            shutil.copy2(probe_binary, context / "pentai-network-probe")
            shutil.copy2(_ROOT / "tools/network-probe/Containerfile", context / "Containerfile")
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


def _run_gateway_lifecycle(
    *,
    runtime: str,
    executable: Path,
    executor: LocalBoundedCommandExecutor,
    network_id: str,
    image_digest: str,
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
    controller = OciGatewayFixtureController(executable=executable, executor=executor)
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
        lifecycle.launch(
            session=sessions[1], containment=attestor.measure(), image_digest=image_digest
        )
        if lifecycle.recover() != 1:
            raise SnapshotCollectionError(
                "GATEWAY_RECOVERY_FAILED", "gateway startup recovery did not terminate fixture"
            )
    if len(safety.calls) != 2:
        raise SnapshotCollectionError("GATEWAY_SAFETY_FAILED", "safety handler was not invoked")


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
    raise SystemExit(main())
