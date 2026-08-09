#!/usr/bin/env python3
"""Build and execute the TEST-NET-only probe under a verified rootless OCI runtime."""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
import uuid
from pathlib import Path

from pentai_core.managed_gateway_network import (
    ManagedGatewayNetworkProvisioner,
    OciNetworkConformanceProbe,
    normalize_oci_image_digest,
    require_rootless_runtime,
)
from pentai_core.runtime_snapshot_collector import (
    LocalBoundedCommandExecutor,
    SnapshotCollectionError,
)

_ROOT = Path(__file__).resolve().parents[1]


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
if __name__ == "__main__":
    raise SystemExit(main())
