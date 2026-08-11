from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from pentai_core.gateway_response import GatewayResponseMeasurement
from pentai_core.runtime_snapshot_collector import BoundedCommandExecutor
from pentai_core.worker_containment import validate_containment_attestation

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


class GatewayHttpFixtureError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OciGatewayHttpFixtureTransport:
    """Run one strictly synthetic HTTP request inside the managed internal network."""

    def __init__(
        self,
        *,
        executable: Path,
        image_digest: str,
        executor: BoundedCommandExecutor,
    ) -> None:
        if not executable.is_absolute() or not _DIGEST.fullmatch(image_digest):
            raise GatewayHttpFixtureError("HTTP_FIXTURE_INVALID", "fixture is invalid")
        self._executable = str(executable)
        self._image_digest = image_digest
        self._executor = executor

    def execute(
        self,
        *,
        network_id: str,
        containment: dict[str, object],
        maximum_response_bytes: int,
        timeout_milliseconds: int,
    ) -> GatewayResponseMeasurement:
        if (
            not _IDENTIFIER.fullmatch(network_id)
            or not 1 <= maximum_response_bytes <= 1_048_576
            or not 1 <= timeout_milliseconds <= 5_000
        ):
            raise GatewayHttpFixtureError("HTTP_FIXTURE_DENIED", "fixture bounds are invalid")
        try:
            validate_containment_attestation(containment)
        except Exception as exc:
            raise GatewayHttpFixtureError(
                "HTTP_FIXTURE_CONTAINMENT_DENIED", "fixture containment is invalid"
            ) from exc
        if containment.get("gateway_network_id") != network_id:
            raise GatewayHttpFixtureError(
                "HTTP_FIXTURE_CONTAINMENT_DENIED", "fixture network is not attested"
            )
        result = self._executor.execute(
            (
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
                self._image_digest,
                "--mode=http-fixture-client",
                "--target=192.0.2.20:8080",
                "--host=example.test",
                "--path=/fixture",
                f"--maximum-response-bytes={maximum_response_bytes}",
                f"--timeout-milliseconds={timeout_milliseconds}",
            ),
            timeout_seconds=min(10, timeout_milliseconds / 1_000 + 2),
            max_output_bytes=4096,
        )
        if result.returncode != 0 or len(result.stdout) > 4096:
            raise GatewayHttpFixtureError("HTTP_FIXTURE_FAILED", "fixture request failed")
        try:
            document = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayHttpFixtureError(
                "HTTP_FIXTURE_INVALID", "fixture output is invalid"
            ) from exc
        if not isinstance(document, dict) or set(document) != {
            "outcome",
            "observed_response_bytes",
            "retained_response_bytes",
        }:
            raise GatewayHttpFixtureError("HTTP_FIXTURE_INVALID", "fixture output is invalid")
        outcome = document.get("outcome")
        observed = document.get("observed_response_bytes")
        retained = document.get("retained_response_bytes")
        if (
            outcome
            not in {
                "completed",
                "deadline_exceeded",
                "response_limit_exceeded",
                "transport_error",
            }
            or type(observed) is not int
            or type(retained) is not int
            or observed < 0
            or retained < 0
            or retained > observed
            or retained > maximum_response_bytes
            or observed > maximum_response_bytes + 1
            or (outcome == "response_limit_exceeded" and observed != maximum_response_bytes + 1)
            or (outcome != "response_limit_exceeded" and retained != observed)
        ):
            raise GatewayHttpFixtureError("HTTP_FIXTURE_INVALID", "fixture output is invalid")
        return GatewayResponseMeasurement(
            outcome, observed, retained, datetime.now(UTC)
        )
