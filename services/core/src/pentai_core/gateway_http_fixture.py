from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from pentai_policy.document import contract_issues, parse_time

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
        executor: BoundedCommandExecutor,
    ) -> None:
        if not executable.is_absolute():
            raise GatewayHttpFixtureError("HTTP_FIXTURE_INVALID", "fixture is invalid")
        self._executable = str(executable)
        self._executor = executor

    def execute(
        self,
        *,
        claim: dict[str, Any],
        containment: dict[str, object],
    ) -> GatewayResponseMeasurement:
        if contract_issues(claim, "gateway-fixture-execution-claim-v1.schema.json"):
            raise GatewayHttpFixtureError("HTTP_FIXTURE_DENIED", "fixture claim is invalid")
        network_id = str(claim["gateway_network_id"])
        maximum_response_bytes = int(claim["response_bytes_limit"])
        if (
            not _IDENTIFIER.fullmatch(network_id)
            or not _DIGEST.fullmatch(str(claim["image_digest"]))
            or not 1 <= maximum_response_bytes <= 1_048_576
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
        if containment.get("attestation_id") != claim["containment_attestation_id"]:
            raise GatewayHttpFixtureError(
                "HTTP_FIXTURE_CONTAINMENT_DENIED", "fixture attestation is not claimed"
            )
        now = datetime.now(UTC)
        durable_deadline = parse_time(claim["deadline_at"])
        effective_deadline = min(durable_deadline, now + timedelta(seconds=5))
        deadline_milliseconds = int(effective_deadline.timestamp() * 1_000)
        if deadline_milliseconds <= int(now.timestamp() * 1_000):
            raise GatewayHttpFixtureError("HTTP_FIXTURE_DEADLINE", "fixture deadline expired")
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
                str(claim["image_digest"]),
                "--mode=http-fixture-client",
                "--target=192.0.2.20:8080",
                "--host=example.test",
                "--path=/fixture",
                f"--maximum-response-bytes={maximum_response_bytes}",
                f"--deadline-unix-milliseconds={deadline_milliseconds}",
            ),
            timeout_seconds=7,
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


class GatewayFixtureAuthority(Protocol):
    def claim_gateway_fixture_execution(
        self, start_id: str, *, containment: dict[str, Any]
    ) -> dict[str, Any]: ...

    def finalize_gateway_request(
        self,
        start_id: str,
        measurement: GatewayResponseMeasurement,
        *,
        execution_claim_id: str | None = None,
    ) -> dict[str, Any]: ...


class GatewayHttpFixtureExecution:
    def __init__(
        self,
        *,
        authority: GatewayFixtureAuthority,
        transport: OciGatewayHttpFixtureTransport,
    ) -> None:
        self._authority = authority
        self._transport = transport

    def execute(
        self, start_id: str, *, containment: dict[str, Any]
    ) -> dict[str, Any]:
        claim = self._authority.claim_gateway_fixture_execution(
            start_id, containment=containment
        )
        measurement = self._transport.execute(claim=claim, containment=containment)
        return self._authority.finalize_gateway_request(
            start_id, measurement, execution_claim_id=str(claim["claim_id"])
        )
