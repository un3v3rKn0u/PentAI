from __future__ import annotations

import json
import re
import sqlite3
from base64 import urlsafe_b64encode
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, Protocol
from uuid import UUID

from pentai_policy.document import contract_issues, parse_time

from pentai_core.audit import append_audit_event
from pentai_core.database import transaction
from pentai_core.gateway_response import GatewayResponseMeasurement
from pentai_core.oci_runtime_command import oci_run_command
from pentai_core.policy_signing import (
    PolicyVerifier,
    gateway_fixture_execution_claim_v2_payload,
)
from pentai_core.runtime_snapshot_collector import (
    BoundedCommandExecutor,
    CommandResult,
    SnapshotCollectionError,
)
from pentai_core.worker_containment import validate_containment_attestation

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")
_CLAIM_PAYLOAD_CHUNK_CHARACTERS = 238
_MAXIMUM_CLAIM_PAYLOAD_CHUNKS = 5
_FIXTURE_LABELS = {
    "com.pentai.managed": "true",
    "com.pentai.role": "gateway-http-fixture",
}


class GatewayHttpFixtureError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _claim_payload_arguments(payload: bytes) -> tuple[str, ...]:
    encoded = urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    chunks = tuple(
        encoded[offset : offset + _CLAIM_PAYLOAD_CHUNK_CHARACTERS]
        for offset in range(0, len(encoded), _CLAIM_PAYLOAD_CHUNK_CHARACTERS)
    )
    if not 1 <= len(chunks) <= _MAXIMUM_CLAIM_PAYLOAD_CHUNKS:
        raise GatewayHttpFixtureError("HTTP_FIXTURE_DENIED", "fixture claim is invalid")
    total = len(chunks)
    return tuple(
        f"--claim-part={index}/{total}:{chunk}"
        for index, chunk in enumerate(chunks)
    )


class GatewayFixtureCleanupRecovery:
    def __init__(
        self,
        *,
        database_path: Path,
        executable: Path,
        executor: BoundedCommandExecutor,
        pause_safety: Callable[[str], Any],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not executable.is_absolute():
            raise GatewayHttpFixtureError("HTTP_FIXTURE_INVALID", "fixture is invalid")
        self._database_path = database_path
        self._executable = str(executable)
        self._executor = executor
        self._pause_safety = pause_safety
        self._clock = clock or (lambda: datetime.now(UTC))

    def recover(self) -> int:
        try:
            with transaction(self._database_path) as connection:
                claims = tuple(
                    row
                    for row in connection.execute(
                        """SELECT gfc.claim_id, gfc.runtime_id,
                        gri.gateway_network_id, gri.image_digest
                        FROM gateway_fixture_execution_claims gfc
                        LEFT JOIN gateway_runtime_instances gri
                          ON gri.runtime_id = gfc.runtime_id
                        WHERE gfc.status = 'claimed'
                        ORDER BY gfc.claimed_at, gfc.claim_id"""
                    )
                )
            for claim in claims:
                claim_id = str(claim["claim_id"])
                runtime_id = str(claim["runtime_id"])
                network_id = claim["gateway_network_id"]
                image_digest = claim["image_digest"]
                if str(UUID(claim_id)) != claim_id:
                    raise GatewayHttpFixtureError(
                        "HTTP_FIXTURE_RECOVERY_FAILED", "fixture recovery failed"
                    )
                if (
                    not _IDENTIFIER.fullmatch(runtime_id)
                    or not isinstance(network_id, str)
                    or not _IDENTIFIER.fullmatch(network_id)
                    or not isinstance(image_digest, str)
                    or not _DIGEST.fullmatch(image_digest)
                ):
                    raise GatewayHttpFixtureError(
                        "HTTP_FIXTURE_RECOVERY_FAILED", "fixture recovery failed"
                    )
                expected_labels = _FIXTURE_LABELS | {
                    "com.pentai.execution-claim": claim_id,
                    "com.pentai.runtime-id": runtime_id,
                    "com.pentai.gateway-network": network_id,
                    "com.pentai.image-digest": image_digest,
                }
                container_name = f"pentai-fixture-{claim_id}"
                container_id = self._container_identity(
                    container_name,
                    expected_labels=expected_labels,
                    image_digest=image_digest,
                    network_id=network_id,
                )
                if container_id is not None:
                    removed = self._executor.execute(
                        (self._executable, "rm", "--force", container_id),
                        timeout_seconds=2,
                        max_output_bytes=4096,
                    )
                    remaining = self._container_identity(
                        container_name,
                        expected_labels=expected_labels,
                        image_digest=image_digest,
                        network_id=network_id,
                    )
                    if removed.returncode != 0 or remaining is not None:
                        raise GatewayHttpFixtureError(
                            "HTTP_FIXTURE_RECOVERY_FAILED", "fixture recovery failed"
                        )
                self._record_reconciliation(
                    claim_id=claim_id,
                    runtime_id=runtime_id,
                    container_id=container_id,
                )
            return len(claims)
        except (
            GatewayHttpFixtureError,
            SnapshotCollectionError,
            sqlite3.Error,
            ValueError,
        ) as exc:
            try:
                self._pause_safety("GATEWAY_FIXTURE_RECOVERY_FAILED")
            except Exception as pause_exc:
                raise GatewayHttpFixtureError(
                    "HTTP_FIXTURE_SAFETY_PAUSE_FAILED", "fixture safety pause failed"
                ) from pause_exc
            if isinstance(exc, GatewayHttpFixtureError):
                raise
            raise GatewayHttpFixtureError(
                "HTTP_FIXTURE_RECOVERY_FAILED", "fixture recovery failed"
            ) from exc

    def _record_reconciliation(
        self, *, claim_id: str, runtime_id: str, container_id: str | None
    ) -> None:
        occurred_at = _trusted_time(self._clock).isoformat().replace("+00:00", "Z")
        with transaction(self._database_path) as connection:
            append_audit_event(
                connection,
                action="gateway.fixture_cleanup_reconciled",
                subject_type="gateway_fixture_execution_claim",
                subject_id=claim_id,
                actor_type="system",
                actor_id="gateway-runtime-supervisor",
                data={
                    "claim_id": claim_id,
                    "runtime_id": runtime_id,
                    "container_id": container_id,
                    "outcome": "removed" if container_id is not None else "already_absent",
                    "execution_enabled": False,
                },
                occurred_at=occurred_at,
            )

    def _container_identity(
        self,
        container_name: str,
        *,
        expected_labels: dict[str, str],
        image_digest: str,
        network_id: str,
    ) -> str | None:
        result = self._executor.execute(
            (
                self._executable,
                "ps",
                "--all",
                "--filter",
                f"name=^{container_name}$",
                "--format",
                "{{.Names}}",
            ),
            timeout_seconds=2,
            max_output_bytes=4096,
        )
        try:
            names = result.stdout.decode(errors="strict").splitlines()
        except UnicodeDecodeError as exc:
            raise GatewayHttpFixtureError(
                "HTTP_FIXTURE_RECOVERY_FAILED", "fixture recovery failed"
            ) from exc
        if result.returncode != 0 or any(name != container_name for name in names):
            raise GatewayHttpFixtureError(
                "HTTP_FIXTURE_RECOVERY_FAILED", "fixture recovery failed"
            )
        if not names:
            return None
        inspected = self._executor.execute(
            (
                self._executable,
                "inspect",
                "--format",
                "{{json .}}",
                container_name,
            ),
            timeout_seconds=2,
            max_output_bytes=4096,
        )
        try:
            document = json.loads(inspected.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GatewayHttpFixtureError(
                "HTTP_FIXTURE_RECOVERY_FAILED", "fixture recovery failed"
            ) from exc
        config = document.get("Config") if isinstance(document, dict) else None
        labels = config.get("Labels") if isinstance(config, dict) else None
        network_settings = document.get("NetworkSettings") if isinstance(document, dict) else None
        networks = (
            network_settings.get("Networks")
            if isinstance(network_settings, dict)
            else None
        )
        container_id = document.get("Id") if isinstance(document, dict) else None
        name = document.get("Name") if isinstance(document, dict) else None
        invalid = (
            inspected.returncode != 0
            or not isinstance(container_id, str)
            or not _CONTAINER_ID.fullmatch(container_id)
            or name not in {container_name, f"/{container_name}"}
            or document.get("Image") != image_digest
            or not isinstance(networks, dict)
            or set(networks) != {network_id}
            or not isinstance(labels, dict)
            or any(labels.get(key) != value for key, value in expected_labels.items())
        )
        if invalid:
            raise GatewayHttpFixtureError(
                "HTTP_FIXTURE_RECOVERY_FAILED", "fixture recovery failed"
            )
        return container_id


class OciGatewayHttpFixtureTransport:
    """Run one strictly synthetic HTTP request inside the managed internal network."""

    def __init__(
        self,
        *,
        executable: Path,
        executor: BoundedCommandExecutor,
        pause_safety: Callable[[str], Any],
        claim_verifier: PolicyVerifier,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not executable.is_absolute():
            raise GatewayHttpFixtureError("HTTP_FIXTURE_INVALID", "fixture is invalid")
        self._executable = str(executable)
        self._executor = executor
        self._pause_safety = pause_safety
        self._claim_verifier = claim_verifier
        self._clock = clock or (lambda: datetime.now(UTC))

    def execute(
        self,
        *,
        claim: dict[str, Any],
        containment: dict[str, object],
    ) -> GatewayResponseMeasurement:
        signature = claim.get("signature")
        if contract_issues(
            claim, "gateway-fixture-execution-claim-v2.schema.json"
        ) or not isinstance(signature, dict):
            raise GatewayHttpFixtureError("HTTP_FIXTURE_DENIED", "fixture claim is invalid")
        claim_payload = gateway_fixture_execution_claim_v2_payload(claim)
        if not self._claim_verifier.verify(
            claim_payload,
            str(signature.get("value", "")),
            str(signature.get("key_id", "")),
        ):
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
        now = _trusted_time(self._clock)
        durable_deadline = parse_time(claim["deadline_at"])
        effective_deadline = min(durable_deadline, now + timedelta(seconds=5))
        deadline_milliseconds = int(effective_deadline.timestamp() * 1_000)
        remaining_seconds = deadline_milliseconds / 1_000 - now.timestamp()
        container_name = f"pentai-fixture-{claim['claim_id']}"
        if remaining_seconds <= 0:
            raise GatewayHttpFixtureError("HTTP_FIXTURE_DEADLINE", "fixture deadline expired")
        claim_payload_arguments = _claim_payload_arguments(claim_payload)
        try:
            result = self._execute_transport(
                claim=claim,
                network_id=network_id,
                maximum_response_bytes=maximum_response_bytes,
                deadline_milliseconds=deadline_milliseconds,
                claim_payload_arguments=claim_payload_arguments,
                signature_value=str(signature["value"]),
                container_name=container_name,
                timeout_seconds=remaining_seconds,
            )
        except SnapshotCollectionError as exc:
            if exc.code == "RUNTIME_COMMAND_TIMEOUT":
                self._remove_timed_out_container(container_name)
                raise GatewayHttpFixtureError(
                    "HTTP_FIXTURE_DEADLINE", "fixture deadline exceeded"
                ) from exc
            raise
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
        completed_at = _trusted_time(self._clock)
        if completed_at >= effective_deadline:
            outcome = "deadline_exceeded"
        return GatewayResponseMeasurement(outcome, observed, retained, completed_at)

    def _execute_transport(
        self,
        *,
        claim: dict[str, Any],
        network_id: str,
        maximum_response_bytes: int,
        deadline_milliseconds: int,
        claim_payload_arguments: tuple[str, ...],
        signature_value: str,
        container_name: str,
        timeout_seconds: float,
    ) -> CommandResult:
        return self._executor.execute(
            oci_run_command(
                self._executable,
                "--rm",
                f"--name={container_name}",
                "--label=com.pentai.managed=true",
                "--label=com.pentai.role=gateway-http-fixture",
                f"--label=com.pentai.execution-claim={claim['claim_id']}",
                f"--label=com.pentai.runtime-id={claim['runtime_id']}",
                f"--label=com.pentai.gateway-network={network_id}",
                f"--label=com.pentai.image-digest={claim['image_digest']}",
                f"--network={network_id}",
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
                *claim_payload_arguments,
                f"--claim-signature={signature_value}",
            ),
            timeout_seconds=timeout_seconds,
            max_output_bytes=4096,
        )

    def _remove_timed_out_container(self, container_name: str) -> None:
        try:
            result = self._executor.execute(
                (self._executable, "rm", "--force", container_name),
                timeout_seconds=2,
                max_output_bytes=4096,
            )
        except SnapshotCollectionError as exc:
            self._fail_cleanup(exc)
        if result.returncode != 0:
            self._fail_cleanup()

    def _fail_cleanup(self, cause: Exception | None = None) -> NoReturn:
        try:
            self._pause_safety("GATEWAY_FIXTURE_CLEANUP_FAILED")
        except Exception as exc:
            raise GatewayHttpFixtureError(
                "HTTP_FIXTURE_SAFETY_PAUSE_FAILED", "fixture safety pause failed"
            ) from exc
        error = GatewayHttpFixtureError(
            "HTTP_FIXTURE_CLEANUP_FAILED", "fixture cleanup failed"
        )
        if cause is not None:
            raise error from cause
        raise error


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


def _trusted_time(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise GatewayHttpFixtureError("HTTP_FIXTURE_CLOCK", "fixture clock is invalid")
    return value.astimezone(UTC)
