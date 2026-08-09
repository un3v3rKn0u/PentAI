from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues, parse_time


class ContainmentError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_REQUIRED_TRUE = (
    "rootless",
    "read_only_root",
    "capabilities_dropped",
    "no_new_privileges",
    "host_pid_disabled",
    "host_ipc_disabled",
    "host_network_disabled",
    "resource_limits_supported",
    "temporary_mounts_only",
    "direct_egress_disabled",
    "external_dns_disabled",
    "ipv6_disabled",
)

_MAX_ATTESTATION_LIFETIME = timedelta(seconds=60)
_MAX_ARGV_ITEMS = 64
_MAX_ARG_LENGTH = 4096


def validate_containment_attestation(
    attestation: dict[str, Any], *, now: datetime | None = None
) -> None:
    if contract_issues(attestation, "worker-containment-attestation-v1.schema.json"):
        raise ContainmentError("CONTAINMENT_ATTESTATION_INVALID", "attestation is malformed")
    instant = now or datetime.now(UTC)
    observed_at = parse_time(attestation["observed_at"])
    expires_at = parse_time(attestation["expires_at"])
    if observed_at > instant:
        raise ContainmentError("CONTAINMENT_ATTESTATION_STALE", "attestation is future-dated")
    if expires_at <= instant:
        raise ContainmentError("CONTAINMENT_ATTESTATION_STALE", "attestation has expired")
    if expires_at <= observed_at or expires_at - observed_at > _MAX_ATTESTATION_LIFETIME:
        raise ContainmentError(
            "CONTAINMENT_ATTESTATION_INVALID",
            "attestation validity window is invalid",
        )
    if any(attestation.get(field) is not True for field in _REQUIRED_TRUE):
        raise ContainmentError("CONTAINMENT_UNAVAILABLE", "required containment is absent")
    if attestation.get("runtime_socket_mounted") is not False:
        raise ContainmentError("CONTAINMENT_RUNTIME_SOCKET", "runtime socket access is denied")


def prepare_worker_launch(
    *,
    session: dict[str, Any],
    containment_attestation: dict[str, Any],
    image_digest: str,
    argv: list[str],
    pid_limit: int = 64,
    memory_bytes: int = 268_435_456,
    cpu_quota: float = 1.0,
    now: datetime | None = None,
) -> dict[str, Any]:
    validate_containment_attestation(containment_attestation, now=now)
    if contract_issues(session, "gateway-session-v1.schema.json"):
        raise ContainmentError("GATEWAY_SESSION_INVALID", "gateway session is malformed")
    if session.get("status") != "prepared" or session.get("execution_enabled") is not False:
        raise ContainmentError("GATEWAY_SESSION_INACTIVE", "gateway session is not prepared")
    if (
        not argv
        or len(argv) > _MAX_ARGV_ITEMS
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > _MAX_ARG_LENGTH
            or "\x00" in item
            for item in argv
        )
    ):
        raise ContainmentError("WORKER_COMMAND_INVALID", "worker command is invalid")
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "launch_id": str(uuid4()),
        "session_id": session["session_id"],
        "containment_attestation_id": containment_attestation["attestation_id"],
        "image_digest": image_digest,
        "argv": argv,
        "network_mode": "gateway_only",
        "gateway_network_id": containment_attestation["gateway_network_id"],
        "read_only_root": True,
        "drop_capabilities": "ALL",
        "no_new_privileges": True,
        "pid_limit": pid_limit,
        "memory_bytes": memory_bytes,
        "cpu_quota": cpu_quota,
        "temporary_workspace": True,
        "mount_runtime_socket": False,
        "host_pid": False,
        "host_ipc": False,
        "ipv6_enabled": False,
        "external_dns_enabled": False,
        "execution_enabled": False,
    }
    if contract_issues(document, "worker-launch-spec-v1.schema.json"):
        raise ContainmentError("WORKER_LAUNCH_INVALID", "worker launch specification is invalid")
    return document
