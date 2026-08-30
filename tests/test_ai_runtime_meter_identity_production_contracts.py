from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues


def _command(*, remote: bool = True) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "meter_id": str(uuid4()),
        "implementation_id": "synthetic-meter",
        "implementation_version": 1,
        "configuration_snapshot_id": str(uuid4()),
        "configuration_snapshot_digest": "sha256:" + "a" * 64,
        "configuration_id": str(uuid4()),
        "configuration_hash": "b" * 64,
        "registry_id": str(uuid4()),
        "registry_revision": 7,
        "provider_type": "approved_remote" if remote else "local_runtime",
        "provider_id": "synthetic-remote" if remote else "synthetic-local",
        "model_id": "synthetic-model-v1",
        "worker_id": "synthetic-worker",
        "worker_version": 3,
        "runtime_instance_id": "synthetic-runtime",
        "containment_attestation_id": str(uuid4()),
        "image_digest": "sha256:" + "c" * 64,
        "supported_dimensions": ["requests", "runtime_seconds"],
        "identity_valid_from": "2026-08-30T21:00:00Z",
        "identity_expires_at": "2026-08-30T21:05:00Z",
        "requester": {
            "actor_type": "human",
            "actor_id": "local-desktop-session",
            "session_id": str(uuid4()),
        },
        "authentication_context": "local_core_authenticated_session",
        "purpose": "record_runtime_meter_identity",
        "requested_at": "2026-08-30T20:59:59Z",
        "expires_at": "2026-08-30T21:00:30Z",
        "production_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def _receipt(command: dict[str, Any]) -> dict[str, Any]:
    excluded = {"schema_version", "purpose", "requested_at", "expires_at"}
    receipt = {key: copy.deepcopy(value) for key, value in command.items() if key not in excluded}
    receipt.update(
        {
            "schema_version": "2.0.0",
            "meter_identity_digest": "sha256:" + "d" * 64,
            "command_digest": "sha256:" + "e" * 64,
            "state": "inactive",
            "attestation_enabled": False,
            "measurement_enabled": False,
            "recorded_at": "2026-08-30T21:00:01Z",
        }
    )
    return receipt


def test_production_contracts_bind_exact_inert_source_lineage() -> None:
    for command in (_command(), _command(remote=False)):
        assert contract_issues(
            command, "ai-runtime-meter-identity-command-v1.schema.json"
        ) == ()
        assert contract_issues(
            _receipt(command), "ai-runtime-meter-identity-receipt-v2.schema.json"
        ) == ()


def test_production_command_denies_mixed_version_and_authority() -> None:
    for field, value in (
        ("schema_version", "2.0.0"),
        ("authentication_context", "caller_assertion"),
        ("purpose", "attest_runtime_meter"),
        ("production_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = _command()
        malformed[field] = value
        assert contract_issues(
            malformed, "ai-runtime-meter-identity-command-v1.schema.json"
        )
    caller = _command()
    caller["requester"]["actor_id"] = "caller-selected"
    assert contract_issues(caller, "ai-runtime-meter-identity-command-v1.schema.json")


def test_production_contracts_deny_payloads_and_ambiguous_dimensions() -> None:
    for field in (
        "credential",
        "secret_reference",
        "prompt",
        "provider_response",
        "usage",
        "pricing",
        "tokenizer",
        "diagnostic",
        "payload",
    ):
        malformed = _command()
        malformed[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed, "ai-runtime-meter-identity-command-v1.schema.json"
        )
        malformed_receipt = _receipt(_command())
        malformed_receipt[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed_receipt, "ai-runtime-meter-identity-receipt-v2.schema.json"
        )
    for dimensions in (
        ["requests", "requests"],
        ["unsupported"],
        [],
    ):
        malformed = _command()
        malformed["supported_dimensions"] = dimensions
        assert contract_issues(
            malformed, "ai-runtime-meter-identity-command-v1.schema.json"
        )


def test_production_receipt_v2_cannot_attest_or_measure() -> None:
    for field, value in (
        ("schema_version", "1.0.0"),
        ("state", "active"),
        ("attestation_enabled", True),
        ("measurement_enabled", True),
        ("production_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = _receipt(_command())
        malformed[field] = value
        assert contract_issues(
            malformed, "ai-runtime-meter-identity-receipt-v2.schema.json"
        )
