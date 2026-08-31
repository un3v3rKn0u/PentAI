from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues


def _command() -> dict[str, Any]:
    return {
        "schema_version": "2.0.0",
        "command_id": str(uuid4()),
        "capability_id": str(uuid4()),
        "manifest_id": str(uuid4()),
        "manifest_revision": 1,
        "manifest_digest": "sha256:" + "a" * 64,
        "manifest_registry_digest": "sha256:" + "b" * 64,
        "implementation_id": "synthetic-meter",
        "implementation_version": 1,
        "implementation_artifact_digest": "sha256:" + "c" * 64,
        "provider_types": ["approved_remote", "local_runtime"],
        "supported_dimensions": ["requests", "runtime_seconds"],
        "capability_valid_from": "2026-08-31T17:00:00Z",
        "capability_expires_at": "2026-08-31T17:05:00Z",
        "requester": {
            "actor_type": "human",
            "actor_id": "test-session",
            "session_id": str(uuid4()),
        },
        "authentication_context": "local_core_authenticated_session",
        "purpose": "record_manifest_verified_runtime_meter_implementation",
        "requested_at": "2026-08-31T16:59:59Z",
        "expires_at": "2026-08-31T17:00:30Z",
        "production_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def _receipt(command: dict[str, Any]) -> dict[str, Any]:
    excluded = {"schema_version", "purpose", "requested_at", "expires_at"}
    receipt = {key: copy.deepcopy(value) for key, value in command.items() if key not in excluded}
    receipt.update(
        {
            "schema_version": "3.0.0",
            "capability_digest": "sha256:" + "d" * 64,
            "command_digest": "sha256:" + "e" * 64,
            "state": "inactive",
            "identity_binding_enabled": False,
            "attestation_enabled": False,
            "measurement_enabled": False,
            "recorded_at": "2026-08-31T17:00:01Z",
        }
    )
    return receipt


def test_manifest_bound_contracts_accept_exact_inert_lineage() -> None:
    command = _command()
    assert contract_issues(
        command, "ai-runtime-meter-implementation-command-v2.schema.json"
    ) == ()
    assert contract_issues(
        _receipt(command), "ai-runtime-meter-implementation-receipt-v3.schema.json"
    ) == ()


def test_command_denies_missing_or_malformed_manifest_bindings() -> None:
    for field, value in (
        ("manifest_id", "caller-manifest"),
        ("manifest_revision", 0),
        ("manifest_digest", "sha256:caller"),
        ("manifest_registry_digest", "sha256:caller"),
        ("implementation_artifact_digest", "sha256:caller"),
    ):
        malformed = _command()
        malformed[field] = value
        assert contract_issues(
            malformed, "ai-runtime-meter-implementation-command-v2.schema.json"
        )

        missing = _command()
        del missing[field]
        assert contract_issues(
            missing, "ai-runtime-meter-implementation-command-v2.schema.json"
        )

        malformed_receipt = _receipt(_command())
        malformed_receipt[field] = value
        assert contract_issues(
            malformed_receipt,
            "ai-runtime-meter-implementation-receipt-v3.schema.json",
        )

        missing_receipt = _receipt(_command())
        del missing_receipt[field]
        assert contract_issues(
            missing_receipt,
            "ai-runtime-meter-implementation-receipt-v3.schema.json",
        )


def test_contracts_deny_mixed_versions_and_capability_escalation() -> None:
    for field, value in (
        ("schema_version", "1.0.0"),
        ("authentication_context", "caller_assertion"),
        ("purpose", "activate_runtime_meter_implementation"),
        ("production_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = _command()
        malformed[field] = value
        assert contract_issues(
            malformed, "ai-runtime-meter-implementation-command-v2.schema.json"
        )

    for field, value in (
        ("schema_version", "2.0.0"),
        ("state", "active"),
        ("identity_binding_enabled", True),
        ("attestation_enabled", True),
        ("measurement_enabled", True),
        ("production_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = _receipt(_command())
        malformed[field] = value
        assert contract_issues(
            malformed, "ai-runtime-meter-implementation-receipt-v3.schema.json"
        )


def test_contracts_deny_untyped_or_sensitive_payloads() -> None:
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
        malformed_command = _command()
        malformed_command[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed_command,
            "ai-runtime-meter-implementation-command-v2.schema.json",
        )

        malformed_receipt = _receipt(_command())
        malformed_receipt[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed_receipt,
            "ai-runtime-meter-implementation-receipt-v3.schema.json",
        )
