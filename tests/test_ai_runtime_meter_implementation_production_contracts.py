from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues


def _command() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "capability_id": str(uuid4()),
        "implementation_id": "synthetic-meter",
        "implementation_version": 1,
        "provider_types": ["approved_remote", "local_runtime"],
        "supported_dimensions": ["requests", "runtime_seconds"],
        "capability_valid_from": "2026-08-31T08:00:00Z",
        "capability_expires_at": "2026-08-31T08:05:00Z",
        "requester": {
            "actor_type": "human",
            "actor_id": "local-desktop-session",
            "session_id": str(uuid4()),
        },
        "authentication_context": "local_core_authenticated_session",
        "purpose": "record_runtime_meter_implementation",
        "requested_at": "2026-08-31T07:59:59Z",
        "expires_at": "2026-08-31T08:00:30Z",
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
            "capability_digest": "sha256:" + "a" * 64,
            "command_digest": "sha256:" + "b" * 64,
            "state": "inactive",
            "identity_binding_enabled": False,
            "attestation_enabled": False,
            "measurement_enabled": False,
            "recorded_at": "2026-08-31T08:00:01Z",
        }
    )
    return receipt


def test_production_contracts_bind_exact_inert_source_lineage() -> None:
    command = _command()
    assert contract_issues(
        command, "ai-runtime-meter-implementation-command-v1.schema.json"
    ) == ()
    assert contract_issues(
        _receipt(command), "ai-runtime-meter-implementation-receipt-v2.schema.json"
    ) == ()


def test_production_command_denies_mixed_version_and_authority() -> None:
    for field, value in (
        ("schema_version", "2.0.0"),
        ("authentication_context", "caller_assertion"),
        ("purpose", "activate_runtime_meter_implementation"),
        ("production_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = _command()
        malformed[field] = value
        assert contract_issues(
            malformed, "ai-runtime-meter-implementation-command-v1.schema.json"
        )
    caller = _command()
    caller["requester"]["actor_id"] = "caller-selected"
    assert contract_issues(
        caller, "ai-runtime-meter-implementation-command-v1.schema.json"
    )


def test_production_contracts_deny_payloads_and_ambiguous_claims() -> None:
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
            malformed, "ai-runtime-meter-implementation-command-v1.schema.json"
        )
        malformed_receipt = _receipt(_command())
        malformed_receipt[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed_receipt,
            "ai-runtime-meter-implementation-receipt-v2.schema.json",
        )
    for field, values in (
        ("provider_types", []),
        ("provider_types", ["local_runtime", "local_runtime"]),
        ("provider_types", ["untrusted_provider"]),
        ("supported_dimensions", []),
        ("supported_dimensions", ["requests", "requests"]),
        ("supported_dimensions", ["unbounded_usage"]),
    ):
        malformed = _command()
        malformed[field] = values
        assert contract_issues(
            malformed, "ai-runtime-meter-implementation-command-v1.schema.json"
        )


def test_production_receipt_v2_cannot_activate_bind_attest_or_measure() -> None:
    for field, value in (
        ("schema_version", "1.0.0"),
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
            malformed, "ai-runtime-meter-implementation-receipt-v2.schema.json"
        )
