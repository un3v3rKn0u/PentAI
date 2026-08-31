from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues


def _capability() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "capability_id": str(uuid4()),
        "implementation_id": "synthetic-meter",
        "implementation_version": 1,
        "provider_types": ["approved_remote", "local_runtime"],
        "supported_dimensions": ["requests", "runtime_seconds"],
        "valid_from": "2026-08-31T06:00:00Z",
        "expires_at": "2026-08-31T06:05:00Z",
        "state": "inactive",
        "identity_binding_enabled": False,
        "attestation_enabled": False,
        "measurement_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def _receipt(capability: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "capability_id": capability["capability_id"],
        "capability_digest": "sha256:" + "a" * 64,
        "implementation_id": capability["implementation_id"],
        "implementation_version": capability["implementation_version"],
        "provider_types": copy.deepcopy(capability["provider_types"]),
        "supported_dimensions": copy.deepcopy(capability["supported_dimensions"]),
        "recorded_at": "2026-08-31T06:00:01Z",
        "expires_at": capability["expires_at"],
        "state": "inactive",
        "identity_binding_enabled": False,
        "attestation_enabled": False,
        "measurement_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def test_implementation_contracts_are_closed_and_inert() -> None:
    capability = _capability()
    assert contract_issues(
        capability, "ai-runtime-meter-implementation-v1.schema.json"
    ) == ()
    assert contract_issues(
        _receipt(capability), "ai-runtime-meter-implementation-receipt-v1.schema.json"
    ) == ()


def test_implementation_contract_denies_capability_and_authority_expansion() -> None:
    for field, value in (
        ("schema_version", "2.0.0"),
        ("state", "active"),
        ("identity_binding_enabled", True),
        ("attestation_enabled", True),
        ("measurement_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = _capability()
        malformed[field] = value
        assert contract_issues(
            malformed, "ai-runtime-meter-implementation-v1.schema.json"
        )
        malformed_receipt = _receipt(_capability())
        malformed_receipt[field] = value
        assert contract_issues(
            malformed_receipt,
            "ai-runtime-meter-implementation-receipt-v1.schema.json",
        )


def test_implementation_contract_denies_ambiguous_or_unsupported_claims() -> None:
    for field, values in (
        ("provider_types", []),
        ("provider_types", ["local_runtime", "local_runtime"]),
        ("provider_types", ["untrusted_provider"]),
        ("supported_dimensions", []),
        ("supported_dimensions", ["requests", "requests"]),
        ("supported_dimensions", ["unbounded_usage"]),
    ):
        malformed = _capability()
        malformed[field] = values
        assert contract_issues(
            malformed, "ai-runtime-meter-implementation-v1.schema.json"
        )


def test_implementation_contract_excludes_runtime_and_provider_payloads() -> None:
    for field in (
        "credential",
        "secret_reference",
        "prompt",
        "provider_response",
        "usage",
        "pricing",
        "tokenizer",
        "diagnostic",
        "command",
        "payload",
    ):
        malformed = _capability()
        malformed[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed, "ai-runtime-meter-implementation-v1.schema.json"
        )
        malformed_receipt = _receipt(_capability())
        malformed_receipt[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed_receipt,
            "ai-runtime-meter-implementation-receipt-v1.schema.json",
        )
