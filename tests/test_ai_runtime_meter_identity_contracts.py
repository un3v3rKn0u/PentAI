from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy import content_hash
from pentai_policy.document import contract_issues


def identity(*, provider_type: str = "approved_remote") -> dict[str, Any]:
    local = provider_type == "local_runtime"
    return {
        "schema_version": "1.0.0",
        "meter_id": str(uuid4()),
        "implementation_id": "synthetic-meter",
        "implementation_version": 1,
        "configuration_snapshot_id": str(uuid4()),
        "configuration_snapshot_digest": "sha256:" + "a" * 64,
        "configuration_id": str(uuid4()),
        "configuration_hash": "b" * 64,
        "registry_id": str(uuid4()),
        "registry_revision": 1,
        "provider_type": provider_type,
        "provider_id": "local-synthetic" if local else "remote-synthetic",
        "model_id": "synthetic-local-q4" if local else "synthetic-model-v1",
        "worker_id": "synthetic-worker",
        "worker_version": 2,
        "runtime_instance_id": "synthetic-runtime",
        "containment_attestation_id": str(uuid4()),
        "image_digest": "sha256:" + "c" * 64,
        "supported_dimensions": [
            "input_tokens",
            "output_tokens",
            "requests",
            "cost_microusd",
            "runtime_seconds",
        ],
        "valid_from": "2026-08-30T17:30:00Z",
        "expires_at": "2026-08-30T17:35:00Z",
        "state": "inactive",
        "measurement_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def receipt(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "meter_id": document["meter_id"],
        "meter_identity_digest": "sha256:" + content_hash(document),
        "configuration_snapshot_id": document["configuration_snapshot_id"],
        "configuration_snapshot_digest": document["configuration_snapshot_digest"],
        "worker_id": document["worker_id"],
        "worker_version": document["worker_version"],
        "implementation_id": document["implementation_id"],
        "implementation_version": document["implementation_version"],
        "recorded_at": "2026-08-30T17:30:01Z",
        "state": "inactive",
        "attestation_enabled": False,
        "measurement_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def test_remote_and_local_meter_identities_are_closed_and_inert() -> None:
    for provider_type in ("approved_remote", "local_runtime"):
        document = identity(provider_type=provider_type)
        assert contract_issues(document, "ai-runtime-meter-identity-v1.schema.json") == ()
        assert contract_issues(
            receipt(document), "ai-runtime-meter-identity-receipt-v1.schema.json"
        ) == ()
        assert document["state"] == "inactive"
        assert document["measurement_enabled"] is False
        assert document["authority"] == "none"
        assert document["execution_enabled"] is False


def test_identity_rejects_mixed_versions_authority_and_unsupported_dimensions() -> None:
    for key, value in (
        ("schema_version", "2.0.0"),
        ("state", "active"),
        ("measurement_enabled", True),
        ("authority", "provider"),
        ("execution_enabled", True),
    ):
        malformed = identity()
        malformed[key] = value
        assert contract_issues(malformed, "ai-runtime-meter-identity-v1.schema.json")

    unsupported = identity()
    unsupported["supported_dimensions"].append("cached_tokens")
    assert contract_issues(unsupported, "ai-runtime-meter-identity-v1.schema.json")

    duplicate = identity()
    duplicate["supported_dimensions"].append("requests")
    assert contract_issues(duplicate, "ai-runtime-meter-identity-v1.schema.json")


def test_identity_and_receipt_exclude_execution_and_provider_payloads() -> None:
    for field in (
        "provider_response",
        "prompt",
        "secret_reference",
        "credential",
        "price",
        "tokenizer",
        "diagnostic",
        "execution_receipt",
    ):
        malformed_identity = identity()
        malformed_identity[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed_identity, "ai-runtime-meter-identity-v1.schema.json"
        )
        malformed_receipt = receipt(identity())
        malformed_receipt[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed_receipt, "ai-runtime-meter-identity-receipt-v1.schema.json"
        )


def test_receipt_rejects_activation_measurement_and_changed_version() -> None:
    document = identity()
    for key, value in (
        ("schema_version", "2.0.0"),
        ("attestation_enabled", True),
        ("measurement_enabled", True),
        ("authority", "meter"),
        ("execution_enabled", True),
    ):
        malformed = copy.deepcopy(receipt(document))
        malformed[key] = value
        assert contract_issues(
            malformed, "ai-runtime-meter-identity-receipt-v1.schema.json"
        )
