from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues


def _snapshot() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "snapshot_id": str(uuid4()),
        "registry_id": str(uuid4()),
        "registry_revision": 3,
        "registry_digest": "sha256:" + "a" * 64,
        "providers": [
            {
                "provider_id": "synthetic-remote",
                "provider_type": "approved_remote",
                "models": ["synthetic-remote-model-v1"],
                "allowed_input_classifications": ["public", "internal"],
                "state": "enabled",
            },
            {
                "provider_id": "synthetic-local",
                "provider_type": "local_runtime",
                "models": ["synthetic-local-model-v1"],
                "allowed_input_classifications": ["public", "internal"],
                "state": "enabled",
            },
        ],
        "providers_digest": "sha256:" + "b" * 64,
        "budget_ceilings": {
            "max_input_tokens": 2000,
            "max_output_tokens": 1000,
            "max_requests": 4,
            "max_cost_microusd": 2000,
            "max_runtime_seconds": 120,
        },
        "remote_providers_enabled": True,
        "configured_at": "2026-08-29T20:00:00Z",
        "expires_at": "2026-08-30T20:00:00Z",
        "snapshotted_at": "2026-08-29T20:01:00Z",
        "state": "inactive",
        "activation_enabled": False,
        "revocation_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def test_registry_snapshot_is_closed_inert_and_provider_typed() -> None:
    snapshot = _snapshot()
    assert contract_issues(snapshot, "ai-provider-registry-snapshot-v1.schema.json") == ()
    for key, value in (
        ("schema_version", "2.0.0"),
        ("state", "active"),
        ("activation_enabled", True),
        ("revocation_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = copy.deepcopy(snapshot)
        malformed[key] = value
        assert contract_issues(malformed, "ai-provider-registry-snapshot-v1.schema.json")


def test_registry_snapshot_rejects_unsafe_or_unbounded_provider_metadata() -> None:
    for classification in ("secret", "restricted_raw_evidence"):
        malformed = _snapshot()
        malformed["providers"][0]["allowed_input_classifications"] = [classification]
        assert contract_issues(malformed, "ai-provider-registry-snapshot-v1.schema.json")
    for field in (
        "secret_ref",
        "credential",
        "pricing",
        "tokenizer",
        "provider_response",
        "diagnostic",
    ):
        malformed = _snapshot()
        malformed["providers"][0][field] = "synthetic but forbidden"
        assert contract_issues(malformed, "ai-provider-registry-snapshot-v1.schema.json")
    duplicated = _snapshot()
    duplicated["providers"].append(copy.deepcopy(duplicated["providers"][0]))
    assert contract_issues(duplicated, "ai-provider-registry-snapshot-v1.schema.json")
    malformed_digest = _snapshot()
    malformed_digest["registry_digest"] = "sha256:synthetic"
    assert contract_issues(
        malformed_digest, "ai-provider-registry-snapshot-v1.schema.json"
    )


def test_registry_snapshot_receipt_cannot_activate_or_revoke() -> None:
    snapshot = _snapshot()
    receipt = {
        "schema_version": "1.0.0",
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_digest": "sha256:" + "c" * 64,
        "registry_id": snapshot["registry_id"],
        "registry_revision": snapshot["registry_revision"],
        "registry_digest": snapshot["registry_digest"],
        "providers_digest": snapshot["providers_digest"],
        "state": "inactive",
        "activation_enabled": False,
        "revocation_enabled": False,
        "recorded_at": "2026-08-29T20:01:01Z",
        "authority": "none",
        "execution_enabled": False,
    }
    assert contract_issues(
        receipt, "ai-provider-registry-snapshot-receipt-v1.schema.json"
    ) == ()
    for field in ("providers", "activation", "revocation", "signature", "payload"):
        malformed = copy.deepcopy(receipt)
        malformed[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed, "ai-provider-registry-snapshot-receipt-v1.schema.json"
        )
