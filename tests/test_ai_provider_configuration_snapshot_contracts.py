from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues


def _snapshot(*, remote: bool = True) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "snapshot_id": str(uuid4()),
        "configuration_id": str(uuid4()),
        "configuration_hash": "a" * 64,
        "registry_id": str(uuid4()),
        "registry_revision": 2,
        "provider_type": "approved_remote" if remote else "local_runtime",
        "provider_id": "synthetic-remote" if remote else "synthetic-local",
        "model_id": "synthetic-model-v1",
        "privacy_classification": "remote_third_party" if remote else "local_device",
        "allowed_input_classifications": ["public", "internal"],
        "budgets": {
            "max_input_tokens": 1000,
            "max_output_tokens": 500,
            "max_requests": 2,
            "max_cost_microusd": 1000 if remote else 0,
            "max_runtime_seconds": 60,
        },
        "remote_provider_opt_in": remote,
        "secret_reference_state": "present_digest_only" if remote else "absent",
        "secret_reference_digest": "sha256:" + "b" * 64 if remote else None,
        "configured_at": "2026-08-29T20:00:00Z",
        "expires_at": "2026-08-30T20:00:00Z",
        "snapshotted_at": "2026-08-29T20:01:00Z",
        "state": "inactive",
        "meter_binding_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def test_remote_and_local_provider_snapshots_are_closed_and_inert() -> None:
    for snapshot in (_snapshot(), _snapshot(remote=False)):
        assert contract_issues(
            snapshot, "ai-provider-configuration-snapshot-v1.schema.json"
        ) == ()
    for key, value in (
        ("schema_version", "2.0.0"),
        ("state", "active"),
        ("meter_binding_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = _snapshot()
        malformed[key] = value
        assert contract_issues(
            malformed, "ai-provider-configuration-snapshot-v1.schema.json"
        )


def test_snapshot_rejects_secret_material_privacy_widening_and_cross_type_fields() -> None:
    injected = _snapshot()
    injected["secret_ref"] = f"secretref://provider/synthetic-remote/{uuid4()}"
    assert contract_issues(
        injected, "ai-provider-configuration-snapshot-v1.schema.json"
    )
    for classification in ("secret", "restricted_raw_evidence"):
        malformed = _snapshot()
        malformed["allowed_input_classifications"] = [classification]
        assert contract_issues(
            malformed, "ai-provider-configuration-snapshot-v1.schema.json"
        )
    local = _snapshot(remote=False)
    local["secret_reference_digest"] = "sha256:" + "c" * 64
    assert contract_issues(
        local, "ai-provider-configuration-snapshot-v1.schema.json"
    )
    remote = _snapshot()
    remote["secret_reference_digest"] = None
    assert contract_issues(
        remote, "ai-provider-configuration-snapshot-v1.schema.json"
    )


def test_snapshot_receipt_cannot_activate_meter_or_execution() -> None:
    snapshot = _snapshot()
    receipt = {
        "schema_version": "1.0.0",
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_digest": "sha256:" + "d" * 64,
        "configuration_id": snapshot["configuration_id"],
        "configuration_hash": snapshot["configuration_hash"],
        "registry_id": snapshot["registry_id"],
        "registry_revision": snapshot["registry_revision"],
        "provider_type": snapshot["provider_type"],
        "provider_id": snapshot["provider_id"],
        "model_id": snapshot["model_id"],
        "state": "inactive",
        "meter_binding_enabled": False,
        "recorded_at": "2026-08-29T20:01:01Z",
        "authority": "none",
        "execution_enabled": False,
    }
    assert contract_issues(
        receipt, "ai-provider-configuration-snapshot-receipt-v1.schema.json"
    ) == ()
    for field in ("prompt", "provider_response", "pricing", "tokenizer", "diagnostic"):
        injected = copy.deepcopy(receipt)
        injected[field] = "synthetic but forbidden"
        assert contract_issues(
            injected, "ai-provider-configuration-snapshot-receipt-v1.schema.json"
        )
