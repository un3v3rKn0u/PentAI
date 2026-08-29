from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues


def _measurement() -> dict[str, Any]:
    def identifier() -> str:
        return str(uuid4())
    digest = "sha256:" + "a" * 64
    return {
        "schema_version": "1.0.0",
        "measurement_id": identifier(),
        "completion_id": identifier(),
        "completion_digest": digest,
        "assessment_id": identifier(),
        "plan_id": identifier(),
        "plan_revision": 8,
        "task_id": identifier(),
        "task_revision": 8,
        "retry_attempt_id": identifier(),
        "attempt_number": 3,
        "budget_reservation_id": identifier(),
        "budget_request_digest": digest,
        "budget_account_id": identifier(),
        "budget_account_version": 4,
        "configuration_id": identifier(),
        "configuration_hash": "b" * 64,
        "registry_id": identifier(),
        "registry_revision": 1,
        "worker_id": "synthetic-worker",
        "worker_version": 1,
        "lease_consumption_id": identifier(),
        "checkpoint_id": None,
        "checkpoint_sequence": None,
        "checkpoint_digest": None,
        "fencing_token": 3,
        "recovery_generation": 1,
        "measurement_source": "trusted_runtime_meter",
        "amounts": {
            "input_tokens": 100,
            "output_tokens": 20,
            "requests": 1,
            "cost_microusd": 250,
            "runtime_seconds": 2,
        },
        "measured_at": "2026-08-29T20:00:00Z",
        "purpose": "record_attempt_three_provider_usage",
        "authority": "none",
        "execution_enabled": False,
    }


def test_provider_usage_measurement_is_closed_integer_only_and_version_exact() -> None:
    measurement = _measurement()
    assert contract_issues(
        measurement, "orchestration-provider-usage-measurement-v1.schema.json"
    ) == ()
    for key, value in (
        ("attempt_number", 4),
        ("schema_version", "2.0.0"),
        ("measurement_source", "caller"),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = copy.deepcopy(measurement)
        malformed[key] = value
        assert contract_issues(
            malformed, "orchestration-provider-usage-measurement-v1.schema.json"
        )
    for value in (-1, 0.5, 1000000001):
        malformed = copy.deepcopy(measurement)
        malformed["amounts"]["cost_microusd"] = value
        assert contract_issues(
            malformed, "orchestration-provider-usage-measurement-v1.schema.json"
        )
    empty = copy.deepcopy(measurement)
    empty["amounts"] = {key: 0 for key in empty["amounts"]}
    assert contract_issues(
        empty, "orchestration-provider-usage-measurement-v1.schema.json"
    )


def test_provider_usage_measurement_rejects_ambiguous_checkpoint_and_payloads() -> None:
    measurement = _measurement()
    measurement["checkpoint_sequence"] = 1
    assert contract_issues(
        measurement, "orchestration-provider-usage-measurement-v1.schema.json"
    )
    for field in ("provider_response", "evidence", "output", "price"):
        injected = _measurement()
        injected[field] = "synthetic but forbidden"
        assert contract_issues(
            injected, "orchestration-provider-usage-measurement-v1.schema.json"
        )


def test_provider_usage_receipt_is_inert_metadata_only() -> None:
    measurement = _measurement()
    receipt = {
        "schema_version": "1.0.0",
        "measurement_id": measurement["measurement_id"],
        "measurement_digest": "sha256:" + "c" * 64,
        "completion_id": measurement["completion_id"],
        "completion_digest": measurement["completion_digest"],
        "assessment_id": measurement["assessment_id"],
        "plan_id": measurement["plan_id"],
        "plan_revision": measurement["plan_revision"],
        "task_id": measurement["task_id"],
        "task_revision": measurement["task_revision"],
        "budget_reservation_id": measurement["budget_reservation_id"],
        "budget_account_id": measurement["budget_account_id"],
        "budget_account_version": measurement["budget_account_version"],
        "amounts": measurement["amounts"],
        "recorded_at": "2026-08-29T20:00:01Z",
        "reconciliation_enabled": False,
        "budget_finalization_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }
    assert contract_issues(
        receipt, "orchestration-provider-usage-receipt-v1.schema.json"
    ) == ()
    for key, value in (
        ("reconciliation_enabled", True),
        ("budget_finalization_enabled", True),
        ("authority", "grant"),
    ):
        malformed = copy.deepcopy(receipt)
        malformed[key] = value
        assert contract_issues(
            malformed, "orchestration-provider-usage-receipt-v1.schema.json"
        )
    empty = copy.deepcopy(receipt)
    empty["amounts"] = {key: 0 for key in empty["amounts"]}
    assert contract_issues(
        empty, "orchestration-provider-usage-receipt-v1.schema.json"
    )
