from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues


def _command() -> dict[str, Any]:
    def identifier() -> str:
        return str(uuid4())

    digest = "sha256:" + "a" * 64
    return {
        "schema_version": "3.0.0", "command_id": identifier(),
        "assessment_id": identifier(), "plan_id": identifier(),
        "expected_plan_revision": 7, "task_id": identifier(),
        "expected_task_revision": 7, "agent_id": "validation-agent",
        "capability_manifest_id": identifier(), "capability_manifest_digest": digest,
        "manifest_revision": 1, "budget_reservation_id": identifier(),
        "budget_request_digest": digest, "budget_account_version": 3,
        "retry_policy_id": identifier(), "retry_policy_digest": digest,
        "retry_activation_id": identifier(), "retry_activation_digest": digest,
        "retry_schedule_id": identifier(), "retry_schedule_digest": digest,
        "retry_attempt_id": identifier(), "retry_attempt_digest": digest,
        "attempt_number": 3, "prior_retry_budget_consumption_id": identifier(),
        "retry_budget_consumption_id": identifier(), "approval_consumption_id": None,
        "lease_consumption_id": identifier(), "lease_consumption_digest": digest,
        "policy_bundle_id": identifier(), "policy_hash": "b" * 64,
        "worker_id": "synthetic-worker", "expected_worker_version": 1,
        "lease_id": identifier(), "lease_generation": 3, "fencing_token": 3,
        "expected_recovery_generation": 1, "checkpoint_id": None,
        "checkpoint_sequence": None, "checkpoint_digest": None,
        "purpose": "consume_attempt_three_validation_task_completion",
        "requested_at": "2026-08-29T12:00:00Z",
        "expires_at": "2026-08-29T12:05:00Z", "authority": "none",
        "execution_enabled": False,
    }


def test_attempt_three_completion_contract_is_closed_and_version_exact() -> None:
    command = _command()
    assert contract_issues(
        command, "orchestration-task-completion-command-v3.schema.json"
    ) == ()
    for key, value in (
        ("attempt_number", 4),
        ("schema_version", "2.0.0"),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = copy.deepcopy(command)
        malformed[key] = value
        assert contract_issues(
            malformed, "orchestration-task-completion-command-v3.schema.json"
        )
    injected = copy.deepcopy(command)
    injected["output"] = "synthetic but forbidden"
    assert contract_issues(
        injected, "orchestration-task-completion-command-v3.schema.json"
    )


def test_attempt_three_completion_checkpoint_tuple_is_all_or_absent() -> None:
    command = _command()
    command["checkpoint_sequence"] = 1
    assert contract_issues(
        command, "orchestration-task-completion-command-v3.schema.json"
    )
    command = _command()
    command["checkpoint_id"] = str(uuid4())
    command["checkpoint_sequence"] = 1
    command["checkpoint_digest"] = "sha256:" + "c" * 64
    assert contract_issues(
        command, "orchestration-task-completion-command-v3.schema.json"
    ) == ()


def test_attempt_three_completion_receipt_is_metadata_only() -> None:
    command = _command()
    receipt = {
        **{key: value for key, value in command.items() if key not in {
            "requested_at", "expires_at", "expected_worker_version",
            "expected_recovery_generation",
        }},
        "completion_id": str(uuid4()),
        "command_digest": "sha256:" + "d" * 64,
        "resulting_plan_revision": command["expected_plan_revision"] + 1,
        "resulting_task_revision": command["expected_task_revision"] + 1,
        "worker_version": command["expected_worker_version"],
        "recovery_generation": command["expected_recovery_generation"],
        "recorded_at": "2026-08-29T12:00:01Z",
        "resulting_task_state": "succeeded",
        "completion_digest": "sha256:" + "e" * 64,
    }
    assert contract_issues(
        receipt, "orchestration-task-completion-receipt-v3.schema.json"
    ) == ()
    injected = copy.deepcopy(receipt)
    injected["provider_output"] = "forbidden"
    assert contract_issues(
        injected, "orchestration-task-completion-receipt-v3.schema.json"
    )
