from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pentai_core.agent_intent import AgentActionIntentService, AgentIntentError
from pentai_core.orchestration_retry_manifest import (
    OrchestrationRetryManifestError,
    OrchestrationRetryManifestService,
)
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_retry_activation_v2 import setup as activation_setup


def setup(
    tmp_path: Path,
) -> tuple[OrchestrationRetryManifestService, dict[str, Any], dict[str, Any]]:
    activations, activation_command, _ = activation_setup(tmp_path)
    activation = activations.consume(activation_command, now=NOW + timedelta(seconds=42))
    command: dict[str, Any] = {
        "schema_version": "4.0.0",
        "request_id": str(uuid4()),
        "assessment_id": activation["assessment_id"],
        "plan_id": activation["plan_id"],
        "expected_plan_revision": activation["resulting_plan_revision"],
        "task_id": activation["task_id"],
        "expected_task_revision": activation["resulting_task_revision"],
        "agent_id": "agent://validation/retry-fixture",
        "retry_activation_id": activation["activation_id"],
        "retry_activation_digest": activation["activation_digest"],
        "policy_bundle_id": activation["policy_bundle_id"],
        "policy_hash": activation["policy_hash"],
        "limits": {
            "maximum_impact": "benign",
            "maximum_timeout_seconds": 30,
            "maximum_response_bytes": 1_048_576,
        },
        "purpose": "issue_attempt_three_validation_manifest",
        "requested_at": (NOW + timedelta(seconds=43)).isoformat(),
        "expires_at": (NOW + timedelta(seconds=54)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationRetryManifestService(activations.authorization), command, activation


def test_issues_attempt_three_ready_manifest_without_authority(tmp_path: Path) -> None:
    service, command, activation = setup(tmp_path)
    manifest = service.issue_v4(command, now=NOW + timedelta(seconds=43))
    assert contract_issues(manifest, "task-capability-manifest-v4.schema.json") == ()
    assert manifest["retry_activation_id"] == activation["activation_id"]
    assert manifest["attempt_number"] == 3
    assert manifest["task_state"] == "ready"
    assert manifest["authority"] == "none" and manifest["execution_enabled"] is False
    assert service.issue_v4(command, now=NOW + timedelta(seconds=43)) == manifest
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM task_capability_manifests_v4"
        ).fetchone() == (1,)
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM orchestration_task_budget_reservations"
            ).fetchone()[0]
            == 2
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_leases WHERE state='active'"
        ).fetchone() == (0,)
        connection.row_factory = sqlite3.Row
        with pytest.raises(AgentIntentError) as denied:
            AgentActionIntentService._revalidate_manifest(
                connection,
                {
                    "capability_manifest_id": manifest["manifest_id"],
                    "expected_manifest_revision": 1,
                },
                NOW + timedelta(seconds=43),
            )
        assert denied.value.code == "AGENT_INTENT_MANIFEST_MISSING"


def test_malformed_mixed_version_tampering_and_attempt_four_deny(tmp_path: Path) -> None:
    cases = (
        {"schema_version": "3.0.0"},
        {"attempt_number": 4},
        {"delegation_allowed": True},
        {"authority": "grant"},
        {"retry_activation_digest": "sha256:" + "0" * 64},
        {"assessment_id": str(uuid4())},
        {"agent_id": "agent://validation/other"},
    )
    for index, changes in enumerate(cases):
        service, command, _ = setup(tmp_path / str(index))
        command.update(changes)
        with pytest.raises(OrchestrationRetryManifestError):
            service.issue_v4(command, now=NOW + timedelta(seconds=43))


def test_changed_replay_concurrency_and_security_fences(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path / "replay")
    service.issue_v4(command, now=NOW + timedelta(seconds=43))
    changed = copy.deepcopy(command)
    changed["limits"]["maximum_response_bytes"] = 4096
    with pytest.raises(OrchestrationRetryManifestError) as conflict:
        service.issue_v4(changed, now=NOW + timedelta(seconds=43))
    assert conflict.value.code == "RETRY_CAPABILITY_IDENTITY_CONFLICT"

    concurrent, contender, _ = setup(tmp_path / "concurrent")

    def issue(candidate: dict[str, Any]) -> str:
        try:
            return str(
                concurrent.issue_v4(candidate, now=NOW + timedelta(seconds=43))["manifest_id"]
            )
        except OrchestrationRetryManifestError as error:
            return error.code

    candidates = (copy.deepcopy(contender), copy.deepcopy(contender))
    candidates[1]["request_id"] = str(uuid4())
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(issue, candidates))
    assert sum(value.startswith("RETRY_CAPABILITY_") for value in outcomes) == 1

    for name in ("safety", "cancel", "worker", "recovery"):
        fenced, fenced_command, _ = setup(tmp_path / name)
        with closing(sqlite3.connect(fenced.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "cancel":
                connection.execute(
                    "UPDATE engagements SET status='revoked' WHERE id=?",
                    (fenced_command["assessment_id"],),
                )
            elif name == "worker":
                connection.execute(
                    """UPDATE worker_runtime_instances SET status='termination_requested',
                    version=version+1 WHERE worker_id='worker:synthetic:retry-lease'"""
                )
            else:
                connection.execute(
                    """UPDATE orchestration_task_lease_fences
                    SET recovery_generation=recovery_generation+1, version=version+1
                    WHERE task_id=?""",
                    (fenced_command["task_id"],),
                )
        with pytest.raises(OrchestrationRetryManifestError):
            fenced.issue_v4(fenced_command, now=NOW + timedelta(seconds=43))


def test_storage_is_immutable_and_direct_insert_denies(tmp_path: Path) -> None:
    service, command, _ = setup(tmp_path)
    manifest = service.issue_v4(command, now=NOW + timedelta(seconds=43))
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE task_capability_manifests_v4 SET authority='none' WHERE manifest_id=?",
                (manifest["manifest_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM task_capability_manifests_v4 WHERE manifest_id=?",
                (manifest["manifest_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO task_capability_manifests_v4
                SELECT ?, 1, ?, request_digest, assessment_id, plan_id, plan_revision,
                task_id, task_revision, agent_id, policy_bundle_id, policy_hash,
                retry_activation_id, retry_schedule_id, retry_attempt_id,
                retry_budget_consumption_id, manifest_json, manifest_hash, issued_at,
                expires_at, 'pentai-core', 0, 'none', 0
                FROM task_capability_manifests_v4 WHERE manifest_id=?""",
                (str(uuid4()), str(uuid4()), manifest["manifest_id"]),
            )
