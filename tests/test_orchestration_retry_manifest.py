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
from test_orchestration_retry_activation import setup as activation_setup


def setup(
    tmp_path: Path,
) -> tuple[OrchestrationRetryManifestService, dict[str, Any], dict[str, Any]]:
    activations, activation_command, _ = activation_setup(tmp_path)
    activation = activations.consume(activation_command, now=NOW + timedelta(seconds=7))
    arguments: dict[str, Any] = {
        "activation_id": activation["activation_id"],
        "activation_digest": activation["activation_digest"],
        "assessment_id": activation["assessment_id"],
        "plan_id": activation["plan_id"],
        "expected_plan_revision": activation["resulting_plan_revision"],
        "task_id": activation["task_id"],
        "expected_task_revision": activation["resulting_task_revision"],
        "agent_id": "agent://validation/retry-fixture",
        "policy_bundle_id": activation["policy_bundle_id"],
        "policy_hash": activation["policy_hash"],
        "now": NOW + timedelta(seconds=8),
    }
    return OrchestrationRetryManifestService(activations.authorization), arguments, activation


def test_issues_exact_retry_bound_ready_manifest_without_authority(tmp_path: Path) -> None:
    service, arguments, activation = setup(tmp_path)
    manifest = service.issue(**arguments)
    assert contract_issues(manifest, "task-capability-manifest-v3.schema.json") == ()
    assert manifest["retry_activation_id"] == activation["activation_id"]
    assert manifest["retry_attempt_id"] == activation["attempt_id"]
    assert manifest["retry_budget_consumption_id"] == activation["retry_budget_consumption_id"]
    assert manifest["task_state"] == "ready"
    assert manifest["authority"] == "none" and manifest["execution_enabled"] is False
    assert service.issue(**arguments) == manifest
    with closing(sqlite3.connect(service.database_path)) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM agent_action_intent_links").fetchone()[0]
            == 0
        )
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_task_leases WHERE state = 'active'"
        ).fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM action_grants").fetchone()[0] == 1
        assert connection.execute(
            "SELECT state FROM orchestration_tasks WHERE task_id = ?", (activation["task_id"],)
        ).fetchone() == ("ready",)
        connection.row_factory = sqlite3.Row
        with pytest.raises(AgentIntentError) as denied:
            AgentActionIntentService._revalidate_manifest(
                connection,
                {
                    "capability_manifest_id": manifest["manifest_id"],
                    "expected_manifest_revision": 1,
                },
                arguments["now"],
            )
        assert denied.value.code == "TASK_CAPABILITY_MANIFEST_MALFORMED"


def test_malformed_limits_and_cross_activation_binding_deny(tmp_path: Path) -> None:
    malformed, malformed_arguments, _ = setup(tmp_path / "malformed")
    malformed_arguments["maximum_timeout_seconds"] = 31
    with pytest.raises(OrchestrationRetryManifestError) as invalid:
        malformed.issue(**malformed_arguments)
    assert invalid.value.code == "RETRY_CAPABILITY_MANIFEST_MALFORMED"

    missing, missing_arguments, _ = setup(tmp_path / "missing")
    missing_arguments["activation_id"] = str(uuid4())
    with pytest.raises(OrchestrationRetryManifestError) as absent:
        missing.issue(**missing_arguments)
    assert absent.value.code == "RETRY_CAPABILITY_ACTIVATION_MISSING"

    service, arguments, _ = setup(tmp_path / "cross")
    arguments["activation_digest"] = "sha256:" + "0" * 64
    with pytest.raises(OrchestrationRetryManifestError) as mismatch:
        service.issue(**arguments)
    assert mismatch.value.code == "RETRY_CAPABILITY_ACTIVATION_MISMATCH"


def test_conflicting_replay_and_concurrent_issuance_deny(tmp_path: Path) -> None:
    service, arguments, _ = setup(tmp_path / "conflict")
    service.issue(**arguments)
    changed = copy.deepcopy(arguments)
    changed["maximum_response_bytes"] = 4096
    with pytest.raises(OrchestrationRetryManifestError) as conflict:
        service.issue(**changed)
    assert conflict.value.code == "RETRY_CAPABILITY_IDENTITY_CONFLICT"

    concurrent, concurrent_arguments, _ = setup(tmp_path / "concurrent")

    def issue() -> str:
        try:
            return str(concurrent.issue(**concurrent_arguments)["manifest_id"])
        except OrchestrationRetryManifestError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: issue(), range(2)))
    assert len(set(outcomes)) == 1
    with closing(sqlite3.connect(concurrent.database_path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM task_capability_manifests WHERE retry_activation_id IS NOT NULL"
        ).fetchone()[0] == 1


def test_safety_policy_recovery_and_task_revision_fences_deny(tmp_path: Path) -> None:
    for name in ("safety", "policy", "recovery", "task"):
        service, arguments, _ = setup(tmp_path / name)
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            if name == "safety":
                connection.execute(
                    "UPDATE safety_state SET global_status='paused', generation=generation+1"
                )
            elif name == "policy":
                connection.execute(
                    "UPDATE policy_bundles SET revoked_at=?",
                    ((NOW + timedelta(seconds=9)).isoformat(),),
                )
            elif name == "recovery":
                connection.execute("UPDATE orchestration_budget_accounts SET version=version+1")
            else:
                connection.execute(
                    """UPDATE orchestration_tasks SET state='cancelled', revision=revision+1
                    WHERE task_id=?""",
                    (arguments["task_id"],),
                )
        with pytest.raises(OrchestrationRetryManifestError) as denied:
            service.issue(**arguments)
        assert denied.value.code in {
            "RETRY_CAPABILITY_POLICY_STALE",
            "RETRY_CAPABILITY_ACTIVATION_INVALID",
        }


def test_manifest_storage_and_retry_provenance_are_immutable(tmp_path: Path) -> None:
    service, arguments, _ = setup(tmp_path)
    manifest = service.issue(**arguments)
    with (
        closing(sqlite3.connect(service.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE task_capability_manifests SET retry_attempt_id=NULL WHERE manifest_id=?",
            (manifest["manifest_id"],),
        )
