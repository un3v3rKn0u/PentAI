from __future__ import annotations

import copy
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.migrate import migrate
from pentai_core.orchestration import DurablePlanGraphService, OrchestrationError
from pentai_policy.document import contract_issues

NOW = datetime(2026, 8, 21, 20, 0, tzinfo=UTC)
ASSESSMENT = "11111111-1111-4111-8111-111111111111"
PLAN = "22222222-2222-4222-8222-222222222222"
FIRST = "33333333-3333-4333-8333-333333333333"
SECOND = "44444444-4444-4444-8444-444444444444"


def graph() -> dict[str, object]:
    tasks = [
        {
            "task_id": FIRST,
            "task_type": "scope",
            "objective": "Review synthetic scope metadata.",
            "input_refs": [],
            "requires_human_approval": False,
            "state": "pending",
            "revision": 1,
            "created_at": NOW.isoformat(),
            "updated_at": NOW.isoformat(),
            "authority": "none",
            "execution_enabled": False,
        },
        {
            "task_id": SECOND,
            "task_type": "reporting",
            "objective": "Prepare synthetic report metadata.",
            "input_refs": ["55555555-5555-4555-8555-555555555555"],
            "requires_human_approval": False,
            "state": "pending",
            "revision": 1,
            "created_at": NOW.isoformat(),
            "updated_at": NOW.isoformat(),
            "authority": "none",
            "execution_enabled": False,
        },
    ]
    return {
        "schema_version": "1.0.0",
        "plan_id": PLAN,
        "assessment_id": ASSESSMENT,
        "idempotency_key": "synthetic-plan-key-0001",
        "revision": 1,
        "state": "active",
        "tasks": tasks,
        "dependencies": [
            {
                "predecessor_task_id": FIRST,
                "successor_task_id": SECOND,
                "dependency_type": "requires_success",
            }
        ],
        "created_at": NOW.isoformat(),
        "updated_at": NOW.isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }


def command(
    task_id: str, plan_revision: int, task_revision: int, target: str, **updates: object
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "plan_id": PLAN,
        "assessment_id": ASSESSMENT,
        "task_id": task_id,
        "expected_plan_revision": plan_revision,
        "expected_task_revision": task_revision,
        "target_state": target,
        "requested_at": NOW.isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    value.update(updates)
    return value


def service(tmp_path: Path) -> DurablePlanGraphService:
    database = tmp_path / "orchestration.db"
    migrate(database)
    return DurablePlanGraphService(database)


def test_graph_is_durable_deterministic_and_non_authoritative(tmp_path: Path) -> None:
    planner = service(tmp_path)
    created = planner.create(graph())
    replay = planner.create(graph())
    restarted = DurablePlanGraphService(planner.database_path).get(PLAN)
    assert created == replay == restarted
    assert contract_issues(created, "orchestration-plan-graph-v1.schema.json") == ()
    assert [task["state"] for task in created["tasks"]] == ["ready", "blocked"]
    assert created["authority"] == "none" and created["execution_enabled"] is False
    assert all(
        task["authority"] == "none" and task["execution_enabled"] is False
        for task in created["tasks"]
    )


def test_task_snapshot_v2_reads_authoritative_state_without_writes(tmp_path: Path) -> None:
    planner = service(tmp_path)
    planner.create(graph())
    with closing(sqlite3.connect(planner.database_path)) as connection:
        before = connection.total_changes
    snapshot = planner.get_task_snapshot_v2(PLAN, FIRST, now=NOW)
    with closing(sqlite3.connect(planner.database_path)) as connection:
        after = connection.total_changes
    assert snapshot == {
        "schema_version": "2.0.0",
        "assessment_id": ASSESSMENT,
        "plan_id": PLAN,
        "plan_revision": 1,
        "plan_state": "active",
        "task_id": FIRST,
        "task_revision": 1,
        "task_type": "scope",
        "task_state": "ready",
        "terminal_lineage": None,
        "observed_at": NOW.isoformat().replace("+00:00", "Z"),
        "authority": "none",
        "execution_enabled": False,
    }
    assert before == after == 0
    assert contract_issues(snapshot, "orchestration-task-snapshot-v2.schema.json") == ()
    assert contract_issues(snapshot, "orchestration-plan-graph-v1.schema.json")


def test_task_snapshot_v2_contract_requires_terminal_lineage_for_dead_letter() -> None:
    snapshot = {
        "schema_version": "2.0.0",
        "assessment_id": ASSESSMENT,
        "plan_id": PLAN,
        "plan_revision": 11,
        "plan_state": "failed",
        "task_id": FIRST,
        "task_revision": 9,
        "task_type": "validation",
        "task_state": "dead_letter",
        "terminal_lineage": {
            "consumption_id": "55555555-5555-4555-8555-555555555555",
            "consumption_digest": "sha256:" + "a" * 64,
            "terminal_decision_id": "66666666-6666-4666-8666-666666666666",
            "terminal_decision_digest": "sha256:" + "b" * 64,
            "outcome": "dead_letter_eligible",
            "reason_code": "retry_ceiling_exhausted",
        },
        "observed_at": NOW.isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    assert contract_issues(snapshot, "orchestration-task-snapshot-v2.schema.json") == ()
    for field in ("terminal_lineage", "authority", "execution_enabled"):
        invalid = copy.deepcopy(snapshot)
        invalid[field] = None if field == "terminal_lineage" else True
        assert contract_issues(invalid, "orchestration-task-snapshot-v2.schema.json")


def test_task_snapshot_v2_denies_malformed_missing_and_unbacked_terminal_state(
    tmp_path: Path,
) -> None:
    planner = service(tmp_path)
    planner.create(graph())
    cases = (
        ("not-a-uuid", FIRST, "ORCHESTRATION_SNAPSHOT_MALFORMED"),
        (PLAN, "not-a-uuid", "ORCHESTRATION_SNAPSHOT_MALFORMED"),
        (PLAN, str(uuid4()), "ORCHESTRATION_SNAPSHOT_NOT_FOUND"),
        (str(uuid4()), FIRST, "ORCHESTRATION_SNAPSHOT_NOT_FOUND"),
    )
    for plan_id, task_id, code in cases:
        with pytest.raises(OrchestrationError) as raised:
            planner.get_task_snapshot_v2(plan_id, task_id, now=NOW)
        assert raised.value.code == code

    with closing(sqlite3.connect(planner.database_path)) as connection, connection:
        connection.execute("DROP TRIGGER orchestration_tasks_version_fenced")
        connection.execute(
            "UPDATE orchestration_tasks SET state='dead_letter',revision=2 WHERE task_id=?",
            (FIRST,),
        )
    with pytest.raises(OrchestrationError) as missing:
        planner.get_task_snapshot_v2(PLAN, FIRST, now=NOW)
    assert missing.value.code == "ORCHESTRATION_SNAPSHOT_TERMINAL_LINEAGE_MISSING"


def test_task_snapshot_v2_denies_tampered_mixed_version_terminal_lineage(
    tmp_path: Path,
) -> None:
    planner = service(tmp_path)
    planner.create(graph())
    with closing(sqlite3.connect(planner.database_path)) as connection, connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("DROP TRIGGER orchestration_tasks_version_fenced")
        connection.execute("DROP TRIGGER orchestration_terminal_consumptions_producer_disabled")
        connection.execute("DROP TRIGGER orchestration_terminal_consumptions_binding_valid")
        connection.execute(
            "UPDATE orchestration_tasks SET state='dead_letter',revision=2 WHERE task_id=?",
            (FIRST,),
        )
        connection.execute(
            """INSERT INTO orchestration_terminal_consumptions(
            consumption_id,command_id,command_digest,assessment_id,plan_id,plan_revision,
            task_id,expected_task_revision,resulting_task_revision,terminal_decision_id,
            terminal_decision_digest,receipt_json,receipt_hash,consumed_at,authority,
            execution_enabled) VALUES(
            '55555555-5555-4555-8555-555555555555',
            '66666666-6666-4666-8666-666666666666',?,?,?,1,?,1,2,
            '77777777-7777-4777-8777-777777777777',?,?,?,?,'none',0)""",
            (
                "sha256:" + "a" * 64,
                ASSESSMENT,
                PLAN,
                FIRST,
                "sha256:" + "b" * 64,
                '{"schema_version":"9.0.0"}',
                "c" * 64,
                NOW.isoformat(),
            ),
        )
    with pytest.raises(OrchestrationError) as invalid:
        planner.get_task_snapshot_v2(PLAN, FIRST, now=NOW)
    assert invalid.value.code == "ORCHESTRATION_SNAPSHOT_TERMINAL_LINEAGE_INVALID"


def test_task_snapshot_v2_leaves_v1_creation_and_read_contract_unchanged(tmp_path: Path) -> None:
    planner = service(tmp_path)
    created = planner.create(graph())
    loaded = planner.get(PLAN)
    assert created == loaded
    assert created["schema_version"] == "1.0.0"
    assert contract_issues(created, "orchestration-plan-graph-v1.schema.json") == ()


def test_graph_rejects_malformed_duplicate_missing_cycle_and_conflict(tmp_path: Path) -> None:
    planner = service(tmp_path)
    malformed = graph()
    malformed["authority"] = "grant"
    duplicate = graph()
    duplicate["tasks"] = [
        copy.deepcopy(duplicate["tasks"][0]),
        copy.deepcopy(duplicate["tasks"][0]),
    ]  # type: ignore[index]
    missing = graph()
    missing["dependencies"][0]["successor_task_id"] = str(uuid4())  # type: ignore[index]
    cycle = graph()
    cycle["dependencies"].append(
        {
            "predecessor_task_id": SECOND,
            "successor_task_id": FIRST,
            "dependency_type": "requires_success",
        }
    )  # type: ignore[union-attr]
    cases = (
        (malformed, "ORCHESTRATION_PLAN_MALFORMED"),
        (duplicate, "ORCHESTRATION_TASK_ID_AMBIGUOUS"),
        (missing, "ORCHESTRATION_DEPENDENCY_MISSING"),
        (cycle, "ORCHESTRATION_DEPENDENCY_CYCLE"),
    )
    for document, code in cases:
        with pytest.raises(OrchestrationError) as raised:
            planner.create(document)
        assert raised.value.code == code
    planner.create(graph())
    conflict = graph()
    conflict["tasks"][0]["objective"] = "Conflicting synthetic objective."  # type: ignore[index]
    with pytest.raises(OrchestrationError) as raised:
        planner.create(conflict)
    assert raised.value.code == "ORCHESTRATION_PLAN_IDENTITY_CONFLICT"


def test_general_running_transition_is_closed_and_cancellation_remains(tmp_path: Path) -> None:
    planner = service(tmp_path)
    planner.create(graph())
    with pytest.raises(OrchestrationError) as denied:
        planner.transition(command(FIRST, 1, 1, "running"), now=NOW)
    assert denied.value.code == "ORCHESTRATION_TRANSITION_DENIED"
    cancelled = planner.transition(command(FIRST, 1, 1, "cancelled"), now=NOW)
    assert cancelled["tasks"][0]["state"] == "cancelled"


def test_transition_denials_replay_conflict_stale_scope_and_concurrency(tmp_path: Path) -> None:
    planner = service(tmp_path)
    planner.create(graph())
    malformed = command(FIRST, 1, 1, "running", authority="grant")
    with pytest.raises(OrchestrationError) as invalid:
        planner.transition(malformed, now=NOW)
    assert invalid.value.code == "ORCHESTRATION_COMMAND_MALFORMED"
    with pytest.raises(OrchestrationError) as plan_fenced:
        planner.transition(command(FIRST, 2, 1, "running"), now=NOW)
    assert plan_fenced.value.code == "ORCHESTRATION_PLAN_FENCED"
    with pytest.raises(OrchestrationError) as task_fenced:
        planner.transition(command(FIRST, 1, 2, "running"), now=NOW)
    assert task_fenced.value.code == "ORCHESTRATION_TASK_FENCED"
    blocked = command(SECOND, 1, 1, "running")
    with pytest.raises(OrchestrationError) as denied:
        planner.transition(blocked, now=NOW)
    assert denied.value.code == "ORCHESTRATION_TRANSITION_DENIED"
    wrong_scope = command(FIRST, 1, 1, "running", assessment_id=str(uuid4()))
    with pytest.raises(OrchestrationError) as scoped:
        planner.transition(wrong_scope, now=NOW)
    assert scoped.value.code == "ORCHESTRATION_ASSESSMENT_MISMATCH"
    stale = command(FIRST, 1, 1, "running", requested_at=(NOW - timedelta(minutes=6)).isoformat())
    with pytest.raises(OrchestrationError) as aged:
        planner.transition(stale, now=NOW)
    assert aged.value.code == "ORCHESTRATION_COMMAND_STALE"
    accepted = command(FIRST, 1, 1, "cancelled")
    result = planner.transition(accepted, now=NOW)
    assert planner.transition(accepted, now=NOW) == result
    assert planner.create(graph()) == result
    changed = copy.deepcopy(accepted)
    changed["target_state"] = "running"
    with pytest.raises(OrchestrationError) as conflict:
        planner.transition(changed, now=NOW)
    assert conflict.value.code == "ORCHESTRATION_COMMAND_IDENTITY_CONFLICT"

    other = service(tmp_path / "concurrent")
    other.create(graph())
    contender = command(FIRST, 1, 1, "cancelled")
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: other.transition(contender, now=NOW), range(2)))
    assert outcomes[0] == outcomes[1]


def test_cancellation_never_unlocks_dependent_work(tmp_path: Path) -> None:
    planner = service(tmp_path)
    planner.create(graph())
    cancelled = planner.transition(command(FIRST, 1, 1, "cancelled"), now=NOW)
    assert cancelled["tasks"][0]["state"] == "cancelled"
    assert cancelled["tasks"][1]["state"] == "blocked"

    assert planner.recover(now=NOW + timedelta(seconds=2)) == []


def test_database_guards_identity_authority_and_history(tmp_path: Path) -> None:
    planner = service(tmp_path)
    planner.create(graph())
    with (
        closing(sqlite3.connect(planner.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE orchestration_plans SET execution_enabled = 1 WHERE plan_id = ?", (PLAN,)
        )
    with (
        closing(sqlite3.connect(planner.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute("DELETE FROM orchestration_tasks WHERE task_id = ?", (FIRST,))
    with (
        closing(sqlite3.connect(planner.database_path)) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute(
            "UPDATE orchestration_tasks SET state = 'succeeded', revision = 2 WHERE task_id = ?",
            (FIRST,),
        )
