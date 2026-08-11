from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.authorization import AuthorizationService
from pentai_core.migrate import migrate
from pentai_core.workflow import AssessmentWorkflowService, WorkflowError
from pentai_policy.document import contract_issues

from scripts.owned_fixture_authority import prepare_owned_fixture_session


def authority(tmp_path: Path) -> tuple[AuthorizationService, AssessmentWorkflowService, str]:
    database = tmp_path / "workflow.db"
    migrate(database)
    authorization, session = prepare_owned_fixture_session(
        database_path=database, source_store_path=tmp_path / "sources"
    )
    with closing(sqlite3.connect(database)) as connection:
        engagement_id = connection.execute(
            "SELECT engagement_id FROM budget_reservations WHERE reservation_id = ?",
            (session["reservation_id"],),
        ).fetchone()[0]
    return authorization, AssessmentWorkflowService(database), engagement_id


def create_ready(
    workflow: AssessmentWorkflowService, engagement_id: str
) -> dict[str, object]:
    created = workflow.create(
        engagement_id,
        idempotency_key="workflow-test-key-0001",
        actor_id="test-human",
    )
    return workflow.transition(
        str(created["workflow_id"]),
        target_status="ready",
        expected_version=1,
        actor_type="human",
        actor_id="test-human",
    )


def test_workflow_and_task_queue_are_durable_idempotent_and_non_executing(
    tmp_path: Path,
) -> None:
    authorization, workflow, engagement_id = authority(tmp_path)

    created = workflow.create(
        engagement_id,
        idempotency_key="workflow-test-key-0001",
        actor_id="test-human",
    )
    replay = workflow.create(
        engagement_id,
        idempotency_key="workflow-test-key-0001",
        actor_id="test-human",
    )
    ready = workflow.transition(
        str(created["workflow_id"]),
        target_status="ready",
        expected_version=1,
        actor_type="human",
        actor_id="test-human",
    )
    task = workflow.enqueue(
        str(created["workflow_id"]),
        task_kind="supervised_action",
        idempotency_key="task-test-key-0000001",
        input_refs=[str(uuid4())],
        parent_task_id=None,
        actor_id="test-human",
    )
    task_replay = workflow.enqueue(
        str(created["workflow_id"]),
        task_kind="supervised_action",
        idempotency_key="task-test-key-0000001",
        input_refs=list(task["input_refs"]),
        parent_task_id=None,
        actor_id="test-human",
    )

    assert replay == created
    assert contract_issues(ready, "assessment-workflow-v1.schema.json") == ()
    assert contract_issues(task, "workflow-task-v1.schema.json") == ()
    assert task_replay == task
    assert task["dispatch_enabled"] is False
    assert task["external_effect_enabled"] is False
    loaded = workflow.get(str(created["workflow_id"]))
    assert loaded == {"workflow": ready, "tasks": [task]}
    assert authorization.verify_audit_chain()["valid"] is True
    with closing(sqlite3.connect(workflow.database_path)) as connection:
        outbox_types = {
            row[0]
            for row in connection.execute(
                "SELECT event_type FROM outbox WHERE event_type LIKE 'workflow.%'"
            )
        }
    assert {"workflow.created", "workflow.transitioned", "workflow.task_queued"} <= outbox_types


def test_workflow_requires_human_start_and_fences_concurrent_transition(
    tmp_path: Path,
) -> None:
    _, workflow, engagement_id = authority(tmp_path)
    ready = create_ready(workflow, engagement_id)
    workflow_id = str(ready["workflow_id"])

    with pytest.raises(WorkflowError) as unsupervised:
        workflow.transition(
            workflow_id,
            target_status="running",
            expected_version=2,
            actor_type="service",
            actor_id="worker",
        )
    assert unsupervised.value.code == "WORKFLOW_SUPERVISION_REQUIRED"

    def start() -> str:
        try:
            return str(
                workflow.transition(
                    workflow_id,
                    target_status="running",
                    expected_version=2,
                    actor_type="human",
                    actor_id="test-human",
                )["status"]
            )
        except WorkflowError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: start(), range(2)))
    assert sorted(outcomes) == ["WORKFLOW_FENCED", "running"]


def test_workflow_recovery_pauses_and_never_resumes_automatically(tmp_path: Path) -> None:
    _, workflow, engagement_id = authority(tmp_path)
    ready = create_ready(workflow, engagement_id)
    running = workflow.transition(
        str(ready["workflow_id"]),
        target_status="running",
        expected_version=2,
        actor_type="human",
        actor_id="test-human",
    )

    assert workflow.recover_startup() == 1
    recovered = workflow.get(str(running["workflow_id"]))["workflow"]

    assert recovered["status"] == "paused"
    assert recovered["version"] == 4
    assert recovered["execution_enabled"] is False
    assert workflow.recover_startup() == 0


def test_stale_or_paused_authority_denies_queue_and_resume(tmp_path: Path) -> None:
    authorization, workflow, engagement_id = authority(tmp_path)
    ready = create_ready(workflow, engagement_id)
    running = workflow.transition(
        str(ready["workflow_id"]),
        target_status="running",
        expected_version=2,
        actor_type="human",
        actor_id="test-human",
    )
    paused = workflow.transition(
        str(running["workflow_id"]),
        target_status="paused",
        expected_version=3,
        actor_type="service",
        actor_id="safety-control",
    )
    authorization.set_global_safety(
        status="paused", reason="synthetic safety pause", actor_id="test-human"
    )

    with pytest.raises(WorkflowError) as enqueue_denied:
        workflow.enqueue(
            str(paused["workflow_id"]),
            task_kind="manual_checkpoint",
            idempotency_key="task-test-key-0000002",
            input_refs=[],
            parent_task_id=None,
            actor_id="test-human",
        )
    assert enqueue_denied.value.code == "WORKFLOW_TASK_DENIED"
    with pytest.raises(WorkflowError) as resume_denied:
        workflow.transition(
            str(paused["workflow_id"]),
            target_status="running",
            expected_version=4,
            actor_type="human",
            actor_id="test-human",
        )
    assert resume_denied.value.code == "WORKFLOW_AUTHORITY_DENIED"


def test_task_parent_and_cancellation_are_fail_closed(tmp_path: Path) -> None:
    _, workflow, engagement_id = authority(tmp_path)
    ready = create_ready(workflow, engagement_id)
    workflow_id = str(ready["workflow_id"])
    parent = workflow.enqueue(
        workflow_id,
        task_kind="manual_checkpoint",
        idempotency_key="task-parent-key-00001",
        input_refs=[],
        parent_task_id=None,
        actor_id="test-human",
    )
    child = workflow.enqueue(
        workflow_id,
        task_kind="report_draft",
        idempotency_key="task-child-key-000001",
        input_refs=[],
        parent_task_id=str(parent["task_id"]),
        actor_id="test-human",
    )

    with pytest.raises(WorkflowError) as parent_denied:
        workflow.cancel_task(str(parent["task_id"]), actor_id="test-human")
    assert parent_denied.value.code == "WORKFLOW_TASK_DENIED"
    child_cancelled = workflow.cancel_task(str(child["task_id"]), actor_id="test-human")
    parent_cancelled = workflow.cancel_task(str(parent["task_id"]), actor_id="test-human")
    assert child_cancelled["state"] == "cancelled"
    assert parent_cancelled["state"] == "cancelled"


def test_completion_requires_resolved_tasks_and_cancellation_closes_queue(
    tmp_path: Path,
) -> None:
    _, workflow, engagement_id = authority(tmp_path)
    ready = create_ready(workflow, engagement_id)
    workflow_id = str(ready["workflow_id"])
    running = workflow.transition(
        workflow_id,
        target_status="running",
        expected_version=2,
        actor_type="human",
        actor_id="test-human",
    )
    task = workflow.enqueue(
        workflow_id,
        task_kind="manual_checkpoint",
        idempotency_key="task-complete-key-0001",
        input_refs=[],
        parent_task_id=None,
        actor_id="test-human",
    )

    with pytest.raises(WorkflowError) as incomplete:
        workflow.transition(
            workflow_id,
            target_status="completed",
            expected_version=int(running["version"]),
            actor_type="human",
            actor_id="test-human",
        )
    assert incomplete.value.code == "WORKFLOW_TRANSITION_DENIED"

    cancelled = workflow.transition(
        workflow_id,
        target_status="cancelled",
        expected_version=int(running["version"]),
        actor_type="human",
        actor_id="test-human",
    )
    assert cancelled["status"] == "cancelled"
    assert workflow.get(workflow_id)["tasks"][0] == {
        **task,
        "state": "cancelled",
        "finalized_at": cancelled["finalized_at"],
    }


def test_invalid_clock_and_inputs_write_nothing(tmp_path: Path) -> None:
    _, workflow, engagement_id = authority(tmp_path)
    before = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(WorkflowError) as clock:
        workflow.create(
            engagement_id,
            idempotency_key="workflow-test-key-0002",
            actor_id="test-human",
            now=before.replace(tzinfo=None),
        )
    assert clock.value.code == "WORKFLOW_CLOCK_INVALID"
    with pytest.raises(WorkflowError) as key:
        workflow.create(engagement_id, idempotency_key="short", actor_id="test-human")
    assert key.value.code == "WORKFLOW_IDEMPOTENCY_INVALID"
    with closing(sqlite3.connect(workflow.database_path)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM assessment_workflows").fetchone()[0] == 0
