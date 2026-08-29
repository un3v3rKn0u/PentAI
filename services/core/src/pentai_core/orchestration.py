from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.database import transaction

MAX_COMMAND_AGE = timedelta(minutes=5)
_TRANSITIONS = {
    "ready": {"cancelled"},
    "awaiting_human": {"cancelled"},
    "running": {"cancelling", "succeeded"},
    "cancelling": {"cancelled", "failed"},
    "blocked": {"cancelled"},
}
_TERMINAL = {"cancelled", "succeeded", "failed"}


class OrchestrationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class DurablePlanGraphService:
    """Persist non-authoritative plan coordination without dispatch or execution."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def create(self, graph: dict[str, Any]) -> dict[str, Any]:
        candidate = copy.deepcopy(graph)
        if contract_issues(candidate, "orchestration-plan-graph-v1.schema.json"):
            raise OrchestrationError("ORCHESTRATION_PLAN_MALFORMED", "plan graph is malformed")
        if candidate["revision"] != 1 or candidate["state"] != "active":
            raise OrchestrationError(
                "ORCHESTRATION_PLAN_INITIAL_STATE_INVALID", "initial state is invalid"
            )
        if any(task["state"] != "pending" or task["revision"] != 1 for task in candidate["tasks"]):
            raise OrchestrationError(
                "ORCHESTRATION_TASK_INITIAL_STATE_INVALID", "task initial state is invalid"
            )
        if candidate["created_at"] != candidate["updated_at"]:
            raise OrchestrationError("ORCHESTRATION_PLAN_TIME_INVALID", "plan timestamps conflict")
        task_ids = [task["task_id"] for task in candidate["tasks"]]
        if len(task_ids) != len(set(task_ids)):
            raise OrchestrationError(
                "ORCHESTRATION_TASK_ID_AMBIGUOUS", "task identity is duplicated"
            )
        edges = self._validate_edges(candidate["dependencies"], set(task_ids))
        self._reject_cycles(set(task_ids), edges)
        states = self._initial_states(candidate["tasks"], edges)
        creation_digest = _digest(candidate)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT plan_id FROM orchestration_plans
                WHERE assessment_id = ? AND idempotency_key = ?""",
                (candidate["assessment_id"], candidate["idempotency_key"]),
            ).fetchone()
            if existing is not None:
                stored = connection.execute(
                    "SELECT creation_digest FROM orchestration_plans WHERE plan_id = ?",
                    (existing["plan_id"],),
                ).fetchone()
                assert stored is not None
                if stored["creation_digest"] != creation_digest:
                    raise OrchestrationError(
                        "ORCHESTRATION_PLAN_IDENTITY_CONFLICT", "idempotency key is already bound"
                    )
                return self._load(connection, str(existing["plan_id"]))
            try:
                connection.execute(
                    """INSERT INTO orchestration_plans
                    VALUES (?, ?, ?, ?, 1, 'active', ?, ?, 'none', 0)""",
                    (
                        candidate["plan_id"],
                        candidate["assessment_id"],
                        candidate["idempotency_key"],
                        creation_digest,
                        candidate["created_at"],
                        candidate["updated_at"],
                    ),
                )
                for task in candidate["tasks"]:
                    connection.execute(
                        """INSERT INTO orchestration_tasks VALUES
                        (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'none', 0)""",
                        (
                            task["task_id"],
                            candidate["plan_id"],
                            candidate["assessment_id"],
                            task["task_type"],
                            task["objective"],
                            canonical_json(task["input_refs"]),
                            int(task["requires_human_approval"]),
                            states[task["task_id"]],
                            task["created_at"],
                            task["updated_at"],
                        ),
                    )
                for predecessor, successor, dependency_type in sorted(edges):
                    connection.execute(
                        "INSERT INTO orchestration_dependencies VALUES (?, ?, ?, ?, ?)",
                        (
                            candidate["plan_id"],
                            candidate["assessment_id"],
                            predecessor,
                            successor,
                            dependency_type,
                        ),
                    )
            except sqlite3.IntegrityError as error:
                raise OrchestrationError(
                    "ORCHESTRATION_PLAN_IDENTITY_CONFLICT", "plan identity conflicts"
                ) from error
            return self._load(connection, candidate["plan_id"])

    def transition(self, command: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        request = copy.deepcopy(command)
        if contract_issues(request, "orchestration-task-transition-v1.schema.json"):
            raise OrchestrationError(
                "ORCHESTRATION_COMMAND_MALFORMED", "transition command is malformed"
            )
        instant = _instant(now)
        requested_at = parse_time(request["requested_at"])
        if requested_at > instant or instant - requested_at > MAX_COMMAND_AGE:
            raise OrchestrationError("ORCHESTRATION_COMMAND_STALE", "transition command is stale")
        digest = _digest(request)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT request_digest, result_json FROM orchestration_commands
                WHERE command_id = ?""",
                (request["command_id"],),
            ).fetchone()
            if replay is not None:
                if replay["request_digest"] != digest:
                    raise OrchestrationError(
                        "ORCHESTRATION_COMMAND_IDENTITY_CONFLICT", "command identity was reused"
                    )
                return cast(dict[str, Any], json.loads(str(replay["result_json"])))
            plan = connection.execute(
                "SELECT * FROM orchestration_plans WHERE plan_id = ?", (request["plan_id"],)
            ).fetchone()
            if plan is None:
                raise OrchestrationError("ORCHESTRATION_PLAN_NOT_FOUND", "plan does not exist")
            if plan["assessment_id"] != request["assessment_id"]:
                raise OrchestrationError(
                    "ORCHESTRATION_ASSESSMENT_MISMATCH", "assessment does not match"
                )
            if plan["state"] != "active":
                raise OrchestrationError("ORCHESTRATION_PLAN_TERMINAL", "plan is terminal")
            if plan["revision"] != request["expected_plan_revision"]:
                raise OrchestrationError("ORCHESTRATION_PLAN_FENCED", "plan revision is stale")
            task = connection.execute(
                "SELECT * FROM orchestration_tasks WHERE task_id = ? AND plan_id = ?",
                (request["task_id"], request["plan_id"]),
            ).fetchone()
            if task is None:
                raise OrchestrationError(
                    "ORCHESTRATION_TASK_NOT_FOUND", "task does not exist in plan"
                )
            if task["revision"] != request["expected_task_revision"]:
                raise OrchestrationError("ORCHESTRATION_TASK_FENCED", "task revision is stale")
            target = request["target_state"]
            if target not in _TRANSITIONS.get(str(task["state"]), set()):
                raise OrchestrationError(
                    "ORCHESTRATION_TRANSITION_DENIED", "task transition is invalid"
                )
            timestamp = _timestamp(instant)
            connection.execute(
                """UPDATE orchestration_tasks
                SET state = ?, revision = revision + 1, updated_at = ?
                WHERE task_id = ? AND revision = ?""",
                (target, timestamp, request["task_id"], request["expected_task_revision"]),
            )
            self._refresh_dependents(connection, request["plan_id"], timestamp)
            plan_state = self._plan_state(connection, request["plan_id"])
            connection.execute(
                """UPDATE orchestration_plans
                SET state = ?, revision = revision + 1, updated_at = ?
                WHERE plan_id = ? AND revision = ?""",
                (plan_state, timestamp, request["plan_id"], request["expected_plan_revision"]),
            )
            result = self._load(connection, request["plan_id"])
            connection.execute(
                "INSERT INTO orchestration_commands VALUES (?, ?, ?, ?, ?)",
                (
                    request["command_id"],
                    request["plan_id"],
                    digest,
                    canonical_json(result),
                    timestamp,
                ),
            )
            return result

    def recover(self, *, now: datetime | None = None) -> list[str]:
        """Fail interrupted tasks on startup; never resume or restore authority."""
        timestamp = _timestamp(_instant(now))
        recovered: list[str] = []
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            plans = connection.execute(
                """SELECT DISTINCT p.plan_id FROM orchestration_plans p
                JOIN orchestration_tasks t ON t.plan_id = p.plan_id
                WHERE p.state = 'active' AND t.state IN ('running', 'cancelling')
                ORDER BY p.plan_id"""
            ).fetchall()
            for row in plans:
                plan_id = str(row["plan_id"])
                interrupted = connection.execute(
                    """SELECT t.task_id, t.revision, COALESCE(f.recovery_generation, 1)
                    AS recovery_generation FROM orchestration_tasks t
                    LEFT JOIN orchestration_task_lease_fences f ON f.task_id = t.task_id
                    WHERE t.plan_id = ? AND t.state = 'running' ORDER BY t.task_id""",
                    (plan_id,),
                ).fetchall()
                for task in interrupted:
                    connection.execute(
                        """INSERT INTO orchestration_task_recovery_failures VALUES
                        (?, ?, ?, ?, ?, ?, ?, 'none', 0)""",
                        (
                            str(uuid4()),
                            plan_id,
                            task["task_id"],
                            task["revision"],
                            int(task["revision"]) + 1,
                            task["recovery_generation"],
                            timestamp,
                        ),
                    )
                    connection.execute(
                        """UPDATE orchestration_tasks
                        SET state = 'failed', revision = revision + 1, updated_at = ?
                        WHERE plan_id = ? AND task_id = ? AND state = 'running'
                          AND revision = ?""",
                        (timestamp, plan_id, task["task_id"], task["revision"]),
                    )
                connection.execute(
                    """UPDATE orchestration_tasks
                    SET state = 'failed', revision = revision + 1, updated_at = ?
                    WHERE plan_id = ? AND state = 'cancelling'""",
                    (timestamp, plan_id),
                )
                self._refresh_dependents(connection, plan_id, timestamp)
                state = self._plan_state(connection, plan_id)
                connection.execute(
                    """UPDATE orchestration_plans
                    SET state = ?, revision = revision + 1, updated_at = ?
                    WHERE plan_id = ?""",
                    (state, timestamp, plan_id),
                )
                recovered.append(plan_id)
        return recovered

    def get(self, plan_id: str) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT plan_id FROM orchestration_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                raise OrchestrationError("ORCHESTRATION_PLAN_NOT_FOUND", "plan does not exist")
            return self._load(connection, plan_id)

    def get_task_snapshot_v2(
        self, plan_id: str, task_id: str, *, now: datetime | None = None
    ) -> dict[str, Any]:
        """Read one version-exact, non-authoritative task snapshot without mutation."""
        if not _uuid(plan_id) or not _uuid(task_id):
            raise OrchestrationError(
                "ORCHESTRATION_SNAPSHOT_MALFORMED", "snapshot identity is malformed"
            )
        observed_at = _timestamp(_instant(now))
        with transaction(self.database_path) as connection:
            row = connection.execute(
                """SELECT p.assessment_id,p.revision AS plan_revision,p.state AS plan_state,
                t.task_id,t.revision AS task_revision,t.task_type,t.state AS task_state
                FROM orchestration_plans p JOIN orchestration_tasks t ON t.plan_id=p.plan_id
                WHERE p.plan_id=? AND t.task_id=?""",
                (plan_id, task_id),
            ).fetchone()
            if row is None:
                raise OrchestrationError(
                    "ORCHESTRATION_SNAPSHOT_NOT_FOUND", "snapshot task does not exist"
                )
            terminal_lineage: dict[str, Any] | None = None
            if row["task_state"] == "dead_letter":
                terminal_lineage = self._load_terminal_lineage(connection, row, plan_id)
            snapshot = {
                "schema_version": "2.0.0",
                "assessment_id": row["assessment_id"],
                "plan_id": plan_id,
                "plan_revision": row["plan_revision"],
                "plan_state": row["plan_state"],
                "task_id": row["task_id"],
                "task_revision": row["task_revision"],
                "task_type": row["task_type"],
                "task_state": row["task_state"],
                "terminal_lineage": terminal_lineage,
                "observed_at": observed_at,
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(snapshot, "orchestration-task-snapshot-v2.schema.json"):
                raise OrchestrationError(
                    "ORCHESTRATION_SNAPSHOT_STORED_STATE_INVALID",
                    "stored snapshot state is invalid",
                )
            return snapshot

    @staticmethod
    def _load_terminal_lineage(
        connection: sqlite3.Connection, task: sqlite3.Row, plan_id: str
    ) -> dict[str, Any]:
        rows = connection.execute(
            "SELECT * FROM orchestration_terminal_consumptions WHERE plan_id=? AND task_id=?",
            (plan_id, task["task_id"]),
        ).fetchall()
        if len(rows) != 1:
            raise OrchestrationError(
                "ORCHESTRATION_SNAPSHOT_TERMINAL_LINEAGE_MISSING",
                "dead-letter terminal lineage is missing or ambiguous",
            )
        stored = rows[0]
        decision_row = connection.execute(
            "SELECT * FROM orchestration_terminal_dispositions WHERE decision_id=?",
            (stored["terminal_decision_id"],),
        ).fetchone()
        try:
            receipt = cast(dict[str, Any], json.loads(str(stored["receipt_json"])))
            decision = (
                cast(dict[str, Any], json.loads(str(decision_row["decision_json"])))
                if decision_row is not None
                else None
            )
        except (TypeError, ValueError) as error:
            raise OrchestrationError(
                "ORCHESTRATION_SNAPSHOT_TERMINAL_LINEAGE_INVALID",
                "dead-letter terminal lineage is invalid",
            ) from error
        if (
            contract_issues(receipt, "orchestration-terminal-consumption-receipt-v1.schema.json")
            or decision_row is None
            or decision is None
            or contract_issues(
                decision, "orchestration-terminal-disposition-decision-v1.schema.json"
            )
            or stored["receipt_hash"] != content_hash(receipt)
            or receipt["receipt_digest"]
            != "sha256:"
            + content_hash(
                {key: value for key, value in receipt.items() if key != "receipt_digest"}
            )
            or stored["assessment_id"] != task["assessment_id"]
            or stored["plan_revision"] != task["plan_revision"]
            or stored["resulting_task_revision"] != task["task_revision"]
            or receipt["consumption_id"] != stored["consumption_id"]
            or receipt["terminal_decision_id"] != stored["terminal_decision_id"]
            or receipt["terminal_decision_digest"] != stored["terminal_decision_digest"]
            or decision_row["decision_hash"] != content_hash(decision)
            or stored["terminal_decision_digest"] != "sha256:" + decision_row["decision_hash"]
            or decision["decision_digest"]
            != "sha256:"
            + content_hash(
                {key: value for key, value in decision.items() if key != "decision_digest"}
            )
            or decision["decision_id"] != stored["terminal_decision_id"]
            or decision["assessment_id"] != task["assessment_id"]
            or decision["plan_id"] != plan_id
            or decision["plan_revision"] != task["plan_revision"]
            or decision["task_id"] != task["task_id"]
            or decision["task_revision"] != stored["expected_task_revision"]
            or decision["outcome"] != receipt["outcome"]
            or decision["reason_code"] != receipt["reason_code"]
        ):
            raise OrchestrationError(
                "ORCHESTRATION_SNAPSHOT_TERMINAL_LINEAGE_INVALID",
                "dead-letter terminal lineage is invalid",
            )
        return {
            "consumption_id": receipt["consumption_id"],
            "consumption_digest": receipt["receipt_digest"],
            "terminal_decision_id": receipt["terminal_decision_id"],
            "terminal_decision_digest": receipt["terminal_decision_digest"],
            "outcome": receipt["outcome"],
            "reason_code": receipt["reason_code"],
        }

    @staticmethod
    def _validate_edges(
        dependencies: list[dict[str, str]], task_ids: set[str]
    ) -> set[tuple[str, str, str]]:
        edges = {
            (edge["predecessor_task_id"], edge["successor_task_id"], edge["dependency_type"])
            for edge in dependencies
        }
        if len(edges) != len(dependencies):
            raise OrchestrationError(
                "ORCHESTRATION_DEPENDENCY_AMBIGUOUS", "dependency is duplicated"
            )
        if any(
            predecessor not in task_ids or successor not in task_ids
            for predecessor, successor, _ in edges
        ):
            raise OrchestrationError(
                "ORCHESTRATION_DEPENDENCY_MISSING", "dependency task is missing"
            )
        return edges

    @staticmethod
    def _reject_cycles(task_ids: set[str], edges: set[tuple[str, str, str]]) -> None:
        incoming = {task_id: 0 for task_id in task_ids}
        outgoing: dict[str, list[str]] = {task_id: [] for task_id in task_ids}
        for predecessor, successor, _ in edges:
            incoming[successor] += 1
            outgoing[predecessor].append(successor)
        ready = sorted(task for task, count in incoming.items() if count == 0)
        visited = 0
        while ready:
            current = ready.pop(0)
            visited += 1
            for successor in sorted(outgoing[current]):
                incoming[successor] -= 1
                if incoming[successor] == 0:
                    ready.append(successor)
                    ready.sort()
        if visited != len(task_ids):
            raise OrchestrationError(
                "ORCHESTRATION_DEPENDENCY_CYCLE", "plan graph contains a cycle"
            )

    @staticmethod
    def _initial_states(
        tasks: list[dict[str, Any]], edges: set[tuple[str, str, str]]
    ) -> dict[str, str]:
        successors = {successor for _, successor, _ in edges}
        return {
            task["task_id"]: (
                "blocked"
                if task["task_id"] in successors
                else "awaiting_human"
                if task["requires_human_approval"]
                else "ready"
            )
            for task in tasks
        }

    @staticmethod
    def _refresh_dependents(connection: sqlite3.Connection, plan_id: str, timestamp: str) -> None:
        rows = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE plan_id = ? ORDER BY task_id", (plan_id,)
        ).fetchall()
        for task in rows:
            if task["state"] not in {"blocked", "ready", "awaiting_human"}:
                continue
            predecessors = connection.execute(
                """SELECT t.state FROM orchestration_dependencies d
                JOIN orchestration_tasks t ON t.task_id = d.predecessor_task_id
                WHERE d.plan_id = ? AND d.successor_task_id = ?""",
                (plan_id, task["task_id"]),
            ).fetchall()
            desired = (
                "blocked"
                if any(row["state"] != "succeeded" for row in predecessors)
                else "awaiting_human"
                if task["requires_human_approval"]
                else "ready"
            )
            if desired != task["state"]:
                connection.execute(
                    """UPDATE orchestration_tasks
                    SET state = ?, revision = revision + 1, updated_at = ?
                    WHERE task_id = ?""",
                    (desired, timestamp, task["task_id"]),
                )

    @staticmethod
    def _plan_state(connection: sqlite3.Connection, plan_id: str) -> str:
        states = [
            str(row[0])
            for row in connection.execute(
                "SELECT state FROM orchestration_tasks WHERE plan_id = ?", (plan_id,)
            )
        ]
        if all(state == "succeeded" for state in states):
            return "completed"
        if all(state in _TERMINAL for state in states):
            return "failed" if "failed" in states else "cancelled"
        return "active"

    @staticmethod
    def _load(connection: sqlite3.Connection, plan_id: str) -> dict[str, Any]:
        plan = connection.execute(
            "SELECT * FROM orchestration_plans WHERE plan_id = ?", (plan_id,)
        ).fetchone()
        assert plan is not None
        tasks = connection.execute(
            "SELECT * FROM orchestration_tasks WHERE plan_id = ? ORDER BY task_id", (plan_id,)
        ).fetchall()
        dependencies = connection.execute(
            """SELECT * FROM orchestration_dependencies WHERE plan_id = ?
            ORDER BY predecessor_task_id, successor_task_id""",
            (plan_id,),
        ).fetchall()
        document = {
            "schema_version": "1.0.0",
            "plan_id": plan["plan_id"],
            "assessment_id": plan["assessment_id"],
            "idempotency_key": plan["idempotency_key"],
            "revision": plan["revision"],
            "state": plan["state"],
            "tasks": [
                {
                    "task_id": row["task_id"],
                    "task_type": row["task_type"],
                    "objective": row["objective"],
                    "input_refs": json.loads(row["input_refs_json"]),
                    "requires_human_approval": bool(row["requires_human_approval"]),
                    "state": row["state"],
                    "revision": row["revision"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                    "authority": "none",
                    "execution_enabled": False,
                }
                for row in tasks
            ],
            "dependencies": [
                {
                    "predecessor_task_id": row["predecessor_task_id"],
                    "successor_task_id": row["successor_task_id"],
                    "dependency_type": row["dependency_type"],
                }
                for row in dependencies
            ],
            "created_at": plan["created_at"],
            "updated_at": plan["updated_at"],
            "authority": "none",
            "execution_enabled": False,
        }
        if contract_issues(document, "orchestration-plan-graph-v1.schema.json"):
            raise OrchestrationError(
                "ORCHESTRATION_STORED_STATE_INVALID", "stored plan state is invalid"
            )
        return document


def _digest(document: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(document).encode()).hexdigest()


def _uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _instant(value: datetime | None) -> datetime:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise OrchestrationError("ORCHESTRATION_CLOCK_INVALID", "clock is invalid")
    return instant.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
