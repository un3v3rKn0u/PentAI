from __future__ import annotations

import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pentai_core.orchestration_dead_letter import (
    OrchestrationDeadLetterError,
    OrchestrationDeadLetterRegistrationService,
)
from pentai_policy import content_hash
from pentai_policy.document import contract_issues
from test_orchestration_budget import NOW
from test_orchestration_terminal import terminal_consumption_setup


def setup(
    tmp_path: Path,
) -> tuple[OrchestrationDeadLetterRegistrationService, dict[str, Any]]:
    terminal, terminal_command = terminal_consumption_setup(tmp_path)
    consumption = terminal.consume(terminal_command, now=NOW + timedelta(seconds=50))
    command = {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "assessment_id": consumption["assessment_id"],
        "plan_id": consumption["plan_id"],
        "expected_plan_revision": consumption["plan_revision"],
        "task_id": consumption["task_id"],
        "expected_task_revision": consumption["resulting_task_revision"],
        "terminal_consumption_id": consumption["consumption_id"],
        "terminal_consumption_digest": "sha256:" + content_hash(consumption),
        "purpose": "register_attempt_three_dead_letter",
        "requested_at": (NOW + timedelta(seconds=51)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "authority": "none",
        "execution_enabled": False,
    }
    return OrchestrationDeadLetterRegistrationService(terminal.authorization), command


def test_registers_inert_immutable_dead_letter_metadata(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection:
        before = connection.execute(
            "SELECT p.state,p.revision,t.state,t.revision FROM orchestration_plans p "
            "JOIN orchestration_tasks t ON t.plan_id=p.plan_id WHERE t.task_id=?",
            (command["task_id"],),
        ).fetchone()
    receipt = service.register(command, now=NOW + timedelta(seconds=51))
    assert contract_issues(
        receipt, "orchestration-dead-letter-registration-receipt-v1.schema.json"
    ) == ()
    assert receipt["task_state"] == "dead_letter"
    assert receipt["attempt_number"] == receipt["maximum_attempts"] == 3
    assert receipt["registration_state"] == "registered"
    assert receipt["retention_mode"] == "immutable_history"
    assert all(
        receipt[key] is False
        for key in (
            "delivery_enabled",
            "claim_enabled",
            "acknowledgement_enabled",
            "retry_enabled",
            "deletion_enabled",
            "cleanup_enabled",
            "operator_review_enabled",
            "execution_enabled",
        )
    )
    assert receipt["authority"] == "none"
    assert service.register(command, now=NOW + timedelta(seconds=51)) == receipt
    with closing(sqlite3.connect(service.database_path)) as connection:
        after = connection.execute(
            "SELECT p.state,p.revision,t.state,t.revision FROM orchestration_plans p "
            "JOIN orchestration_tasks t ON t.plan_id=p.plan_id WHERE t.task_id=?",
            (command["task_id"],),
        ).fetchone()
        assert after == before
        assert connection.execute(
            "SELECT COUNT(*) FROM orchestration_dead_letter_registrations"
        ).fetchone()[0] == 1
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM outbox WHERE event_type="
                "'orchestration.dead_letter_registered'"
            ).fetchone()[0]
        )
        assert payload["delivery_enabled"] is False
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE orchestration_dead_letter_registrations SET authority='grant'"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM orchestration_dead_letter_registrations")


def test_registration_rejects_malformed_changed_replay_and_concurrency(
    tmp_path: Path,
) -> None:
    cases = (
        {"schema_version": "2.0.0"},
        {"authority": "grant"},
        {"terminal_consumption_digest": "sha256:" + "0" * 64},
        {"task_id": str(uuid4())},
        {"delivery_enabled": True},
        {"queue": "synthetic"},
    )
    for index, changes in enumerate(cases):
        service, command = setup(tmp_path / f"malformed-{index}")
        command.update(changes)
        with pytest.raises(OrchestrationDeadLetterError):
            service.register(command, now=NOW + timedelta(seconds=51))

    service, command = setup(tmp_path / "replay")
    service.register(command, now=NOW + timedelta(seconds=51))
    changed = copy.deepcopy(command)
    changed["terminal_consumption_digest"] = "sha256:" + "0" * 64
    with pytest.raises(OrchestrationDeadLetterError) as conflict:
        service.register(changed, now=NOW + timedelta(seconds=51))
    assert (
        conflict.value.code
        == "ORCHESTRATION_DEAD_LETTER_REGISTRATION_IDENTITY_CONFLICT"
    )

    concurrent, candidate = setup(tmp_path / "concurrent")
    contenders = (copy.deepcopy(candidate), copy.deepcopy(candidate))
    contenders[1]["command_id"] = str(uuid4())

    def register(value: dict[str, Any]) -> str:
        try:
            return concurrent.register(value, now=NOW + timedelta(seconds=51))[
                "registration_id"
            ]
        except OrchestrationDeadLetterError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, contenders))
    assert sum(
        value.startswith("ORCHESTRATION_DEAD_LETTER_REGISTRATION_")
        for value in outcomes
    ) == 1


def test_registration_revalidates_security_and_denies_storage_bypass(tmp_path: Path) -> None:
    for name, sql in (
        ("safety", "UPDATE safety_state SET global_status='paused',generation=generation+1"),
        ("cancel", "UPDATE engagements SET status='revoked'"),
        (
            "worker",
            "UPDATE worker_runtime_instances SET status='termination_requested',version=version+1",
        ),
        ("account", "UPDATE orchestration_budget_accounts SET version=version+1"),
        (
            "recovery",
            "UPDATE orchestration_task_lease_fences SET "
            "recovery_generation=recovery_generation+1,version=version+1",
        ),
    ):
        service, command = setup(tmp_path / name)
        with closing(sqlite3.connect(service.database_path)) as connection, connection:
            connection.execute(sql)
        with pytest.raises(OrchestrationDeadLetterError) as denied:
            service.register(command, now=NOW + timedelta(seconds=51))
        assert (
            denied.value.code
            == "ORCHESTRATION_DEAD_LETTER_REGISTRATION_SECURITY_DENIED"
        )

    service, command = setup(tmp_path / "storage")
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO orchestration_dead_letter_registrations(
                registration_id,command_id,command_digest,assessment_id,plan_id,
                plan_revision,task_id,task_revision,terminal_consumption_id,
                terminal_consumption_digest,terminal_decision_id,
                terminal_decision_digest,receipt_json,receipt_hash,registered_at,
                authority,execution_enabled)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'none',0)""",
                (
                    str(uuid4()),
                    str(uuid4()),
                    "sha256:" + "1" * 64,
                    command["assessment_id"],
                    command["plan_id"],
                    command["expected_plan_revision"],
                    command["task_id"],
                    command["expected_task_revision"],
                    command["terminal_consumption_id"],
                    command["terminal_consumption_digest"],
                    str(uuid4()),
                    "sha256:" + "2" * 64,
                    '{"schema_version":"9.0.0"}',
                    "3" * 64,
                    (NOW + timedelta(seconds=51)).isoformat(),
                ),
            )


def test_registration_rejects_tampered_terminal_consumption(tmp_path: Path) -> None:
    service, command = setup(tmp_path)
    with closing(sqlite3.connect(service.database_path)) as connection, connection:
        connection.execute("DROP TRIGGER orchestration_terminal_consumptions_immutable")
        connection.execute(
            "UPDATE orchestration_terminal_consumptions SET receipt_json=?",
            ('{"schema_version":"9.0.0"}',),
        )
    with pytest.raises(OrchestrationDeadLetterError) as denied:
        service.register(command, now=NOW + timedelta(seconds=51))
    assert denied.value.code == "ORCHESTRATION_DEAD_LETTER_REGISTRATION_LINEAGE_INVALID"
