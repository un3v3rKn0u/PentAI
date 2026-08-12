from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues, parse_time

from pentai_core.audit import append_audit_event
from pentai_core.database import transaction

_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{15,127}$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]+$")
_OUTCOMES = {"tested_no_findings", "finding_identified", "blocked", "not_tested"}


class CoverageError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class AssessmentCoverageService:
    """Record human coverage assertions without inferring completeness."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def record(
        self,
        workflow_id: str,
        *,
        idempotency_key: str,
        asset_rule_id: str,
        capability_rule_id: str,
        capability: str,
        outcome: str,
        started_at: datetime,
        ended_at: datetime,
        evidence_ids: list[str],
        limitations: list[str],
        notes: str,
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        recorded = _instant(now)
        started = _aware(started_at, "COVERAGE_INTERVAL_INVALID")
        ended = _aware(ended_at, "COVERAGE_INTERVAL_INVALID")
        if started > ended or ended > recorded:
            raise CoverageError("COVERAGE_INTERVAL_INVALID", "coverage interval is invalid")
        _identity(actor_id)
        if not _KEY.fullmatch(idempotency_key):
            raise CoverageError("COVERAGE_IDEMPOTENCY_INVALID", "idempotency key is invalid")
        if outcome not in _OUTCOMES:
            raise CoverageError("COVERAGE_OUTCOME_INVALID", "coverage outcome is invalid")
        if not _CAPABILITY.fullmatch(capability) or len(capability) > 128:
            raise CoverageError("COVERAGE_CAPABILITY_INVALID", "capability is invalid")
        _uuid(asset_rule_id, "COVERAGE_ASSET_RULE_INVALID")
        _uuid(capability_rule_id, "COVERAGE_CAPABILITY_RULE_INVALID")
        if len(evidence_ids) > 128 or len(set(evidence_ids)) != len(evidence_ids):
            raise CoverageError("COVERAGE_EVIDENCE_INVALID", "evidence references are invalid")
        for evidence_id in evidence_ids:
            _uuid(evidence_id, "COVERAGE_EVIDENCE_INVALID")
        if outcome in {"tested_no_findings", "finding_identified"} and not evidence_ids:
            raise CoverageError("COVERAGE_EVIDENCE_REQUIRED", "tested coverage requires evidence")
        normalized_limitations = _strings(limitations, 1, 32, 500, "COVERAGE_LIMITATIONS_INVALID")
        normalized_notes = notes.strip()
        if not 1 <= len(normalized_notes) <= 5000:
            raise CoverageError("COVERAGE_NOTES_INVALID", "coverage notes are invalid")
        recorded_at = _timestamp(recorded)
        requested = {
            "asset_rule_id": asset_rule_id,
            "capability_rule_id": capability_rule_id,
            "capability": capability,
            "outcome": outcome,
            "started_at": _timestamp(started),
            "ended_at": _timestamp(ended),
            "evidence_ids": evidence_ids,
            "limitations": normalized_limitations,
            "notes": normalized_notes,
        }
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT document_json FROM assessment_coverage
                   WHERE workflow_id = ? AND idempotency_key = ?""",
                (workflow_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                document = cast(dict[str, Any], json.loads(existing["document_json"]))
                if any(document[key] != value for key, value in requested.items()):
                    raise CoverageError(
                        "COVERAGE_IDEMPOTENCY_CONFLICT", "idempotency key is already bound"
                    )
                _valid(document)
                return document
            workflow = connection.execute(
                "SELECT * FROM assessment_workflows WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            if workflow is None or workflow["status"] not in {"running", "paused", "completed"}:
                raise CoverageError("COVERAGE_WORKFLOW_DENIED", "workflow does not accept coverage")
            if workflow["started_at"] is None or started < parse_time(str(workflow["started_at"])):
                raise CoverageError(
                    "COVERAGE_INTERVAL_INVALID", "coverage predates the assessment workflow"
                )
            policy_row = connection.execute(
                "SELECT policy_json FROM policy_bundles WHERE id = ?",
                (workflow["policy_bundle_id"],),
            ).fetchone()
            if policy_row is None:
                raise CoverageError("COVERAGE_POLICY_MISSING", "coverage policy is unavailable")
            try:
                policy = cast(dict[str, Any], json.loads(policy_row["policy_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise CoverageError(
                    "COVERAGE_POLICY_INVALID", "coverage policy is invalid"
                ) from exc
            _policy_links(policy, asset_rule_id, capability_rule_id, capability)
            _evidence_links(
                connection,
                workflow_id,
                str(workflow["policy_bundle_id"]),
                evidence_ids,
            )
            coverage_id = str(uuid4())
            document = {
                "schema_version": "1.0.0",
                "coverage_id": coverage_id,
                "workflow_id": workflow_id,
                "engagement_id": workflow["engagement_id"],
                "policy_bundle_id": workflow["policy_bundle_id"],
                **requested,
                "recorded_by": actor_id,
                "recorded_at": recorded_at,
                "coverage_complete": False,
            }
            _valid(document)
            digest = content_hash(document)
            connection.execute(
                """INSERT INTO assessment_coverage(
                    coverage_id, workflow_id, engagement_id, policy_bundle_id,
                    idempotency_key, asset_rule_id, capability_rule_id, capability,
                    outcome, started_at, ended_at, evidence_ids_json, limitations_json,
                    notes, recorded_by, recorded_at, document_json, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    coverage_id,
                    workflow_id,
                    workflow["engagement_id"],
                    workflow["policy_bundle_id"],
                    idempotency_key,
                    asset_rule_id,
                    capability_rule_id,
                    capability,
                    outcome,
                    requested["started_at"],
                    requested["ended_at"],
                    canonical_json(evidence_ids),
                    canonical_json(normalized_limitations),
                    normalized_notes,
                    actor_id,
                    recorded_at,
                    canonical_json(document),
                    digest,
                ),
            )
            append_audit_event(
                connection,
                action="coverage.recorded",
                subject_type="assessment_coverage",
                subject_id=coverage_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "workflow_id": workflow_id,
                    "policy_bundle_id": workflow["policy_bundle_id"],
                    "asset_rule_id": asset_rule_id,
                    "capability_rule_id": capability_rule_id,
                    "outcome": outcome,
                    "content_hash": digest,
                    "coverage_complete": False,
                },
                occurred_at=recorded_at,
            )
        return document

    def list_for_workflow(self, workflow_id: str) -> list[dict[str, Any]]:
        with transaction(self.database_path) as connection:
            rows = connection.execute(
                """SELECT document_json FROM assessment_coverage
                   WHERE workflow_id = ? ORDER BY started_at, coverage_id""",
                (workflow_id,),
            ).fetchall()
        documents = [cast(dict[str, Any], json.loads(row["document_json"])) for row in rows]
        for document in documents:
            _valid(document)
        return documents


def _policy_links(
    policy: dict[str, Any], asset_rule_id: str, capability_rule_id: str, capability: str
) -> None:
    asset_rules = policy.get("asset_rules")
    capability_rules = policy.get("capability_rules")
    if not isinstance(asset_rules, list) or not isinstance(capability_rules, list):
        raise CoverageError("COVERAGE_POLICY_INVALID", "coverage policy is invalid")
    asset = next(
        (
            item
            for item in asset_rules
            if isinstance(item, dict) and item.get("rule_id") == asset_rule_id
        ),
        None,
    )
    if asset is None or asset.get("effect") != "allow":
        raise CoverageError("COVERAGE_ASSET_DENIED", "coverage asset rule is not allowed")
    rule = next(
        (
            item
            for item in capability_rules
            if isinstance(item, dict) and item.get("rule_id") == capability_rule_id
        ),
        None,
    )
    if rule is None or rule.get("capability") != capability or rule.get("effect") == "deny":
        raise CoverageError(
            "COVERAGE_CAPABILITY_DENIED", "coverage capability rule is not permitted"
        )
    applicable = rule.get("applicable_asset_rule_ids")
    if applicable is not None and (
        not isinstance(applicable, list) or asset_rule_id not in applicable
    ):
        raise CoverageError(
            "COVERAGE_CAPABILITY_DENIED", "capability rule does not apply to the asset"
        )


def _evidence_links(
    connection: sqlite3.Connection,
    workflow_id: str,
    policy_bundle_id: str,
    evidence_ids: list[str],
) -> None:
    for evidence_id in evidence_ids:
        row = connection.execute(
            """SELECT workflow_id, policy_bundle_id FROM evidence_objects o
               WHERE evidence_id = ? AND NOT EXISTS (
                   SELECT 1 FROM evidence_deletions d
                   WHERE d.artifact_type = 'original' AND d.artifact_id = o.evidence_id
               )""",
            (evidence_id,),
        ).fetchone()
        if (
            row is None
            or row["workflow_id"] != workflow_id
            or row["policy_bundle_id"] != policy_bundle_id
        ):
            raise CoverageError("COVERAGE_EVIDENCE_UNAVAILABLE", "coverage evidence is unavailable")


def _valid(document: dict[str, Any]) -> None:
    if contract_issues(document, "assessment-coverage-v1.schema.json"):
        raise CoverageError("COVERAGE_CONTRACT_INVALID", "coverage contract is invalid")


def _strings(
    values: list[str], minimum: int, maximum: int, length: int, code: str
) -> list[str]:
    normalized = [value.strip() for value in values]
    if (
        not minimum <= len(normalized) <= maximum
        or len(set(normalized)) != len(normalized)
        or any(not value or len(value) > length for value in normalized)
    ):
        raise CoverageError(code, "coverage text collection is invalid")
    return normalized


def _identity(value: str) -> None:
    if not 1 <= len(value.strip()) <= 128:
        raise CoverageError("COVERAGE_ACTOR_REQUIRED", "human actor is required")


def _uuid(value: str, code: str) -> None:
    try:
        UUID(value)
    except (ValueError, TypeError) as exc:
        raise CoverageError(code, "coverage identifier is invalid") from exc


def _aware(value: datetime, code: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CoverageError(code, "coverage time must include a timezone")
    return value.astimezone(UTC)


def _instant(now: datetime | None) -> datetime:
    return _aware(now or datetime.now(UTC), "COVERAGE_TIME_INVALID")


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
