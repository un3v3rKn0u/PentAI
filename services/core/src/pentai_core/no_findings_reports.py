from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues

from pentai_core.audit import append_audit_event
from pentai_core.database import transaction
from pentai_core.reports import REPORT_FORMATS, render_report_artifacts

_TEMPLATES = {"generic", "hackerone", "bugcrowd", "intigriti"}
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{15,127}$")


class NoFindingsReportError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class NoFindingsReportService:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def create_draft(
        self,
        workflow_id: str,
        *,
        idempotency_key: str,
        title: str,
        template: str,
        coverage_ids: list[str],
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        created_at = _timestamp(now)
        _uuid(workflow_id, "NO_FINDINGS_WORKFLOW_INVALID")
        if not 1 <= len(actor_id.strip()) <= 128:
            raise NoFindingsReportError("NO_FINDINGS_ACTOR_INVALID", "human actor is invalid")
        if not _KEY.fullmatch(idempotency_key):
            raise NoFindingsReportError(
                "NO_FINDINGS_IDEMPOTENCY_INVALID", "idempotency key is invalid"
            )
        normalized_title = title.strip()
        if not 1 <= len(normalized_title) <= 200 or template not in _TEMPLATES:
            raise NoFindingsReportError("NO_FINDINGS_REQUEST_INVALID", "request is invalid")
        if not 1 <= len(coverage_ids) <= 500 or len(set(coverage_ids)) != len(coverage_ids):
            raise NoFindingsReportError(
                "NO_FINDINGS_COVERAGE_INVALID", "coverage selection is invalid"
            )
        for coverage_id in coverage_ids:
            _uuid(coverage_id, "NO_FINDINGS_COVERAGE_INVALID")

        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT document_json FROM no_findings_report_drafts
                   WHERE workflow_id = ? AND idempotency_key = ?""",
                (workflow_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                document = cast(dict[str, Any], json.loads(existing["document_json"]))
                if (
                    document["title"] != normalized_title
                    or document["template"] != template
                    or [item["coverage_id"] for item in document["coverage_refs"]]
                    != coverage_ids
                ):
                    raise NoFindingsReportError(
                        "NO_FINDINGS_IDEMPOTENCY_CONFLICT",
                        "idempotency key is already bound",
                    )
                _valid(document)
                return document
            workflow = connection.execute(
                "SELECT * FROM assessment_workflows WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            if (
                workflow is None
                or workflow["status"] != "completed"
                or workflow["started_at"] is None
                or workflow["finalized_at"] is None
            ):
                raise NoFindingsReportError(
                    "NO_FINDINGS_WORKFLOW_INCOMPLETE", "workflow must be completed"
                )
            unresolved = connection.execute(
                "SELECT COUNT(*) FROM findings WHERE workflow_id = ? AND state != 'rejected'",
                (workflow_id,),
            ).fetchone()[0]
            if unresolved:
                raise NoFindingsReportError(
                    "NO_FINDINGS_FINDINGS_PRESENT", "workflow has unresolved findings"
                )
            policy_row = connection.execute(
                "SELECT policy_json FROM policy_bundles WHERE id = ?",
                (workflow["policy_bundle_id"],),
            ).fetchone()
            if policy_row is None:
                raise NoFindingsReportError(
                    "NO_FINDINGS_POLICY_INVALID", "workflow policy is unavailable"
                )
            try:
                policy = cast(dict[str, Any], json.loads(policy_row["policy_json"]))
            except (TypeError, json.JSONDecodeError) as exc:
                raise NoFindingsReportError(
                    "NO_FINDINGS_POLICY_INVALID", "workflow policy is invalid"
                ) from exc
            expected = _expected_matrix(policy)
            all_coverage = connection.execute(
                """SELECT * FROM assessment_coverage
                   WHERE workflow_id = ? ORDER BY recorded_at, coverage_id""",
                (workflow_id,),
            ).fetchall()
            selected = _selected_coverage(all_coverage, coverage_ids, expected)
            refs: list[dict[str, Any]] = []
            limitations: list[str] = []
            payload_coverage: list[dict[str, Any]] = []
            for row, coverage in selected:
                _available_evidence(
                    connection,
                    workflow_id,
                    str(workflow["policy_bundle_id"]),
                    cast(list[str], coverage["evidence_ids"]),
                )
                refs.append(
                    {
                        "coverage_id": row["coverage_id"],
                        "content_hash": row["content_hash"],
                        "asset_rule_id": coverage["asset_rule_id"],
                        "capability_rule_id": coverage["capability_rule_id"],
                        "capability": coverage["capability"],
                        "evidence_ids": coverage["evidence_ids"],
                        "started_at": coverage["started_at"],
                        "ended_at": coverage["ended_at"],
                    }
                )
                limitations.extend(cast(list[str], coverage["limitations"]))
                payload_coverage.append(
                    {
                        "asset_rule_id": coverage["asset_rule_id"],
                        "capability_rule_id": coverage["capability_rule_id"],
                        "capability": coverage["capability"],
                        "testing_period": {
                            "started_at": coverage["started_at"],
                            "ended_at": coverage["ended_at"],
                        },
                        "evidence_ids": coverage["evidence_ids"],
                        "limitations": coverage["limitations"],
                    }
                )
            unique_limitations = list(dict.fromkeys(limitations))
            payload = {
                "report_kind": "no_findings",
                "title": normalized_title,
                "template": template,
                "engagement_id": workflow["engagement_id"],
                "policy_bundle_id": workflow["policy_bundle_id"],
                "testing_period": {
                    "started_at": workflow["started_at"],
                    "ended_at": workflow["finalized_at"],
                },
                "statement": "No findings were identified within the documented coverage.",
                "coverage": payload_coverage,
                "limitations": unique_limitations,
                "findings": [],
            }
            rendered = render_report_artifacts(payload)
            artifacts: list[dict[str, Any]] = [
                {
                    "format": format_name,
                    "media_type": REPORT_FORMATS[format_name],
                    "sha256": sha256(content).hexdigest(),
                    "size_bytes": len(content),
                }
                for format_name, content in rendered.items()
            ]
            if any(cast(int, item["size_bytes"]) > 2_097_152 for item in artifacts):
                raise NoFindingsReportError(
                    "NO_FINDINGS_TOO_LARGE", "report draft exceeds its output bound"
                )
            report_id = str(uuid4())
            document = {
                "schema_version": "1.0.0",
                "report_id": report_id,
                "report_kind": "no_findings",
                "workflow_id": workflow_id,
                "engagement_id": workflow["engagement_id"],
                "policy_bundle_id": workflow["policy_bundle_id"],
                "status": "draft",
                "classification": "restricted",
                "template": template,
                "title": normalized_title,
                "coverage_refs": refs,
                "limitations": unique_limitations,
                "artifacts": artifacts,
                "created_by": actor_id,
                "created_at": created_at,
            }
            _valid(document)
            connection.execute(
                """INSERT INTO no_findings_report_drafts(
                    report_id, workflow_id, engagement_id, policy_bundle_id,
                    idempotency_key, template, title, coverage_refs_json,
                    document_json, content_hash, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    report_id,
                    workflow_id,
                    workflow["engagement_id"],
                    workflow["policy_bundle_id"],
                    idempotency_key,
                    template,
                    normalized_title,
                    canonical_json(refs),
                    canonical_json(document),
                    content_hash(document),
                    actor_id,
                    created_at,
                ),
            )
            for descriptor in artifacts:
                format_name = cast(str, descriptor["format"])
                content = rendered[format_name]
                connection.execute(
                    """INSERT INTO no_findings_report_artifacts(
                        report_id, format, media_type, content, sha256, size_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        report_id,
                        descriptor["format"],
                        descriptor["media_type"],
                        content,
                        descriptor["sha256"],
                        descriptor["size_bytes"],
                    ),
                )
            append_audit_event(
                connection,
                action="report.no_findings_draft_created",
                subject_type="report",
                subject_id=report_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "workflow_id": workflow_id,
                    "policy_bundle_id": workflow["policy_bundle_id"],
                    "coverage_refs": refs,
                    "artifact_digests": {
                        item["format"]: item["sha256"] for item in artifacts
                    },
                    "status": "draft",
                },
                occurred_at=created_at,
            )
        return document

    def get(self, report_id: str) -> dict[str, Any]:
        _uuid(report_id, "NO_FINDINGS_REPORT_ID_INVALID")
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT document_json FROM no_findings_report_drafts WHERE report_id = ?",
                (report_id,),
            ).fetchone()
        if row is None:
            raise NoFindingsReportError("NO_FINDINGS_REPORT_NOT_FOUND", "report is missing")
        document = cast(dict[str, Any], json.loads(row["document_json"]))
        _valid(document)
        return document

    def artifact(self, report_id: str, format_name: str) -> tuple[str, bytes, str]:
        _uuid(report_id, "NO_FINDINGS_REPORT_ID_INVALID")
        if format_name not in REPORT_FORMATS:
            raise NoFindingsReportError("NO_FINDINGS_FORMAT_INVALID", "format is invalid")
        with transaction(self.database_path) as connection:
            row = connection.execute(
                """SELECT media_type, content, sha256 FROM no_findings_report_artifacts
                   WHERE report_id = ? AND format = ?""",
                (report_id, format_name),
            ).fetchone()
        if row is None:
            raise NoFindingsReportError("NO_FINDINGS_REPORT_NOT_FOUND", "artifact is missing")
        content = bytes(row["content"])
        if sha256(content).hexdigest() != row["sha256"]:
            raise NoFindingsReportError(
                "NO_FINDINGS_INTEGRITY_FAILED", "artifact integrity failed"
            )
        return str(row["media_type"]), content, str(row["sha256"])


def _expected_matrix(policy: dict[str, Any]) -> set[tuple[str, str, str]]:
    assets = policy.get("asset_rules")
    capabilities = policy.get("capability_rules")
    if not isinstance(assets, list) or not isinstance(capabilities, list):
        raise NoFindingsReportError("NO_FINDINGS_POLICY_INVALID", "policy is invalid")
    allowed_assets = {
        item["rule_id"]
        for item in assets
        if isinstance(item, dict)
        and item.get("effect") == "allow"
        and isinstance(item.get("rule_id"), str)
    }
    matrix: set[tuple[str, str, str]] = set()
    for rule in capabilities:
        if (
            not isinstance(rule, dict)
            or rule.get("effect") not in {"allow", "conditional"}
            or not isinstance(rule.get("rule_id"), str)
            or not isinstance(rule.get("capability"), str)
        ):
            continue
        applicable = rule.get("applicable_asset_rule_ids")
        if applicable is None:
            rule_assets = allowed_assets
        elif isinstance(applicable, list) and all(isinstance(item, str) for item in applicable):
            rule_assets = allowed_assets.intersection(applicable)
        else:
            raise NoFindingsReportError("NO_FINDINGS_POLICY_INVALID", "policy is invalid")
        matrix.update((asset, rule["rule_id"], rule["capability"]) for asset in rule_assets)
    if not matrix or len(matrix) > 500:
        raise NoFindingsReportError(
            "NO_FINDINGS_MATRIX_INVALID", "policy coverage matrix is empty or too large"
        )
    return matrix


def _selected_coverage(
    rows: list[sqlite3.Row],
    coverage_ids: list[str],
    expected: set[tuple[str, str, str]],
) -> list[tuple[sqlite3.Row, dict[str, Any]]]:
    by_id = {str(row["coverage_id"]): row for row in rows}
    if set(coverage_ids) != set(by_id).intersection(coverage_ids):
        raise NoFindingsReportError(
            "NO_FINDINGS_COVERAGE_MISSING", "selected coverage is unavailable"
        )
    grouped: dict[tuple[str, str, str], list[sqlite3.Row]] = {}
    for row in rows:
        key = (str(row["asset_rule_id"]), str(row["capability_rule_id"]), str(row["capability"]))
        grouped.setdefault(key, []).append(row)
    selected: list[tuple[sqlite3.Row, dict[str, Any]]] = []
    selected_pairs: set[tuple[str, str, str]] = set()
    for coverage_id in coverage_ids:
        row = by_id[coverage_id]
        key = (str(row["asset_rule_id"]), str(row["capability_rule_id"]), str(row["capability"]))
        peers = grouped.get(key, [])
        latest_at = max(str(peer["recorded_at"]) for peer in peers)
        latest = [peer for peer in peers if str(peer["recorded_at"]) == latest_at]
        if len(latest) != 1 or latest[0]["coverage_id"] != coverage_id:
            raise NoFindingsReportError(
                "NO_FINDINGS_COVERAGE_STALE", "selected coverage is stale or ambiguous"
            )
        try:
            document = cast(dict[str, Any], json.loads(row["document_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise NoFindingsReportError(
                "NO_FINDINGS_COVERAGE_INVALID", "coverage document is invalid"
            ) from exc
        if (
            content_hash(document) != row["content_hash"]
            or document.get("outcome") != "tested_no_findings"
        ):
            raise NoFindingsReportError(
                "NO_FINDINGS_COVERAGE_INSUFFICIENT", "coverage does not support no findings"
            )
        if key in selected_pairs:
            raise NoFindingsReportError(
                "NO_FINDINGS_COVERAGE_INVALID", "coverage pair is duplicated"
            )
        selected_pairs.add(key)
        selected.append((row, document))
    if selected_pairs != expected:
        raise NoFindingsReportError(
            "NO_FINDINGS_COVERAGE_INCOMPLETE", "coverage matrix is incomplete"
        )
    return selected


def _available_evidence(
    connection: sqlite3.Connection,
    workflow_id: str,
    policy_bundle_id: str,
    evidence_ids: list[str],
) -> None:
    if not evidence_ids:
        raise NoFindingsReportError(
            "NO_FINDINGS_EVIDENCE_UNAVAILABLE", "coverage evidence is unavailable"
        )
    placeholders = ",".join("?" for _ in evidence_ids)
    rows = connection.execute(
        f"""SELECT o.evidence_id FROM evidence_objects o
             WHERE o.evidence_id IN ({placeholders}) AND o.workflow_id = ?
               AND o.policy_bundle_id = ? AND NOT EXISTS (
                   SELECT 1 FROM evidence_deletions d
                   WHERE d.artifact_type = 'original' AND d.artifact_id = o.evidence_id
               )""",  # noqa: S608 -- generated placeholders; values remain bound
        (*evidence_ids, workflow_id, policy_bundle_id),
    ).fetchall()
    if {row["evidence_id"] for row in rows} != set(evidence_ids):
        raise NoFindingsReportError(
            "NO_FINDINGS_EVIDENCE_UNAVAILABLE", "coverage evidence is unavailable"
        )


def _valid(document: dict[str, Any]) -> None:
    if contract_issues(document, "no-findings-report-draft-v1.schema.json"):
        raise NoFindingsReportError("NO_FINDINGS_CONTRACT_INVALID", "contract is invalid")


def _uuid(value: str, code: str) -> None:
    try:
        UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise NoFindingsReportError(code, "identifier is invalid") from exc


def _timestamp(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise NoFindingsReportError("NO_FINDINGS_TIME_INVALID", "time must include a timezone")
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")
