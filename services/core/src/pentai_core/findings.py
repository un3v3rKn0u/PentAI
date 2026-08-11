from __future__ import annotations

import json
import math
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues

from pentai_core.audit import append_audit_event
from pentai_core.database import transaction

_CWE = re.compile(r"^CWE-[1-9][0-9]{0,4}$")
_TRANSITIONS = {
    "candidate": {"scope_reviewed", "rejected"},
    "scope_reviewed": {"duplicate_reviewed", "rejected"},
    "duplicate_reviewed": {"validated", "rejected"},
    "validated": {"report_ready", "duplicate_reviewed"},
    "report_ready": {"closed", "validated"},
}
_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
_VALIDATION = {"unverified", "confirmed", "not_reproduced", "false_positive", "needs_retest"}
_DUPLICATE = {"pending", "clear", "duplicate"}


class FindingError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class FindingService:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def create(
        self,
        workflow_id: str,
        *,
        idempotency_key: str,
        title: str,
        severity: str,
        cvss_vector: str,
        cvss_score: float,
        cwe: str,
        confidence: int,
        affected_asset_rule_ids: list[str],
        evidence_ids: list[str],
        reproduction: str,
        impact: str,
        remediation: str,
        references: list[str],
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        created_at = _timestamp(now)
        _identity(actor_id)
        _key(idempotency_key)
        normalized = _content(
            title=title,
            severity=severity,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            cwe=cwe,
            confidence=confidence,
            affected_asset_rule_ids=affected_asset_rule_ids,
            evidence_ids=evidence_ids,
            reproduction=reproduction,
            impact=impact,
            remediation=remediation,
            references=references,
        )
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM findings WHERE workflow_id = ? AND idempotency_key = ?",
                (workflow_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                document = _document(existing)
                requested = {key: normalized[key] for key in normalized}
                stored = {key: document[key] for key in normalized}
                if requested != stored:
                    raise FindingError(
                        "FINDING_IDEMPOTENCY_CONFLICT", "finding idempotency key was reused"
                    )
                return document
            workflow = connection.execute(
                "SELECT * FROM assessment_workflows WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            if workflow is None:
                raise FindingError("FINDING_WORKFLOW_MISSING", "assessment workflow is missing")
            if workflow["status"] not in {"running", "paused", "completed"}:
                raise FindingError(
                    "FINDING_WORKFLOW_DENIED", "workflow state does not permit findings"
                )
            policy = connection.execute(
                "SELECT policy_json FROM policy_bundles WHERE id = ?",
                (workflow["policy_bundle_id"],),
            ).fetchone()
            if policy is None:
                raise FindingError("FINDING_POLICY_MISSING", "finding policy is unavailable")
            try:
                policy_document = json.loads(policy["policy_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise FindingError("FINDING_POLICY_INVALID", "finding policy is invalid") from exc
            _asset_links(policy_document, normalized["affected_asset_rule_ids"])
            _evidence_links(
                connection,
                workflow_id,
                str(workflow["policy_bundle_id"]),
                normalized["evidence_ids"],
            )
            finding_id = str(uuid4())
            fingerprint = content_hash(
                {
                    "title": normalized["title"].casefold(),
                    "cwe": normalized["cwe"],
                    "affected_asset_rule_ids": normalized["affected_asset_rule_ids"],
                }
            )
            document = {
                "schema_version": "1.0.0",
                "finding_id": finding_id,
                "workflow_id": workflow_id,
                "engagement_id": workflow["engagement_id"],
                "policy_bundle_id": workflow["policy_bundle_id"],
                "state": "candidate",
                "version": 1,
                **normalized,
                "validation_status": "unverified",
                "duplicate_status": "pending",
                "duplicate_of": None,
                "fingerprint": fingerprint,
                "created_by": actor_id,
                "created_at": created_at,
                "updated_at": created_at,
            }
            _valid(document)
            digest = content_hash(document)
            connection.execute(
                """INSERT INTO findings(
                    finding_id, workflow_id, engagement_id, policy_bundle_id,
                    idempotency_key, state, version, title, severity, cvss_vector,
                    cvss_score, cwe, confidence, validation_status, duplicate_status,
                    duplicate_of, affected_asset_rule_ids_json, evidence_ids_json,
                    reproduction, impact, remediation, references_json, fingerprint,
                    created_by, created_at, updated_at, document_json, content_hash
                ) VALUES (?, ?, ?, ?, ?, 'candidate', 1, ?, ?, ?, ?, ?, ?, 'unverified',
                          'pending', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    workflow_id,
                    workflow["engagement_id"],
                    workflow["policy_bundle_id"],
                    idempotency_key,
                    normalized["title"],
                    normalized["severity"],
                    normalized["cvss"]["vector"],
                    normalized["cvss"]["base_score"],
                    normalized["cwe"],
                    normalized["confidence"],
                    canonical_json(normalized["affected_asset_rule_ids"]),
                    canonical_json(normalized["evidence_ids"]),
                    normalized["reproduction"],
                    normalized["impact"],
                    normalized["remediation"],
                    canonical_json(normalized["references"]),
                    fingerprint,
                    actor_id,
                    created_at,
                    created_at,
                    canonical_json(document),
                    digest,
                ),
            )
            _version(connection, document, "candidate created", actor_id, created_at)
            _audit(connection, document, "finding.created", actor_id, created_at)
        return document

    def transition(
        self,
        finding_id: str,
        *,
        target_state: str,
        expected_version: int,
        reason: str,
        actor_id: str,
        validation_status: str | None = None,
        duplicate_status: str | None = None,
        duplicate_of: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        changed_at = _timestamp(now)
        _identity(actor_id)
        normalized_reason = reason.strip()
        if not 1 <= len(normalized_reason) <= 1000:
            raise FindingError("FINDING_REASON_INVALID", "transition reason is invalid")
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
            if row is None:
                raise FindingError("FINDING_NOT_FOUND", "finding does not exist")
            if row["version"] != expected_version:
                raise FindingError("FINDING_FENCED", "finding version is stale")
            if target_state not in _TRANSITIONS.get(str(row["state"]), set()):
                raise FindingError("FINDING_TRANSITION_DENIED", "finding transition is invalid")
            next_validation = (
                validation_status
                if validation_status is not None
                else str(row["validation_status"])
            )
            next_duplicate = (
                duplicate_status if duplicate_status is not None else str(row["duplicate_status"])
            )
            next_duplicate_of = (
                duplicate_of if duplicate_status is not None else row["duplicate_of"]
            )
            if next_validation not in _VALIDATION or next_duplicate not in _DUPLICATE:
                raise FindingError("FINDING_REVIEW_INVALID", "finding review state is invalid")
            if next_duplicate == "duplicate":
                _duplicate_target(connection, row, next_duplicate_of)
            elif next_duplicate_of is not None:
                raise FindingError("FINDING_DUPLICATE_INVALID", "duplicate identity is invalid")
            if target_state == "scope_reviewed" and (
                next_validation != "unverified" or next_duplicate != "pending"
            ):
                raise FindingError("FINDING_REVIEW_INVALID", "scope review cannot skip review")
            if target_state == "duplicate_reviewed" and next_duplicate == "pending":
                raise FindingError("FINDING_DUPLICATE_REQUIRED", "duplicate review is required")
            if target_state in {"validated", "report_ready", "closed"} and (
                next_duplicate != "clear" or next_validation != "confirmed"
            ):
                raise FindingError(
                    "FINDING_VALIDATION_REQUIRED", "confirmed non-duplicate validation is required"
                )
            if target_state == "rejected" and (
                next_duplicate != "duplicate"
                and next_validation not in {"not_reproduced", "false_positive"}
            ):
                raise FindingError(
                    "FINDING_REJECTION_REVIEW_REQUIRED", "rejection requires a review outcome"
                )
            version = expected_version + 1
            document = _document(row) | {
                "state": target_state,
                "version": version,
                "validation_status": next_validation,
                "duplicate_status": next_duplicate,
                "duplicate_of": next_duplicate_of,
                "updated_at": changed_at,
            }
            _valid(document)
            digest = content_hash(document)
            _version(connection, document, normalized_reason, actor_id, changed_at)
            updated = connection.execute(
                """UPDATE findings SET state = ?, version = ?, validation_status = ?,
                       duplicate_status = ?, duplicate_of = ?, updated_at = ?,
                       document_json = ?, content_hash = ?
                   WHERE finding_id = ? AND version = ? AND state = ?""",
                (
                    target_state,
                    version,
                    next_validation,
                    next_duplicate,
                    next_duplicate_of,
                    changed_at,
                    canonical_json(document),
                    digest,
                    finding_id,
                    expected_version,
                    row["state"],
                ),
            )
            if updated.rowcount != 1:
                raise FindingError("FINDING_FENCED", "finding version changed")
            _audit(connection, document, "finding.transitioned", actor_id, changed_at)
        return document

    def get(self, finding_id: str) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        if row is None:
            raise FindingError("FINDING_NOT_FOUND", "finding does not exist")
        document = _document(row)
        _valid(document)
        return document

    def list_for_workflow(self, workflow_id: str) -> list[dict[str, Any]]:
        with transaction(self.database_path) as connection:
            rows = connection.execute(
                "SELECT * FROM findings WHERE workflow_id = ? ORDER BY created_at, finding_id",
                (workflow_id,),
            ).fetchall()
        documents = [_document(row) for row in rows]
        for document in documents:
            _valid(document)
        return documents

    def history(self, finding_id: str) -> list[dict[str, Any]]:
        with transaction(self.database_path) as connection:
            rows = connection.execute(
                """SELECT version, document_json, content_hash, transition_reason, author_type,
                          author_id, created_at FROM finding_versions
                   WHERE finding_id = ? ORDER BY version""",
                (finding_id,),
            ).fetchall()
        if not rows:
            raise FindingError("FINDING_NOT_FOUND", "finding does not exist")
        history: list[dict[str, Any]] = []
        for row in rows:
            try:
                document = json.loads(row["document_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise FindingError(
                    "FINDING_INTEGRITY_FAILED", "finding history integrity verification failed"
                ) from exc
            if not isinstance(document, dict) or content_hash(document) != row["content_hash"]:
                raise FindingError(
                    "FINDING_INTEGRITY_FAILED", "finding history integrity verification failed"
                )
            _valid(document)
            history.append(
                {
                    "version": row["version"],
                    "document": document,
                    "transition_reason": row["transition_reason"],
                    "author_type": row["author_type"],
                    "author_id": row["author_id"],
                    "created_at": row["created_at"],
                }
            )
        return history


def _content(**values: Any) -> dict[str, Any]:
    title = str(values["title"]).strip()
    severity = str(values["severity"])
    cwe = str(values["cwe"])
    confidence = values["confidence"]
    if not 1 <= len(title) <= 200 or severity not in _SEVERITIES or not _CWE.fullmatch(cwe):
        raise FindingError("FINDING_CLASSIFICATION_INVALID", "finding classification is invalid")
    if (
        not isinstance(confidence, int)
        or isinstance(confidence, bool)
        or not 0 <= confidence <= 100
    ):
        raise FindingError("FINDING_CONFIDENCE_INVALID", "finding confidence is invalid")
    calculated = _cvss_score(str(values["cvss_vector"]))
    supplied = values["cvss_score"]
    if (
        not isinstance(supplied, (int, float))
        or isinstance(supplied, bool)
        or supplied != calculated
    ):
        raise FindingError("FINDING_CVSS_INVALID", "CVSS vector and score do not match")
    expected_severity = _severity(calculated)
    if severity != expected_severity:
        raise FindingError("FINDING_SEVERITY_INVALID", "severity does not match CVSS score")
    assets = _uuid_list(values["affected_asset_rule_ids"], 64, "FINDING_ASSETS_INVALID")
    evidence = _uuid_list(values["evidence_ids"], 128, "FINDING_EVIDENCE_INVALID")
    if not isinstance(values["references"], list) or any(
        not isinstance(item, str) for item in values["references"]
    ):
        raise FindingError("FINDING_REFERENCES_INVALID", "finding references are invalid")
    references = sorted(set(values["references"]))
    if len(references) > 32 or any(not _reference(item) for item in references):
        raise FindingError("FINDING_REFERENCES_INVALID", "finding references are invalid")
    text: dict[str, str] = {}
    for field, limit in (("reproduction", 20_000), ("impact", 10_000), ("remediation", 10_000)):
        value = str(values[field]).strip()
        if not 1 <= len(value) <= limit:
            raise FindingError("FINDING_CONTENT_INVALID", "finding content is invalid")
        text[field] = value
    return {
        "title": title,
        "severity": severity,
        "cvss": {"version": "3.1", "vector": values["cvss_vector"], "base_score": calculated},
        "cwe": cwe,
        "confidence": confidence,
        "affected_asset_rule_ids": assets,
        "evidence_ids": evidence,
        **text,
        "references": references,
    }


def _cvss_score(vector: str) -> float:
    pattern = re.compile(
        r"^CVSS:3\.1/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/"
        r"UI:(?P<UI>[NR])/S:(?P<S>[UC])/C:(?P<C>[NLH])/I:(?P<I>[NLH])/A:(?P<A>[NLH])$"
    )
    match = pattern.fullmatch(vector)
    if match is None:
        raise FindingError("FINDING_CVSS_INVALID", "CVSS 3.1 vector is invalid")
    metric = match.groupdict()
    scope_changed = metric["S"] == "C"
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metric["AV"]]
    ac = {"L": 0.77, "H": 0.44}[metric["AC"]]
    pr = ({"N": 0.85, "L": 0.68, "H": 0.5} if scope_changed else {"N": 0.85, "L": 0.62, "H": 0.27})[
        metric["PR"]
    ]
    ui = {"N": 0.85, "R": 0.62}[metric["UI"]]
    impact_metric = {"N": 0.0, "L": 0.22, "H": 0.56}
    isc = 1 - (1 - impact_metric[metric["C"]]) * (1 - impact_metric[metric["I"]]) * (
        1 - impact_metric[metric["A"]]
    )
    impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15) if scope_changed else 6.42 * isc
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    base = (
        min(1.08 * (impact + exploitability), 10)
        if scope_changed
        else min(impact + exploitability, 10)
    )
    return math.ceil(base * 10 - 1e-10) / 10


def _severity(score: float) -> str:
    if score == 0:
        return "informational"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def _asset_links(policy: dict[str, Any], requested: list[str]) -> None:
    if not isinstance(policy, dict) or not isinstance(policy.get("asset_rules"), list):
        raise FindingError("FINDING_POLICY_INVALID", "finding policy is invalid")
    allowed = {
        rule["rule_id"]
        for rule in policy.get("asset_rules", [])
        if isinstance(rule, dict) and rule.get("effect") == "allow"
    }
    if not set(requested) <= allowed:
        raise FindingError("FINDING_ASSET_OUT_OF_SCOPE", "affected asset is not allowed")


def _evidence_links(
    connection: sqlite3.Connection, workflow_id: str, policy_bundle_id: str, evidence_ids: list[str]
) -> None:
    placeholders = ",".join("?" for _ in evidence_ids)
    rows = connection.execute(
        f"""SELECT o.evidence_id FROM evidence_objects o
             WHERE o.evidence_id IN ({placeholders}) AND o.workflow_id = ?
               AND o.policy_bundle_id = ? AND NOT EXISTS (
                   SELECT 1 FROM evidence_deletions d
                   WHERE d.artifact_type = 'original' AND d.artifact_id = o.evidence_id
               )""",  # noqa: S608 -- placeholders are generated, values remain bound
        (*evidence_ids, workflow_id, policy_bundle_id),
    ).fetchall()
    if {row["evidence_id"] for row in rows} != set(evidence_ids):
        raise FindingError("FINDING_EVIDENCE_MISMATCH", "evidence is unavailable or mismatched")


def _duplicate_target(connection: sqlite3.Connection, row: sqlite3.Row, target: Any) -> None:
    if not isinstance(target, str) or target == row["finding_id"]:
        raise FindingError("FINDING_DUPLICATE_INVALID", "duplicate identity is invalid")
    candidate = connection.execute(
        "SELECT engagement_id, state FROM findings WHERE finding_id = ?", (target,)
    ).fetchone()
    if (
        candidate is None
        or candidate["engagement_id"] != row["engagement_id"]
        or candidate["state"] == "rejected"
    ):
        raise FindingError("FINDING_DUPLICATE_INVALID", "duplicate target is invalid")


def _uuid_list(values: Any, maximum: int, code: str) -> list[str]:
    if not isinstance(values, list) or not 1 <= len(values) <= maximum:
        raise FindingError(code, "finding reference list is invalid")
    try:
        normalized = sorted({str(UUID(value)) for value in values})
    except (ValueError, TypeError, AttributeError) as exc:
        raise FindingError(code, "finding reference list is invalid") from exc
    if len(normalized) != len(values):
        raise FindingError(code, "finding reference list contains duplicates")
    return normalized


def _reference(value: Any) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return False
    parsed = urlsplit(value)
    if parsed.scheme == "https":
        return bool(parsed.hostname) and parsed.username is None and parsed.password is None
    return parsed.scheme == "urn" and bool(parsed.path)


def _document(row: sqlite3.Row) -> dict[str, Any]:
    try:
        parsed = json.loads(row["document_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise FindingError(
            "FINDING_INTEGRITY_FAILED", "finding integrity verification failed"
        ) from exc
    if not isinstance(parsed, dict):
        raise FindingError("FINDING_INTEGRITY_FAILED", "finding integrity verification failed")
    document = cast(dict[str, Any], parsed)
    if content_hash(document) != row["content_hash"]:
        raise FindingError("FINDING_INTEGRITY_FAILED", "finding integrity verification failed")
    return document


def _version(
    connection: sqlite3.Connection,
    document: dict[str, Any],
    reason: str,
    actor_id: str,
    created_at: str,
) -> None:
    connection.execute(
        """INSERT INTO finding_versions(
               version_id, finding_id, version, document_json, content_hash,
               transition_reason, author_type, author_id, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, 'human', ?, ?)""",
        (
            str(uuid4()),
            document["finding_id"],
            document["version"],
            canonical_json(document),
            content_hash(document),
            reason,
            actor_id,
            created_at,
        ),
    )


def _audit(
    connection: sqlite3.Connection,
    document: dict[str, Any],
    action: str,
    actor_id: str,
    occurred_at: str,
) -> None:
    append_audit_event(
        connection,
        action=action,
        subject_type="finding",
        subject_id=str(document["finding_id"]),
        actor_type="human",
        actor_id=actor_id,
        data={
            "workflow_id": document["workflow_id"],
            "policy_bundle_id": document["policy_bundle_id"],
            "state": document["state"],
            "version": document["version"],
            "validation_status": document["validation_status"],
            "duplicate_status": document["duplicate_status"],
            "evidence_ids": document["evidence_ids"],
            "affected_asset_rule_ids": document["affected_asset_rule_ids"],
        },
        occurred_at=occurred_at,
    )


def _valid(document: dict[str, Any]) -> None:
    if contract_issues(document, "finding-v1.schema.json"):
        raise FindingError("FINDING_CONTRACT_INVALID", "finding contract is invalid")


def _identity(actor_id: str) -> None:
    if not isinstance(actor_id, str) or not 1 <= len(actor_id) <= 128:
        raise FindingError("FINDING_ACTOR_INVALID", "finding actor is invalid")


def _key(value: str) -> None:
    if not isinstance(value, str) or not 16 <= len(value) <= 128:
        raise FindingError("FINDING_IDEMPOTENCY_INVALID", "finding idempotency key is invalid")


def _timestamp(now: datetime | None) -> str:
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise FindingError("FINDING_TIME_INVALID", "finding time is invalid")
    return instant.astimezone(UTC).isoformat().replace("+00:00", "Z")
