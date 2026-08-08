from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from pentai_policy import (
    canonical_json,
    compile_manifest,
    content_hash,
    evaluate,
    validate_and_canonicalize_manifest,
)
from pentai_policy.document import parse_time

from pentai_core.database import transaction


class DomainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


class AuthorizationService:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        action: str,
        subject_type: str,
        subject_id: str,
        actor_type: str,
        actor_id: str,
        data: dict[str, Any],
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else None
        event = {
            "event_id": str(uuid4()),
            "occurred_at": occurred_at or _timestamp(),
            "actor_type": actor_type,
            "actor_id": actor_id,
            "action": action,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "data": data,
            "previous_hash": previous_hash,
        }
        event_hash = content_hash(event)
        connection.execute(
            """
            INSERT INTO audit_events(
                event_id, occurred_at, actor_type, actor_id, action, subject_type,
                subject_id, data_json, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["event_id"],
                event["occurred_at"],
                actor_type,
                actor_id,
                action,
                subject_type,
                subject_id,
                canonical_json(data),
                previous_hash,
                event_hash,
            ),
        )
        return {**event, "event_hash": event_hash}

    def create_program(self, name: str, platform: str | None = None) -> dict[str, Any]:
        if not name.strip():
            raise DomainError("PROGRAM_NAME_REQUIRED", "program name is required")
        program_id = str(uuid4())
        with transaction(self.database_path) as connection:
            connection.execute(
                "INSERT INTO programs(id, name, platform, status) VALUES (?, ?, ?, 'draft')",
                (program_id, name.strip(), platform),
            )
        return {"id": program_id, "name": name.strip(), "platform": platform, "status": "draft"}

    def create_engagement(
        self,
        program_id: str,
        *,
        effective_from: str,
        expires_at: str,
        timezone: str,
    ) -> dict[str, Any]:
        try:
            if parse_time(expires_at) <= parse_time(effective_from):
                raise ValueError
        except ValueError as exc:
            raise DomainError("VALIDITY_INVALID", "engagement validity window is invalid") from exc
        engagement_id = str(uuid4())
        with transaction(self.database_path) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO engagements(
                        id, program_id, status, effective_from, expires_at, timezone
                    ) VALUES (?, ?, 'draft', ?, ?, ?)
                    """,
                    (engagement_id, program_id, effective_from, expires_at, timezone),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("PROGRAM_NOT_FOUND", "program does not exist") from exc
        return {
            "id": engagement_id,
            "program_id": program_id,
            "status": "draft",
            "effective_from": effective_from,
            "expires_at": expires_at,
            "timezone": timezone,
        }

    def import_source(
        self,
        program_id: str,
        *,
        authority: str,
        reference: str,
        content: str,
        effective_at: str | None = None,
    ) -> dict[str, Any]:
        if not content:
            raise DomainError("SOURCE_EMPTY", "source content is required")
        source_id = str(uuid4())
        digest = hashlib.sha256(content.encode()).hexdigest()
        retrieved_at = _timestamp()
        with transaction(self.database_path) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO source_documents(
                        id, program_id, authority, reference, retrieved_at, effective_at,
                        content_hash, encrypted_blob_ref, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}')
                    """,
                    (
                        source_id,
                        program_id,
                        authority,
                        reference,
                        retrieved_at,
                        effective_at,
                        digest,
                        f"sha256:{digest}",
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("PROGRAM_NOT_FOUND", "program does not exist") from exc
        return {
            "id": source_id,
            "program_id": program_id,
            "authority": authority,
            "reference": reference,
            "retrieved_at": retrieved_at,
            "effective_at": effective_at,
            "content_hash": digest,
        }

    def save_manifest(self, engagement_id: str, candidate: dict[str, Any]) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            engagement = connection.execute(
                "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
            ).fetchone()
            if engagement is None:
                raise DomainError("ENGAGEMENT_NOT_FOUND", "engagement does not exist")
            candidate_engagement = candidate.get("engagement")
            expected_engagement = {
                "id": engagement["id"],
                "effective_from": engagement["effective_from"],
                "expires_at": engagement["expires_at"],
                "timezone": engagement["timezone"],
            }
            if not isinstance(candidate_engagement, dict) or any(
                candidate_engagement.get(key) != value for key, value in expected_engagement.items()
            ):
                raise DomainError(
                    "ENGAGEMENT_MISMATCH",
                    "manifest engagement identity and validity must match the stored engagement",
                )
            source_rows = connection.execute(
                "SELECT id, content_hash FROM source_documents WHERE program_id = ?",
                (engagement["program_id"],),
            ).fetchall()
            source_hashes = {row["id"]: row["content_hash"] for row in source_rows}
            validation = validate_and_canonicalize_manifest(candidate, source_hashes=source_hashes)
            canonical = validation.document or candidate
            digest = content_hash(canonical)
            previous = connection.execute(
                """
                SELECT id FROM manifest_versions
                WHERE engagement_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1
                """,
                (engagement_id,),
            ).fetchone()
            manifest_id = str(uuid4())
            try:
                connection.execute(
                    """
                    INSERT INTO manifest_versions(
                        id, engagement_id, schema_version, document_json, content_hash,
                        supersedes_id
                    ) VALUES (?, ?, '2.0.0', ?, ?, ?)
                    """,
                    (
                        manifest_id,
                        engagement_id,
                        canonical_json(canonical),
                        digest,
                        previous["id"] if previous else None,
                    ),
                )
            except sqlite3.IntegrityError:
                existing = connection.execute(
                    "SELECT id FROM manifest_versions WHERE content_hash = ?", (digest,)
                ).fetchone()
                if existing is None:
                    raise
                manifest_id = existing["id"]
            return {
                "id": manifest_id,
                "engagement_id": engagement_id,
                "content_hash": digest,
                "document": canonical,
                "valid": validation.valid,
                "issues": [issue.as_dict() for issue in validation.issues],
                "supersedes_id": previous["id"] if previous else None,
            }

    def compile_policy(self, manifest_version_id: str) -> dict[str, Any]:
        rejection_code: str | None = None
        result: dict[str, Any] | None = None
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM manifest_versions WHERE id = ?", (manifest_version_id,)
            ).fetchone()
            if row is None:
                raise DomainError("MANIFEST_NOT_FOUND", "manifest does not exist")
            manifest = json.loads(row["document_json"])
            engagement = connection.execute(
                "SELECT program_id FROM engagements WHERE id = ?", (row["engagement_id"],)
            ).fetchone()
            sources = connection.execute(
                "SELECT id, content_hash FROM source_documents WHERE program_id = ?",
                (engagement["program_id"],),
            ).fetchall()
            validation = validate_and_canonicalize_manifest(
                manifest, source_hashes={item["id"]: item["content_hash"] for item in sources}
            )
            if not validation.valid or content_hash(manifest) != row["content_hash"]:
                codes = [issue.code for issue in validation.issues] or ["MANIFEST_HASH_MISMATCH"]
                self._audit(
                    connection,
                    action="policy.rejected",
                    subject_type="manifest",
                    subject_id=manifest_version_id,
                    actor_type="service",
                    actor_id="policy-compiler",
                    data={"reason_codes": sorted(set(codes))},
                )
                rejection_code = codes[0]
            else:
                policy = compile_manifest(manifest, row["content_hash"])
                existing = connection.execute(
                    "SELECT id FROM policy_bundles WHERE content_hash = ?",
                    (policy["content_hash"],),
                ).fetchone()
                policy_id = existing["id"] if existing else str(uuid4())
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO policy_bundles(
                            id, engagement_id, manifest_version_id, schema_version,
                            compiler_version, policy_json, content_hash
                        ) VALUES (?, ?, ?, '1.0.0', '1.0.0', ?, ?)
                        """,
                        (
                            policy_id,
                            row["engagement_id"],
                            manifest_version_id,
                            canonical_json(policy),
                            policy["content_hash"],
                        ),
                    )
                result = {
                    "id": policy_id,
                    "policy": policy,
                    "content_hash": policy["content_hash"],
                }
        if rejection_code is not None:
            raise DomainError(rejection_code, "manifest is not eligible for compilation")
        if result is None:
            raise DomainError("COMPILATION_FAILED", "policy compilation failed")
        return result

    def approve_policy(
        self,
        policy_bundle_id: str,
        *,
        approver_id: str,
        decision: str = "approved",
        expires_at: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        if not approver_id.strip():
            raise DomainError("HUMAN_APPROVER_REQUIRED", "human approver identity is required")
        if decision not in {"approved", "rejected"}:
            raise DomainError("APPROVAL_DECISION_INVALID", "decision must be approved or rejected")
        decided_at = _timestamp()
        expiry = (
            _timestamp(parse_time(expires_at))
            if expires_at is not None
            else _timestamp(_now() + timedelta(hours=8))
        )
        if parse_time(expiry) <= parse_time(decided_at):
            raise DomainError("APPROVAL_EXPIRED", "approval expiry must be in the future")
        with transaction(self.database_path) as connection:
            policy = connection.execute(
                """
                SELECT p.*, m.content_hash AS manifest_hash
                FROM policy_bundles p
                JOIN manifest_versions m ON m.id = p.manifest_version_id
                WHERE p.id = ?
                """,
                (policy_bundle_id,),
            ).fetchone()
            if policy is None:
                raise DomainError("POLICY_NOT_FOUND", "policy does not exist")
            approval_id = str(uuid4())
            attestation_payload = {
                "approval_id": approval_id,
                "manifest_hash": policy["manifest_hash"],
                "policy_hash": policy["content_hash"],
                "approver_id": approver_id.strip(),
                "decision": decision,
                "decided_at": decided_at,
                "expires_at": expiry,
            }
            document: dict[str, Any] = {
                "schema_version": "1.1.0",
                "approval_id": approval_id,
                "approval_type": "policy_activation",
                "subject": {"subject_type": "policy", "subject_id": policy_bundle_id},
                "assessment_id": policy["engagement_id"],
                "policy_hash": policy["content_hash"],
                "constraints": {},
                "decision": decision,
                "approver": {"actor_type": "human", "actor_id": approver_id.strip()},
                "decided_at": decided_at,
                "expires_at": expiry,
                "signature": {
                    "algorithm": "local-transaction-sha256",
                    "key_id": "local-authorization-ledger",
                    "value": content_hash(attestation_payload),
                },
            }
            if reason:
                document["reason"] = reason
            connection.execute(
                """
                INSERT INTO approvals(
                    id, approval_type, engagement_id, manifest_version_id, manifest_hash,
                    policy_bundle_id, policy_hash, decision, approver_id, decided_at,
                    expires_at, document_json
                ) VALUES (?, 'policy_activation', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    policy["engagement_id"],
                    policy["manifest_version_id"],
                    policy["manifest_hash"],
                    policy_bundle_id,
                    policy["content_hash"],
                    decision,
                    approver_id.strip(),
                    decided_at,
                    expiry,
                    canonical_json(document),
                ),
            )
            self._audit(
                connection,
                action="policy.approval" if decision == "approved" else "policy.rejection",
                subject_type="policy",
                subject_id=policy_bundle_id,
                actor_type="human",
                actor_id=approver_id.strip(),
                data={
                    "approval_id": approval_id,
                    "decision": decision,
                    "manifest_hash": policy["manifest_hash"],
                    "policy_hash": policy["content_hash"],
                    "reason": reason,
                },
                occurred_at=decided_at,
            )
            return document

    def activate_policy(self, policy_bundle_id: str, *, actor_id: str) -> dict[str, Any]:
        activated_at = _timestamp()
        with transaction(self.database_path) as connection:
            policy = connection.execute(
                """
                SELECT p.*, m.content_hash AS manifest_hash, m.document_json,
                       e.program_id, e.status AS engagement_status
                FROM policy_bundles p
                JOIN manifest_versions m ON m.id = p.manifest_version_id
                JOIN engagements e ON e.id = p.engagement_id
                WHERE p.id = ?
                """,
                (policy_bundle_id,),
            ).fetchone()
            if policy is None:
                raise DomainError("POLICY_NOT_FOUND", "policy does not exist")
            if policy["revoked_at"] is not None:
                raise DomainError("POLICY_REVOKED", "revoked policies cannot be activated")
            if policy["activated_at"] is not None:
                raise DomainError("POLICY_ALREADY_ACTIVE", "policy is already active")
            policy_document = json.loads(policy["policy_json"])
            if (
                content_hash({k: v for k, v in policy_document.items() if k != "content_hash"})
                != policy["content_hash"]
                or policy_document["manifest_hash"] != policy["manifest_hash"]
                or content_hash(json.loads(policy["document_json"])) != policy["manifest_hash"]
            ):
                raise DomainError("POLICY_HASH_MISMATCH", "policy provenance is altered")
            source_rows = connection.execute(
                "SELECT id, content_hash FROM source_documents WHERE program_id = ?",
                (policy["program_id"],),
            ).fetchall()
            validation = validate_and_canonicalize_manifest(
                json.loads(policy["document_json"]),
                source_hashes={row["id"]: row["content_hash"] for row in source_rows},
            )
            if not validation.valid:
                raise DomainError(
                    validation.issues[0].code, "manifest is no longer eligible for activation"
                )
            approval = connection.execute(
                """
                SELECT * FROM approvals
                WHERE policy_bundle_id = ? AND approval_type = 'policy_activation'
                  AND decision = 'approved' AND invalidated_at IS NULL
                  AND manifest_hash = ? AND policy_hash = ?
                  AND julianday(expires_at) > julianday(?)
                ORDER BY decided_at DESC LIMIT 1
                """,
                (
                    policy_bundle_id,
                    policy["manifest_hash"],
                    policy["content_hash"],
                    activated_at,
                ),
            ).fetchone()
            if approval is None:
                raise DomainError("APPROVAL_MISSING", "exact human policy approval is required")
            approval_document = json.loads(approval["document_json"])
            expected_attestation = content_hash(
                {
                    "approval_id": approval["id"],
                    "manifest_hash": approval["manifest_hash"],
                    "policy_hash": approval["policy_hash"],
                    "approver_id": approval["approver_id"],
                    "decision": approval["decision"],
                    "decided_at": approval["decided_at"],
                    "expires_at": approval["expires_at"],
                }
            )
            signature = approval_document.get("signature", {})
            common_fields_valid = (
                approval_document.get("schema_version") in {"1.0.0", "1.1.0"}
                and approval_document.get("approval_id") == approval["id"]
                and approval_document.get("approval_type") == approval["approval_type"]
                and approval_document.get("subject", {}).get("subject_type") == "policy"
                and approval_document.get("subject", {}).get("subject_id")
                == approval["policy_bundle_id"]
                and approval_document.get("policy_hash") == approval["policy_hash"]
                and approval_document.get("decision") == approval["decision"]
                and approval_document.get("decided_at") == approval["decided_at"]
                and approval_document.get("expires_at") == approval["expires_at"]
                and approval_document.get("approver", {}).get("actor_id") == approval["approver_id"]
            )
            current_attestation_valid = (
                approval_document.get("schema_version") == "1.1.0"
                and signature.get("algorithm") == "local-transaction-sha256"
                and signature.get("key_id") == "local-authorization-ledger"
                and signature.get("value") == expected_attestation
            )
            legacy_attestation = content_hash(
                {
                    "approval_id": approval["id"],
                    "manifest_hash": approval["manifest_hash"],
                    "policy_hash": approval["policy_hash"],
                    "approver_id": approval["approver_id"],
                    "decision": approval["decision"],
                }
            )
            legacy_attestation_valid = (
                approval_document.get("schema_version") == "1.0.0"
                and signature.get("algorithm") == "Ed25519"
                and signature.get("key_id") == "local-human-attestation"
                and signature.get("value") == legacy_attestation
            )
            if not common_fields_valid or not (
                current_attestation_valid or legacy_attestation_valid
            ):
                raise DomainError("APPROVAL_INVALID", "approval attestation is invalid")
            previous_policy = connection.execute(
                """
                SELECT * FROM policy_bundles
                WHERE engagement_id = ? AND activated_at IS NOT NULL
                  AND revoked_at IS NULL AND id != ?
                """,
                (policy["engagement_id"], policy_bundle_id),
            ).fetchone()
            if previous_policy is not None:
                connection.execute(
                    "UPDATE policy_bundles SET revoked_at = ? WHERE id = ?",
                    (activated_at, previous_policy["id"]),
                )
                connection.execute(
                    """
                    UPDATE engagements
                    SET revocation_epoch = revocation_epoch + 1
                    WHERE id = ?
                    """,
                    (policy["engagement_id"],),
                )
                self._audit(
                    connection,
                    action="policy.revocation",
                    subject_type="policy",
                    subject_id=previous_policy["id"],
                    actor_type="human",
                    actor_id=actor_id,
                    data={
                        "policy_hash": previous_policy["content_hash"],
                        "reason": "replaced by approved policy",
                        "replacement_policy_id": policy_bundle_id,
                    },
                    occurred_at=activated_at,
                )
            activated = connection.execute(
                """
                UPDATE policy_bundles SET activated_at = ?
                WHERE id = ? AND activated_at IS NULL AND revoked_at IS NULL
                """,
                (activated_at, policy_bundle_id),
            )
            if activated.rowcount != 1:
                raise DomainError("POLICY_STATE_CHANGED", "policy activation state changed")
            connection.execute(
                """
                UPDATE engagements SET status = 'active', active_policy_id = ?
                WHERE id = ?
                """,
                (policy_bundle_id, policy["engagement_id"]),
            )
            connection.execute(
                "UPDATE programs SET status = 'active' WHERE id = ?", (policy["program_id"],)
            )
            self._audit(
                connection,
                action="policy.activation",
                subject_type="policy",
                subject_id=policy_bundle_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "approval_id": approval["id"],
                    "manifest_hash": policy["manifest_hash"],
                    "policy_hash": policy["content_hash"],
                },
                occurred_at=activated_at,
            )
        return {"id": policy_bundle_id, "status": "active", "activated_at": activated_at}

    def revoke_policy(self, policy_bundle_id: str, *, actor_id: str, reason: str) -> None:
        revoked_at = _timestamp()
        with transaction(self.database_path) as connection:
            policy = connection.execute(
                "SELECT * FROM policy_bundles WHERE id = ?", (policy_bundle_id,)
            ).fetchone()
            if policy is None:
                raise DomainError("POLICY_NOT_FOUND", "policy does not exist")
            connection.execute(
                "UPDATE policy_bundles SET revoked_at = ? WHERE id = ?",
                (revoked_at, policy_bundle_id),
            )
            connection.execute(
                """
                UPDATE engagements
                SET status = 'revoked', active_policy_id = NULL,
                    revocation_epoch = revocation_epoch + 1
                WHERE id = ?
                """,
                (policy["engagement_id"],),
            )
            self._audit(
                connection,
                action="policy.revocation",
                subject_type="policy",
                subject_id=policy_bundle_id,
                actor_type="human",
                actor_id=actor_id,
                data={"policy_hash": policy["content_hash"], "reason": reason},
                occurred_at=revoked_at,
            )

    def evaluate_intent(
        self, engagement_id: str, intent: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            engagement = connection.execute(
                "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
            ).fetchone()
            if engagement is None or engagement["active_policy_id"] is None:
                raise DomainError("POLICY_INACTIVE", "engagement has no active policy")
            policy = connection.execute(
                "SELECT * FROM policy_bundles WHERE id = ?", (engagement["active_policy_id"],)
            ).fetchone()
            policy_document = json.loads(policy["policy_json"])
            decision = evaluate(
                intent,
                policy_document,
                active=policy["activated_at"] is not None,
                revoked=policy["revoked_at"] is not None,
                now=now,
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO policy_evaluations(
                    decision_id, intent_id, engagement_id, policy_bundle_id,
                    intent_json, decision_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision["decision_id"],
                    decision["intent_id"],
                    engagement_id,
                    policy["id"],
                    canonical_json(intent),
                    canonical_json(decision),
                    _timestamp(),
                ),
            )
            self._audit(
                connection,
                action="policy.evaluation",
                subject_type="action_intent",
                subject_id=decision["intent_id"],
                actor_type="service",
                actor_id="policy-evaluator",
                data={
                    "decision_id": decision["decision_id"],
                    "outcome": decision["outcome"],
                    "reason_codes": decision["reason_codes"],
                    "evaluated_rule_ids": decision["evaluated_rule_ids"],
                    "policy_hash": decision["policy_hash"],
                    "intent_hash": content_hash(intent),
                },
            )
            return decision

    def audit_events(self) -> list[dict[str, Any]]:
        with transaction(self.database_path) as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        return [
            {
                "sequence": row["sequence"],
                "event_id": row["event_id"],
                "occurred_at": row["occurred_at"],
                "actor_type": row["actor_type"],
                "actor_id": row["actor_id"],
                "action": row["action"],
                "subject_type": row["subject_type"],
                "subject_id": row["subject_id"],
                "data": json.loads(row["data_json"]),
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        ]

    def verify_audit_chain(self) -> dict[str, Any]:
        events = self.audit_events()
        previous: str | None = None
        for event in events:
            expected = content_hash(
                {
                    "event_id": event["event_id"],
                    "occurred_at": event["occurred_at"],
                    "actor_type": event["actor_type"],
                    "actor_id": event["actor_id"],
                    "action": event["action"],
                    "subject_type": event["subject_type"],
                    "subject_id": event["subject_id"],
                    "data": event["data"],
                    "previous_hash": event["previous_hash"],
                }
            )
            if event["previous_hash"] != previous or event["event_hash"] != expected:
                return {
                    "valid": False,
                    "event_count": len(events),
                    "failed_sequence": event["sequence"],
                }
            previous = event["event_hash"]
        return {"valid": True, "event_count": len(events), "head_hash": previous}
