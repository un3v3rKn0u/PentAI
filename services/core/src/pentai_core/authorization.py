from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pentai_policy import (
    compile_manifest,
    content_hash,
    evaluate,
    source_content_hash,
    validate_manifest,
)
from pentai_policy.documents import ManifestValidationError, canonical_json

from pentai_core.database import transaction
from pentai_core.migrate import migrate


class AuthorizationError(ValueError):
    """A fail-closed domain transition error."""


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).astimezone(UTC).isoformat().replace("+00:00", "Z")


def _uuid() -> str:
    return str(uuid.uuid4())


class AuthorizationService:
    def __init__(self, database_path: Path):
        self.database_path = database_path
        migrate(database_path)

    def _audit(
        self,
        connection: sqlite3.Connection,
        action: str,
        subject_type: str,
        subject_id: str,
        data: dict[str, Any],
        *,
        actor_id: str,
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        event = {
            "event_id": _uuid(),
            "occurred_at": occurred_at or _iso(),
            "actor_type": "human" if actor_id != "policy-evaluator" else "service",
            "actor_id": actor_id,
            "action": action,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "data": data,
            "previous_hash": previous["event_hash"] if previous else None,
        }
        event["event_hash"] = content_hash(event)
        connection.execute(
            """INSERT INTO audit_events(
                event_id, occurred_at, actor_type, actor_id, action, subject_type,
                subject_id, data_json, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event["event_id"],
                event["occurred_at"],
                event["actor_type"],
                actor_id,
                action,
                subject_type,
                subject_id,
                canonical_json(data),
                event["previous_hash"],
                event["event_hash"],
            ),
        )
        return event

    def create_program(self, name: str, platform: str | None = None) -> dict[str, Any]:
        if not name.strip():
            raise AuthorizationError("program name is required")
        program = {"id": _uuid(), "name": name.strip(), "platform": platform, "status": "draft"}
        with transaction(self.database_path) as connection:
            connection.execute(
                "INSERT INTO programs(id, name, platform, status) VALUES (?, ?, ?, 'draft')",
                (program["id"], program["name"], platform),
            )
        return program

    def import_source(
        self,
        program_id: str,
        *,
        reference: str,
        authority: str,
        content: str,
        retrieved_at: str | None = None,
    ) -> dict[str, Any]:
        if not reference.strip() or not content:
            raise AuthorizationError("source reference and content are required")
        if authority not in {
            "contract",
            "program_staff",
            "program_page",
            "platform_rule",
            "internal_note",
        }:
            raise AuthorizationError("unsupported source authority")
        digest = source_content_hash(content)
        source = {
            "id": _uuid(),
            "program_id": program_id,
            "reference": reference,
            "authority": authority,
            "retrieved_at": retrieved_at or _iso(),
            "content_hash": digest,
            "encrypted_blob_ref": f"sha256:{digest}",
        }
        with transaction(self.database_path) as connection:
            if not connection.execute(
                "SELECT 1 FROM programs WHERE id = ?", (program_id,)
            ).fetchone():
                raise AuthorizationError("program not found")
            connection.execute(
                """INSERT INTO source_documents(
                    id, program_id, authority, reference, retrieved_at,
                    content_hash, encrypted_blob_ref
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    source["id"],
                    program_id,
                    authority,
                    reference,
                    source["retrieved_at"],
                    digest,
                    source["encrypted_blob_ref"],
                ),
            )
        return source

    def create_engagement(self, program_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        engagement = manifest.get("engagement", {})
        engagement_id = engagement.get("id")
        if not engagement_id:
            raise AuthorizationError("manifest engagement.id is required")
        with transaction(self.database_path) as connection:
            connection.execute(
                """INSERT INTO engagements(
                    id, program_id, status, effective_from, expires_at, timezone
                )
                VALUES (?, ?, 'draft', ?, ?, ?)""",
                (
                    engagement_id,
                    program_id,
                    engagement["effective_from"],
                    engagement["expires_at"],
                    engagement["timezone"],
                ),
            )
        return self.save_manifest(engagement_id, manifest)

    def save_manifest(self, engagement_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        validation = validate_manifest(manifest)
        document = validation["canonical_document"]
        digest = validation["content_hash"]
        version_id = _uuid()
        with transaction(self.database_path) as connection:
            prior = connection.execute(
                """SELECT id FROM manifest_versions
                WHERE engagement_id = ?
                ORDER BY created_at DESC, rowid DESC LIMIT 1""",
                (engagement_id,),
            ).fetchone()
            if prior:
                connection.execute(
                    "UPDATE manifest_versions SET validation_status = 'superseded' WHERE id = ?",
                    (prior["id"],),
                )
                connection.execute(
                    """UPDATE approvals SET revoked_at = ?
                    WHERE manifest_version_id = ? AND revoked_at IS NULL
                      AND policy_bundle_id IN (
                        SELECT id FROM policy_bundles
                        WHERE manifest_version_id = ? AND activated_at IS NULL
                      )""",
                    (_iso(), prior["id"], prior["id"]),
                )
            connection.execute(
                """INSERT INTO manifest_versions(
                    id, engagement_id, schema_version, document_json, content_hash,
                    supersedes_id, validation_status, validation_json
                ) VALUES (?, ?, '2.0.0', ?, ?, ?, ?, ?)""",
                (
                    version_id,
                    engagement_id,
                    canonical_json(document),
                    digest,
                    prior["id"] if prior else None,
                    "valid" if validation["valid"] else "invalid",
                    canonical_json(validation),
                ),
            )
        return {"id": version_id, "engagement_id": engagement_id, **validation}

    def compile(self, manifest_version_id: str) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM manifest_versions WHERE id = ?", (manifest_version_id,)
            ).fetchone()
            if not row:
                raise AuthorizationError("manifest version not found")
            if row["validation_status"] != "valid":
                raise AuthorizationError("manifest version is not valid")
            manifest = json.loads(row["document_json"])
            for source in manifest["sources"]:
                persisted = connection.execute(
                    "SELECT content_hash FROM source_documents WHERE id = ?",
                    (source["source_id"],),
                ).fetchone()
                if not persisted or persisted["content_hash"] != source["content_hash"]:
                    raise AuthorizationError("source provenance is missing or altered")
            try:
                policy = compile_manifest(manifest)
            except ManifestValidationError as exc:
                raise AuthorizationError(str(exc)) from exc
            if policy["manifest_hash"] != row["content_hash"]:
                raise AuthorizationError("compiled policy does not match manifest hash")
            policy_id = policy["policy_id"]
            existing = connection.execute(
                "SELECT policy_json FROM policy_bundles WHERE id = ?", (policy_id,)
            ).fetchone()
            if existing:
                return cast(dict[str, Any], json.loads(existing["policy_json"]))
            connection.execute(
                """INSERT INTO policy_bundles(
                    id, engagement_id, manifest_version_id, schema_version, compiler_version,
                    policy_json, content_hash, status
                ) VALUES (?, ?, ?, '1.0.0', '1.0.0', ?, ?, 'awaiting_approval')""",
                (
                    policy_id,
                    row["engagement_id"],
                    manifest_version_id,
                    canonical_json(policy),
                    policy["content_hash"],
                ),
            )
        return policy

    def approve(
        self, policy_id: str, *, approver_id: str, expires_at: str, decision: str = "approved"
    ) -> dict[str, Any]:
        if not approver_id.strip():
            raise AuthorizationError("human approver identity is required")
        if decision not in {"approved", "rejected"}:
            raise AuthorizationError("approval decision must be approved or rejected")
        try:
            approval_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuthorizationError("approval expiry must be an RFC 3339 date-time") from exc
        if approval_expiry.tzinfo is None or approval_expiry.astimezone(UTC) <= _now():
            raise AuthorizationError("approval expiry must be in the future")
        with transaction(self.database_path) as connection:
            row = connection.execute(
                """SELECT pb.*, mv.content_hash AS manifest_hash
                FROM policy_bundles pb JOIN manifest_versions mv ON mv.id = pb.manifest_version_id
                WHERE pb.id = ?""",
                (policy_id,),
            ).fetchone()
            if not row:
                raise AuthorizationError("policy not found")
            if row["status"] != "awaiting_approval" or row["activated_at"] is not None:
                raise AuthorizationError("policy is not awaiting approval")
            decided_at = _iso()
            approval = {
                "schema_version": "1.0.0",
                "approval_id": _uuid(),
                "approval_type": "policy_activation",
                "subject": {"subject_type": "policy", "subject_id": policy_id},
                "assessment_id": None,
                "policy_hash": row["content_hash"],
                "constraints": {},
                "decision": decision,
                "approver": {"actor_type": "human", "actor_id": approver_id},
                "decided_at": decided_at,
                "expires_at": expires_at,
                "signature": {
                    "algorithm": "Ed25519",
                    "key_id": "local-human-review",
                    "value": content_hash(
                        [
                            approver_id,
                            row["manifest_hash"],
                            row["content_hash"],
                            decision,
                            decided_at,
                            expires_at,
                        ]
                    ),
                },
            }
            connection.execute(
                """INSERT INTO approvals(
                    id, approval_type, policy_bundle_id, manifest_version_id, manifest_hash,
                    policy_hash, decision, approver_actor_id, decided_at, expires_at, signature_json
                ) VALUES (?, 'policy_activation', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    approval["approval_id"],
                    policy_id,
                    row["manifest_version_id"],
                    row["manifest_hash"],
                    row["content_hash"],
                    decision,
                    approver_id,
                    decided_at,
                    expires_at,
                    canonical_json(approval["signature"]),
                ),
            )
            action = "approval" if decision == "approved" else "rejection"
            connection.execute(
                "UPDATE policy_bundles SET status = ? WHERE id = ?",
                ("awaiting_approval" if decision == "approved" else "rejected", policy_id),
            )
            self._audit(
                connection,
                action,
                "policy",
                policy_id,
                {
                    "approval_id": approval["approval_id"],
                    "manifest_hash": row["manifest_hash"],
                    "policy_hash": row["content_hash"],
                    "decision": decision,
                },
                actor_id=approver_id,
                occurred_at=decided_at,
            )
        return approval

    def activate(self, policy_id: str, *, actor_id: str) -> dict[str, Any]:
        instant = _iso()
        with transaction(self.database_path) as connection:
            row = connection.execute(
                """SELECT pb.*, mv.content_hash AS manifest_hash, mv.document_json
                FROM policy_bundles pb JOIN manifest_versions mv ON mv.id = pb.manifest_version_id
                WHERE pb.id = ?""",
                (policy_id,),
            ).fetchone()
            if not row:
                raise AuthorizationError("policy not found")
            if row["status"] != "awaiting_approval" or row["activated_at"] is not None:
                raise AuthorizationError("policy is not eligible for activation")
            policy = json.loads(row["policy_json"])
            material = dict(policy)
            stored_hash = material.pop("content_hash", "")
            if content_hash(material) != stored_hash or stored_hash != row["content_hash"]:
                raise AuthorizationError("policy integrity check failed")
            if (
                content_hash(json.loads(row["document_json"])) != row["manifest_hash"]
                or policy["manifest_hash"] != row["manifest_hash"]
            ):
                raise AuthorizationError("manifest integrity check failed")
            approval = connection.execute(
                """SELECT * FROM approvals
                WHERE policy_bundle_id = ?
                  AND approval_type = 'policy_activation'
                  AND decision = 'approved'
                  AND revoked_at IS NULL
                ORDER BY decided_at DESC LIMIT 1""",
                (policy_id,),
            ).fetchone()
            if not approval:
                raise AuthorizationError("valid human policy_activation approval is required")
            if (
                approval["policy_hash"] != stored_hash
                or approval["manifest_hash"] != row["manifest_hash"]
            ):
                raise AuthorizationError("approval is not bound to exact artifacts")
            if _now() >= datetime.fromisoformat(approval["expires_at"].replace("Z", "+00:00")):
                raise AuthorizationError("approval has expired")
            latest = connection.execute(
                """SELECT id FROM manifest_versions WHERE engagement_id = ?
                ORDER BY created_at DESC, rowid DESC LIMIT 1""",
                (row["engagement_id"],),
            ).fetchone()
            if not latest or latest["id"] != row["manifest_version_id"]:
                raise AuthorizationError("approval was superseded by a newer manifest version")
            active = connection.execute(
                """SELECT 1 FROM policy_bundles WHERE engagement_id = ?
                AND status = 'active' AND revoked_at IS NULL""",
                (row["engagement_id"],),
            ).fetchone()
            if active:
                raise AuthorizationError("engagement already has an active policy")
            connection.execute(
                "UPDATE policy_bundles SET activated_at = ?, status = 'active' WHERE id = ?",
                (instant, policy_id),
            )
            connection.execute(
                "UPDATE engagements SET active_policy_id = ?, status = 'active' WHERE id = ?",
                (policy_id, row["engagement_id"]),
            )
            self._audit(
                connection,
                "activation",
                "policy",
                policy_id,
                {
                    "manifest_hash": row["manifest_hash"],
                    "policy_hash": stored_hash,
                    "approval_id": approval["id"],
                },
                actor_id=actor_id,
                occurred_at=instant,
            )
        return {"policy_id": policy_id, "status": "active", "activated_at": instant}

    def revoke(self, policy_id: str, *, actor_id: str) -> dict[str, Any]:
        instant = _iso()
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM policy_bundles WHERE id = ?", (policy_id,)
            ).fetchone()
            if not row:
                raise AuthorizationError("policy not found")
            if row["status"] != "active" or row["revoked_at"] is not None:
                raise AuthorizationError("only an active policy can be revoked")
            connection.execute(
                "UPDATE policy_bundles SET revoked_at = ?, status = 'revoked' WHERE id = ?",
                (instant, policy_id),
            )
            connection.execute(
                """UPDATE engagements
                SET active_policy_id = NULL, status = 'revoked',
                    revocation_epoch = revocation_epoch + 1
                WHERE id = ?""",
                (row["engagement_id"],),
            )
            connection.execute(
                """UPDATE approvals SET revoked_at = ?
                WHERE policy_bundle_id = ? AND revoked_at IS NULL""",
                (instant, policy_id),
            )
            self._audit(
                connection,
                "revocation",
                "policy",
                policy_id,
                {"policy_hash": row["content_hash"]},
                actor_id=actor_id,
                occurred_at=instant,
            )
        return {"policy_id": policy_id, "status": "revoked", "revoked_at": instant}

    def evaluate_intent(
        self, policy_id: str, intent: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM policy_bundles WHERE id = ?", (policy_id,)
            ).fetchone()
            if not row:
                raise AuthorizationError("policy not found")
            decision = evaluate(
                json.loads(row["policy_json"]),
                intent,
                active=row["status"] == "active",
                revoked=row["revoked_at"] is not None,
                now=now,
            )
            self._audit(
                connection,
                "policy_evaluation",
                "action_intent",
                intent["intent_id"],
                {
                    "policy_id": policy_id,
                    "policy_hash": row["content_hash"],
                    "outcome": decision["outcome"],
                    "reason_codes": decision["reason_codes"],
                    "evaluated_rule_ids": decision["evaluated_rule_ids"],
                },
                actor_id="policy-evaluator",
                occurred_at=decision["decided_at"],
            )
        return decision

    def audit_events(self) -> list[dict[str, Any]]:
        with transaction(self.database_path) as connection:
            return [
                dict(row) | {"data": json.loads(row["data_json"])}
                for row in connection.execute("SELECT * FROM audit_events ORDER BY sequence")
            ]

    def verify_audit_chain(self) -> dict[str, Any]:
        events = self.audit_events()
        previous = None
        for event in events:
            material = {
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
            if event["previous_hash"] != previous or content_hash(material) != event["event_hash"]:
                return {"valid": False, "broken_sequence": event["sequence"]}
            previous = event["event_hash"]
        return {"valid": True, "event_count": len(events), "head_hash": previous}
