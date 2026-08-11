from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues

from pentai_core.audit import append_audit_event
from pentai_core.database import transaction
from pentai_core.evidence_store import EncryptedEvidenceStore, EvidenceStoreError

_MAX_BYTES = 2 * 1024 * 1024
_KINDS = {"note", "http_metadata", "response_excerpt", "screenshot", "imported_file", "tool_output"}
_CLASSIFICATIONS = {"internal", "restricted"}
_DERIVATIVE_CLASSIFICATIONS = {"public", "internal"}
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$")
_TEXT_MEDIA_TYPES = {
    "application/json",
    "application/xml",
    "application/xhtml+xml",
}
_REDACTION_REASONS = {"secret", "personal_data", "irrelevant", "operator_selected"}
_PREVIEW_CHARACTERS = 65_536


class EvidenceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class EvidenceService:
    def __init__(
        self,
        database_path: Path,
        store: EncryptedEvidenceStore | None,
        *,
        storage_failure_handler: Callable[[], None] | None = None,
    ) -> None:
        self.database_path = database_path
        self.store = store
        self.storage_failure_handler = storage_failure_handler

    def _storage_failed(self) -> None:
        if self.storage_failure_handler is not None:
            self.storage_failure_handler()

    def create_original(
        self,
        workflow_id: str,
        *,
        content: bytes,
        evidence_kind: str,
        media_type: str,
        classification: str,
        idempotency_key: str,
        actor_id: str,
        execution_trace_id: str | None = None,
    ) -> dict[str, Any]:
        if self.store is None:
            self._storage_failed()
            raise EvidenceError("EVIDENCE_KEY_UNAVAILABLE", "evidence encryption is unavailable")
        if not content or len(content) > _MAX_BYTES:
            raise EvidenceError(
                "EVIDENCE_SIZE_INVALID", "evidence must contain 1 through 2097152 bytes"
            )
        if evidence_kind not in _KINDS:
            raise EvidenceError("EVIDENCE_KIND_INVALID", "evidence kind is invalid")
        if classification not in _CLASSIFICATIONS:
            raise EvidenceError(
                "EVIDENCE_CLASSIFICATION_INVALID", "evidence classification is invalid"
            )
        if not _MEDIA_TYPE.fullmatch(media_type):
            raise EvidenceError("EVIDENCE_MEDIA_TYPE_INVALID", "evidence media type is invalid")
        if not 16 <= len(idempotency_key) <= 128 or not actor_id or len(actor_id) > 128:
            raise EvidenceError("EVIDENCE_IDENTITY_INVALID", "evidence identity is invalid")

        digest = hashlib.sha256(content).hexdigest()
        try:
            storage_ref = self.store.store(content, digest)
        except EvidenceStoreError as exc:
            self._storage_failed()
            raise EvidenceError(
                "EVIDENCE_STORAGE_FAILED", "evidence storage failed closed"
            ) from exc

        created_at = _timestamp()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM evidence_objects WHERE workflow_id = ? AND idempotency_key = ?",
                (workflow_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                document = self._document(existing)
                requested_identity = (
                    digest,
                    evidence_kind,
                    media_type,
                    classification,
                    execution_trace_id,
                )
                stored_identity = (
                    document["sha256"],
                    document["evidence_kind"],
                    document["media_type"],
                    document["classification"],
                    document["execution_trace_id"],
                )
                if stored_identity != requested_identity:
                    raise EvidenceError(
                        "EVIDENCE_IDEMPOTENCY_CONFLICT", "idempotency key was already used"
                    )
                return document
            workflow = connection.execute(
                "SELECT * FROM assessment_workflows WHERE workflow_id = ?", (workflow_id,)
            ).fetchone()
            if workflow is None:
                raise EvidenceError(
                    "EVIDENCE_WORKFLOW_MISSING", "assessment workflow does not exist"
                )
            if workflow["status"] not in {"ready", "running", "paused"}:
                raise EvidenceError(
                    "EVIDENCE_WORKFLOW_DENIED", "workflow state does not permit evidence capture"
                )
            if execution_trace_id is not None:
                trace = connection.execute(
                    """SELECT t.trace_id, i.engagement_id, t.policy_bundle_id
                       FROM execution_traces t JOIN action_intents i ON i.intent_id = t.intent_id
                       WHERE t.trace_id = ?""",
                    (execution_trace_id,),
                ).fetchone()
                if trace is None:
                    raise EvidenceError("EVIDENCE_TRACE_MISSING", "execution trace does not exist")
                if (trace["engagement_id"], trace["policy_bundle_id"]) != (
                    workflow["engagement_id"],
                    workflow["policy_bundle_id"],
                ):
                    raise EvidenceError(
                        "EVIDENCE_TRACE_MISMATCH",
                        "execution trace is outside this workflow authority",
                    )
            evidence_id = str(uuid4())
            document = {
                "schema_version": "1.0.0",
                "evidence_id": evidence_id,
                "workflow_id": workflow_id,
                "engagement_id": workflow["engagement_id"],
                "policy_bundle_id": workflow["policy_bundle_id"],
                "execution_trace_id": execution_trace_id,
                "evidence_kind": evidence_kind,
                "sha256": digest,
                "storage_ref": storage_ref,
                "size_bytes": len(content),
                "media_type": media_type,
                "classification": classification,
                "encryption_version": "aes-256-gcm-hkdf-v1",
                "created_by": actor_id,
                "created_at": created_at,
            }
            self._valid(document, "evidence-original-v1.schema.json")
            connection.execute(
                """INSERT INTO evidence_objects(
                    evidence_id, workflow_id, engagement_id, policy_bundle_id,
                    execution_trace_id, idempotency_key, evidence_kind, sha256,
                    storage_ref, size_bytes, media_type, classification,
                    encryption_version, created_by, created_at, document_json, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evidence_id,
                    workflow_id,
                    workflow["engagement_id"],
                    workflow["policy_bundle_id"],
                    execution_trace_id,
                    idempotency_key,
                    evidence_kind,
                    digest,
                    storage_ref,
                    len(content),
                    media_type,
                    classification,
                    "aes-256-gcm-hkdf-v1",
                    actor_id,
                    created_at,
                    canonical_json(document),
                    content_hash(document),
                ),
            )
            self._custody(connection, evidence_id, "stored", "human", actor_id, created_at)
            append_audit_event(
                connection,
                action="evidence.original_stored",
                subject_type="evidence_object",
                subject_id=evidence_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "workflow_id": workflow_id,
                    "policy_bundle_id": workflow["policy_bundle_id"],
                    "execution_trace_id": execution_trace_id,
                    "evidence_kind": evidence_kind,
                    "sha256": digest,
                    "size_bytes": len(content),
                    "classification": classification,
                },
                occurred_at=created_at,
            )
        return document

    def create_redaction(
        self,
        evidence_id: str,
        *,
        redactions: list[dict[str, Any]],
        classification: str,
        confirm_classification: bool,
        idempotency_key: str,
        actor_id: str,
    ) -> dict[str, Any]:
        if classification not in _DERIVATIVE_CLASSIFICATIONS:
            raise EvidenceError(
                "EVIDENCE_CLASSIFICATION_INVALID",
                "redacted evidence classification is invalid",
            )
        if confirm_classification is not True:
            raise EvidenceError(
                "EVIDENCE_CLASSIFICATION_CONFIRMATION_REQUIRED",
                "a human must confirm the derivative classification",
            )
        if not 16 <= len(idempotency_key) <= 128 or not actor_id or len(actor_id) > 128:
            raise EvidenceError("EVIDENCE_IDENTITY_INVALID", "evidence identity is invalid")
        normalized = self._redactions(redactions)

        with transaction(self.database_path) as connection:
            parent = connection.execute(
                "SELECT * FROM evidence_objects WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
            if parent is None:
                raise EvidenceError("EVIDENCE_NOT_FOUND", "evidence does not exist")
            parent_document = self._document(parent)
            existing = connection.execute(
                """SELECT * FROM evidence_derivatives
                   WHERE parent_evidence_id = ? AND idempotency_key = ?""",
                (evidence_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                document = self._derivative_document(existing)
                if (
                    document["classification"] != classification
                    or document["redactions"] != normalized
                ):
                    raise EvidenceError(
                        "EVIDENCE_IDEMPOTENCY_CONFLICT", "idempotency key was already used"
                    )
                return document
            media_type = str(parent_document["media_type"])
            if not (media_type.startswith("text/") or media_type in _TEXT_MEDIA_TYPES):
                raise EvidenceError(
                    "EVIDENCE_REDACTION_UNSUPPORTED",
                    "this evidence media type cannot be safely redacted",
                )

        source = self.load_original(evidence_id, actor_id=actor_id)
        try:
            text = source.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise EvidenceError(
                "EVIDENCE_REDACTION_UNSUPPORTED", "evidence is not valid UTF-8 text"
            ) from exc
        for item in normalized:
            if item["end"] > len(text):
                raise EvidenceError(
                    "EVIDENCE_REDACTION_RANGE_INVALID", "redaction range is out of bounds"
                )
        redacted = text
        for item in reversed(normalized):
            redacted = redacted[: item["start"]] + "[REDACTED]" + redacted[item["end"] :]
        if redacted == text or not redacted:
            raise EvidenceError(
                "EVIDENCE_REDACTION_INVALID", "redaction must produce changed content"
            )
        self._safe_text(redacted)
        content = redacted.encode("utf-8")
        if len(content) > _MAX_BYTES:
            raise EvidenceError("EVIDENCE_SIZE_INVALID", "redacted evidence is too large")
        if self.store is None:
            self._storage_failed()
            raise EvidenceError("EVIDENCE_KEY_UNAVAILABLE", "evidence encryption is unavailable")
        digest = hashlib.sha256(content).hexdigest()
        try:
            storage_ref = self.store.store(content, digest)
        except EvidenceStoreError as exc:
            self._storage_failed()
            raise EvidenceError(
                "EVIDENCE_STORAGE_FAILED", "evidence storage failed closed"
            ) from exc

        created_at = _timestamp()
        derivative_id = str(uuid4())
        document = {
            "schema_version": "1.0.0",
            "derivative_id": derivative_id,
            "parent_evidence_id": evidence_id,
            "workflow_id": parent_document["workflow_id"],
            "engagement_id": parent_document["engagement_id"],
            "policy_bundle_id": parent_document["policy_bundle_id"],
            "derivative_kind": "redaction",
            "source_sha256": parent_document["sha256"],
            "sha256": digest,
            "storage_ref": storage_ref,
            "size_bytes": len(content),
            "media_type": "text/plain",
            "classification": classification,
            "classification_confirmed_by": actor_id,
            "classification_confirmed_at": created_at,
            "encryption_version": "aes-256-gcm-hkdf-v1",
            "offset_unit": "unicode_codepoints",
            "redactions": normalized,
            "created_by": actor_id,
            "created_at": created_at,
        }
        self._valid(document, "evidence-redaction-v1.schema.json")
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM evidence_objects WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
            if current is None or current["content_hash"] != parent["content_hash"]:
                raise EvidenceError(
                    "EVIDENCE_INTEGRITY_FAILED", "source evidence changed during redaction"
                )
            self._document(current)
            replay = connection.execute(
                """SELECT * FROM evidence_derivatives
                   WHERE parent_evidence_id = ? AND idempotency_key = ?""",
                (evidence_id, idempotency_key),
            ).fetchone()
            if replay is not None:
                replay_document = self._derivative_document(replay)
                if (
                    replay_document["classification"] != classification
                    or replay_document["redactions"] != normalized
                ):
                    raise EvidenceError(
                        "EVIDENCE_IDEMPOTENCY_CONFLICT", "idempotency key was already used"
                    )
                return replay_document
            connection.execute(
                """INSERT INTO evidence_derivatives(
                    derivative_id, parent_evidence_id, workflow_id, engagement_id,
                    policy_bundle_id, idempotency_key, derivative_kind, source_sha256,
                    sha256, storage_ref, size_bytes, media_type, classification,
                    encryption_version, redactions_json, created_by, created_at,
                    document_json, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, 'redaction', ?, ?, ?, ?, 'text/plain', ?,
                          'aes-256-gcm-hkdf-v1', ?, ?, ?, ?, ?)""",
                (
                    derivative_id,
                    evidence_id,
                    parent_document["workflow_id"],
                    parent_document["engagement_id"],
                    parent_document["policy_bundle_id"],
                    idempotency_key,
                    parent_document["sha256"],
                    digest,
                    storage_ref,
                    len(content),
                    classification,
                    canonical_json(normalized),
                    actor_id,
                    created_at,
                    canonical_json(document),
                    content_hash(document),
                ),
            )
            self._derivative_event(
                connection, derivative_id, "stored", "human", actor_id, created_at
            )
            append_audit_event(
                connection,
                action="evidence.redaction_stored",
                subject_type="evidence_derivative",
                subject_id=derivative_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "parent_evidence_id": evidence_id,
                    "policy_bundle_id": parent_document["policy_bundle_id"],
                    "source_sha256": parent_document["sha256"],
                    "sha256": digest,
                    "classification": classification,
                    "redaction_count": len(normalized),
                },
                occurred_at=created_at,
            )
        return document

    def preview_redaction(self, derivative_id: str, *, actor_id: str) -> dict[str, Any]:
        if self.store is None:
            self._storage_failed()
            raise EvidenceError("EVIDENCE_KEY_UNAVAILABLE", "evidence encryption is unavailable")
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM evidence_derivatives WHERE derivative_id = ?", (derivative_id,)
            ).fetchone()
        if row is None:
            raise EvidenceError("EVIDENCE_DERIVATIVE_NOT_FOUND", "redacted evidence does not exist")
        document = self._derivative_document(row)
        try:
            content = self.store.load(str(row["sha256"]))
            text = content.decode("utf-8", errors="strict")
        except (EvidenceStoreError, UnicodeDecodeError) as exc:
            self._storage_failed()
            raise EvidenceError(
                "EVIDENCE_STORAGE_FAILED", "redacted evidence failed authentication"
            ) from exc
        self._safe_text(text)
        previewed_at = _timestamp()
        preview = {
            "schema_version": "1.0.0",
            "derivative_id": derivative_id,
            "classification": document["classification"],
            "sha256": document["sha256"],
            "render_mode": "plain_text",
            "media_type": "text/plain",
            "content": text[:_PREVIEW_CHARACTERS],
            "truncated": len(text) > _PREVIEW_CHARACTERS,
            "active_content_disabled": True,
            "previewed_at": previewed_at,
        }
        self._valid(preview, "evidence-preview-v1.schema.json")
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._derivative_event(
                connection, derivative_id, "previewed", "human", actor_id, previewed_at
            )
            append_audit_event(
                connection,
                action="evidence.redaction_previewed",
                subject_type="evidence_derivative",
                subject_id=derivative_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "sha256": document["sha256"],
                    "classification": document["classification"],
                    "truncated": preview["truncated"],
                    "render_mode": "plain_text",
                },
                occurred_at=previewed_at,
            )
        return preview

    def metadata(self, evidence_id: str, *, actor_id: str) -> dict[str, Any]:
        accessed_at = _timestamp()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM evidence_objects WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
            if row is None:
                raise EvidenceError("EVIDENCE_NOT_FOUND", "evidence does not exist")
            document = self._document(row)
            custody = self._custody(
                connection, evidence_id, "metadata_accessed", "human", actor_id, accessed_at
            )
            append_audit_event(
                connection,
                action="evidence.metadata_accessed",
                subject_type="evidence_object",
                subject_id=evidence_id,
                actor_type="human",
                actor_id=actor_id,
                data={"sha256": document["sha256"], "classification": document["classification"]},
                occurred_at=accessed_at,
            )
        return {"evidence": document, "custody_event": custody}

    def load_original(self, evidence_id: str, *, actor_id: str) -> bytes:
        if self.store is None:
            raise EvidenceError("EVIDENCE_KEY_UNAVAILABLE", "evidence encryption is unavailable")
        with transaction(self.database_path) as connection:
            row = connection.execute(
                "SELECT * FROM evidence_objects WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
        if row is None:
            raise EvidenceError("EVIDENCE_NOT_FOUND", "evidence does not exist")
        try:
            content = self.store.load(str(row["sha256"]))
        except EvidenceStoreError as exc:
            self._storage_failed()
            raise EvidenceError(
                "EVIDENCE_STORAGE_FAILED", "evidence storage failed closed"
            ) from exc
        accessed_at = _timestamp()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._custody(
                connection, evidence_id, "content_accessed", "human", actor_id, accessed_at
            )
            append_audit_event(
                connection,
                action="evidence.content_accessed",
                subject_type="evidence_object",
                subject_id=evidence_id,
                actor_type="human",
                actor_id=actor_id,
                data={"sha256": row["sha256"], "size_bytes": row["size_bytes"]},
                occurred_at=accessed_at,
            )
        return content

    @staticmethod
    def _valid(document: dict[str, Any], schema: str) -> None:
        if contract_issues(document, schema):
            raise EvidenceError("EVIDENCE_CONTRACT_INVALID", "evidence contract is invalid")

    def _document(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            document = json.loads(row["document_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise EvidenceError(
                "EVIDENCE_CONTRACT_INVALID", "evidence contract is invalid"
            ) from exc
        if content_hash(document) != row["content_hash"]:
            raise EvidenceError("EVIDENCE_INTEGRITY_FAILED", "evidence metadata integrity failed")
        self._valid(document, "evidence-original-v1.schema.json")
        return cast(dict[str, Any], document)

    def _derivative_document(self, row: sqlite3.Row) -> dict[str, Any]:
        try:
            document = json.loads(row["document_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise EvidenceError(
                "EVIDENCE_CONTRACT_INVALID", "evidence derivative contract is invalid"
            ) from exc
        if content_hash(document) != row["content_hash"]:
            raise EvidenceError("EVIDENCE_INTEGRITY_FAILED", "evidence derivative integrity failed")
        self._valid(document, "evidence-redaction-v1.schema.json")
        return cast(dict[str, Any], document)

    @staticmethod
    def _redactions(redactions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not isinstance(redactions, list) or not 1 <= len(redactions) <= 256:
            raise EvidenceError(
                "EVIDENCE_REDACTION_INVALID", "one through 256 redactions are required"
            )
        normalized: list[dict[str, Any]] = []
        previous_end = 0
        for item in redactions:
            if not isinstance(item, dict) or set(item) != {"start", "end", "reason"}:
                raise EvidenceError("EVIDENCE_REDACTION_INVALID", "redaction fields are invalid")
            start = item["start"]
            end = item["end"]
            reason = item["reason"]
            if (
                type(start) is not int
                or type(end) is not int
                or start < previous_end
                or start < 0
                or end <= start
                or not isinstance(reason, str)
                or reason not in _REDACTION_REASONS
            ):
                raise EvidenceError(
                    "EVIDENCE_REDACTION_RANGE_INVALID",
                    "redaction ranges must be ordered and non-overlapping",
                )
            normalized.append(
                {"start": start, "end": end, "reason": reason, "replacement": "[REDACTED]"}
            )
            previous_end = end
        return normalized

    @staticmethod
    def _safe_text(content: str) -> None:
        if any(ord(character) < 32 and character not in "\n\r\t" for character in content):
            raise EvidenceError(
                "EVIDENCE_PREVIEW_UNSAFE", "preview contains unsupported control characters"
            )

    def _custody(
        self,
        connection: sqlite3.Connection,
        evidence_id: str,
        action: str,
        actor_type: str,
        actor_id: str,
        occurred_at: str,
    ) -> dict[str, Any]:
        previous = connection.execute(
            """SELECT event_hash FROM evidence_custody_events
               WHERE evidence_id = ? ORDER BY sequence DESC LIMIT 1""",
            (evidence_id,),
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else None
        event_id = str(uuid4())
        payload = {
            "schema_version": "1.0.0",
            "event_id": event_id,
            "evidence_id": evidence_id,
            "action": action,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        event_hash = content_hash(payload)
        cursor = connection.execute(
            """INSERT INTO evidence_custody_events(
                event_id, evidence_id, action, actor_type, actor_id, occurred_at,
                previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                evidence_id,
                action,
                actor_type,
                actor_id,
                occurred_at,
                previous_hash,
                event_hash,
            ),
        )
        event = {**payload, "sequence": cursor.lastrowid, "event_hash": event_hash}
        self._valid(event, "evidence-custody-event-v1.schema.json")
        return event

    def _derivative_event(
        self,
        connection: sqlite3.Connection,
        derivative_id: str,
        action: str,
        actor_type: str,
        actor_id: str,
        occurred_at: str,
    ) -> dict[str, Any]:
        previous = connection.execute(
            """SELECT event_hash FROM evidence_derivative_events
               WHERE derivative_id = ? ORDER BY sequence DESC LIMIT 1""",
            (derivative_id,),
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else None
        event_id = str(uuid4())
        payload = {
            "schema_version": "1.0.0",
            "event_id": event_id,
            "derivative_id": derivative_id,
            "action": action,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        event_hash = content_hash(payload)
        cursor = connection.execute(
            """INSERT INTO evidence_derivative_events(
                event_id, derivative_id, action, actor_type, actor_id, occurred_at,
                previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                derivative_id,
                action,
                actor_type,
                actor_id,
                occurred_at,
                previous_hash,
                event_hash,
            ),
        )
        event = {**payload, "sequence": cursor.lastrowid, "event_hash": event_hash}
        self._valid(event, "evidence-derivative-event-v1.schema.json")
        return event
