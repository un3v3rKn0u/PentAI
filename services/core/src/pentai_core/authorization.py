from __future__ import annotations

import hashlib
import json
import math
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path, PurePath
from typing import Any, Protocol
from urllib.parse import urljoin
from uuid import uuid4

from pentai_policy import (
    CanonicalizationError,
    canonical_json,
    canonicalize_url,
    compile_manifest,
    content_hash,
    evaluate,
    validate_and_canonicalize_manifest,
)
from pentai_policy.document import contract_issues, parse_time

from pentai_core.controlled_dns import ControlledDnsError, ControlledResolver
from pentai_core.database import transaction
from pentai_core.network_attestation import AttestationError, NetworkAttestor
from pentai_core.network_control import authorize_destination, validate_attestation
from pentai_core.policy_signing import PolicySigner
from pentai_core.source_store import EncryptedSourceStore, SourceStoreError

_SOURCE_AUTHORITIES = {
    "contract",
    "program_staff",
    "program_page",
    "platform_rule",
    "internal_note",
}
_SOURCE_KINDS = {"pasted_text", "file", "url"}
_MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
_FILE_MEDIA_EXTENSIONS = {
    "application/json": {".json"},
    "application/pdf": {".pdf"},
    "text/html": {".htm", ".html"},
    "text/markdown": {".markdown", ".md"},
    "text/plain": {".txt"},
}


class DomainError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ControlledResolverSource(Protocol):
    def for_assessment(self, assessment_id: str) -> ControlledResolver: ...


def _now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _grant_payload(document: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    return b"pentai-action-grant-v1:" + canonical_json(unsigned).encode()


def _intent_target_digest(intent: dict[str, Any]) -> str:
    return content_hash(
        {
            "target": intent.get("target"),
            "http": intent.get("http"),
            "account_reference": intent.get("account_reference"),
        }
    )


def _canonical_registered_sources(values: list[str], *, version: int) -> tuple[str, ...]:
    if len(values) > 16 or any(not isinstance(value, str) or "%" in value for value in values):
        raise DomainError("NETWORK_PROFILE_SOURCE_INVALID", "registered source IP is invalid")
    try:
        addresses = tuple(sorted({ip_address(value).compressed for value in values}))
        parsed = tuple(ip_address(value) for value in addresses)
    except ValueError as exc:
        raise DomainError(
            "NETWORK_PROFILE_SOURCE_INVALID", "registered source IP is invalid"
        ) from exc
    if any(
        address.version != version or not address.is_global or address.is_multicast
        for address in parsed
    ):
        raise DomainError("NETWORK_PROFILE_SOURCE_INVALID", "registered source IP is invalid")
    return addresses


def _network_profile_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "profile_id": row["profile_id"],
        "proposal_id": row["proposal_id"],
        "route_profile_id": row["route_profile_id"],
        "route_interface": row["route_interface"],
        "route_gateway": row["route_gateway"],
        "resolver_mode": row["resolver_mode"],
        "resolver_id": row["resolver_id"],
        "resolver_addresses": json.loads(row["resolver_addresses_json"]),
        "registered_source_ipv4": json.loads(row["registered_source_ipv4_json"]),
        "registered_source_ipv6": json.loads(row["registered_source_ipv6_json"]),
        "ipv6_mode": row["ipv6_mode"],
        "status": row["status"],
        "confirmed_by": row["confirmed_by"],
        "confirmed_at": row["confirmed_at"],
        "revoked_at": row["revoked_at"],
        "revocation_reason": row["revocation_reason"],
        "execution_enabled": False,
    }


class AuthorizationService:
    def __init__(
        self,
        database_path: Path,
        *,
        source_store: EncryptedSourceStore | None = None,
        policy_signer: PolicySigner | None = None,
    ) -> None:
        self.database_path = database_path
        self.source_store = source_store
        self.policy_signer = policy_signer

    @staticmethod
    def _reserve_rate_bucket(
        connection: sqlite3.Connection,
        *,
        engagement_id: str,
        policy_bundle_id: str,
        bucket_key: str,
        refill_rate: float,
        capacity: int,
        reserved_at: datetime,
    ) -> None:
        row = connection.execute(
            """
            SELECT * FROM gateway_rate_buckets
            WHERE engagement_id = ? AND bucket_key = ?
            """,
            (engagement_id, bucket_key),
        ).fetchone()
        if row is None or row["policy_bundle_id"] != policy_bundle_id:
            tokens = float(capacity)
        else:
            updated_at = parse_time(row["updated_at"])
            if reserved_at < updated_at:
                raise DomainError("CLOCK_UNTRUSTED", "rate limiter clock moved backward")
            elapsed = (reserved_at - updated_at).total_seconds()
            tokens = min(float(capacity), float(row["tokens"]) + elapsed * refill_rate)
        if tokens + 1e-9 < 1:
            raise DomainError("RATE_LIMITED", "gateway request rate is exhausted")
        connection.execute(
            """
            INSERT INTO gateway_rate_buckets(
                engagement_id, bucket_key, policy_bundle_id, refill_rate,
                capacity, tokens, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, bucket_key) DO UPDATE SET
                policy_bundle_id = excluded.policy_bundle_id,
                refill_rate = excluded.refill_rate,
                capacity = excluded.capacity,
                tokens = excluded.tokens,
                updated_at = excluded.updated_at
            """,
            (
                engagement_id,
                bucket_key,
                policy_bundle_id,
                refill_rate,
                capacity,
                tokens - 1,
                _timestamp(reserved_at),
            ),
        )

    @staticmethod
    def _release_rate_reservation(
        connection: sqlite3.Connection, *, reservation_id: str, finalized_at: datetime
    ) -> None:
        row = connection.execute(
            """
            SELECT * FROM gateway_rate_reservations
            WHERE reservation_id = ? AND status = 'reserved'
            """,
            (reservation_id,),
        ).fetchone()
        if row is None:
            return
        for bucket_key in ("global", f"host:{row['host_key']}"):
            bucket = connection.execute(
                """
                SELECT * FROM gateway_rate_buckets
                WHERE engagement_id = ? AND bucket_key = ?
                """,
                (row["engagement_id"], bucket_key),
            ).fetchone()
            if bucket is None or bucket["policy_bundle_id"] != row["policy_bundle_id"]:
                raise DomainError("RATE_STATE_INVALID", "rate reservation bucket is missing")
            updated_at = parse_time(bucket["updated_at"])
            effective_time = max(finalized_at, updated_at)
            elapsed = (effective_time - updated_at).total_seconds()
            tokens = min(
                float(bucket["capacity"]),
                float(bucket["tokens"]) + elapsed * float(bucket["refill_rate"]) + 1,
            )
            connection.execute(
                """
                UPDATE gateway_rate_buckets SET tokens = ?, updated_at = ?
                WHERE engagement_id = ? AND bucket_key = ?
                """,
                (tokens, _timestamp(effective_time), row["engagement_id"], bucket_key),
            )
        connection.execute(
            """
            UPDATE gateway_rate_reservations
            SET status = 'released', finalized_at = ?
            WHERE reservation_id = ? AND status = 'reserved'
            """,
            (_timestamp(finalized_at), reservation_id),
        )

    @staticmethod
    def _abort_gateway_sessions(
        connection: sqlite3.Connection, *, finalized_at: str, engagement_id: str | None = None
    ) -> int:
        committed = connection.execute(
            """
            SELECT br.engagement_id, COUNT(*) AS amount
            FROM gateway_request_starts grs
            JOIN gateway_sessions gs ON gs.session_id = grs.session_id
            JOIN budget_reservations br ON br.reservation_id = gs.reservation_id
            WHERE grs.status = 'committed' AND gs.status = 'prepared'
              AND (? IS NULL OR br.engagement_id = ?)
            GROUP BY br.engagement_id
            """,
            (engagement_id, engagement_id),
        ).fetchall()
        for row in committed:
            connection.execute(
                """
                UPDATE budget_accounts
                SET active_connections = active_connections - ?, updated_at = ?
                WHERE engagement_id = ?
                """,
                (row["amount"], finalized_at, row["engagement_id"]),
            )
        if engagement_id is None:
            cancelled = connection.execute(
                """
                UPDATE gateway_request_starts
                SET status = 'cancelled', finalized_at = ?
                WHERE status = 'committed'
                """,
                (finalized_at,),
            ).rowcount
            connection.execute(
                """
                UPDATE gateway_sessions SET status = 'aborted', finalized_at = ?
                WHERE status = 'prepared' AND session_id IN (
                    SELECT session_id FROM gateway_request_starts
                    WHERE status = 'cancelled'
                )
                """,
                (finalized_at,),
            )
        else:
            cancelled = connection.execute(
                """
                UPDATE gateway_request_starts
                SET status = 'cancelled', finalized_at = ?
                WHERE status = 'committed' AND reservation_id IN (
                    SELECT reservation_id FROM budget_reservations
                    WHERE engagement_id = ?
                )
                """,
                (finalized_at, engagement_id),
            ).rowcount
            connection.execute(
                """
                UPDATE gateway_sessions SET status = 'aborted', finalized_at = ?
                WHERE status = 'prepared' AND session_id IN (
                    SELECT session_id FROM gateway_request_starts
                    WHERE status = 'cancelled'
                ) AND reservation_id IN (
                    SELECT reservation_id FROM budget_reservations
                    WHERE engagement_id = ?
                )
                """,
                (finalized_at, engagement_id),
            )
        rate_rows = connection.execute(
            """
            SELECT gs.reservation_id FROM gateway_sessions gs
            JOIN budget_reservations br ON br.reservation_id = gs.reservation_id
            WHERE gs.status = 'prepared'
              AND NOT EXISTS (
                  SELECT 1 FROM gateway_request_starts grs WHERE grs.session_id = gs.session_id
              )
              AND (? IS NULL OR br.engagement_id = ?)
            """,
            (engagement_id, engagement_id),
        ).fetchall()
        finalized = parse_time(finalized_at)
        for rate_row in rate_rows:
            AuthorizationService._release_rate_reservation(
                connection,
                reservation_id=rate_row["reservation_id"],
                finalized_at=finalized,
            )
        if engagement_id is None:
            rows = connection.execute(
                """
                SELECT br.engagement_id, COUNT(*) AS amount
                FROM gateway_sessions gs
                JOIN budget_reservations br ON br.reservation_id = gs.reservation_id
                WHERE gs.status = 'prepared'
                  AND NOT EXISTS (
                      SELECT 1 FROM gateway_request_starts grs
                      WHERE grs.session_id = gs.session_id
                  )
                GROUP BY br.engagement_id
                """
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT br.engagement_id, COUNT(*) AS amount
                FROM gateway_sessions gs
                JOIN budget_reservations br ON br.reservation_id = gs.reservation_id
                WHERE gs.status = 'prepared' AND br.engagement_id = ?
                  AND NOT EXISTS (
                      SELECT 1 FROM gateway_request_starts grs
                      WHERE grs.session_id = gs.session_id
                  )
                GROUP BY br.engagement_id
                """,
                (engagement_id,),
            ).fetchall()
        for row in rows:
            connection.execute(
                """
                UPDATE budget_accounts
                SET reserved_requests = reserved_requests - ?,
                    active_connections = active_connections - ?, updated_at = ?
                WHERE engagement_id = ?
                """,
                (row["amount"], row["amount"], finalized_at, row["engagement_id"]),
            )
        if engagement_id is None:
            connection.execute(
                """
                UPDATE budget_reservations SET status = 'released', finalized_at = ?
                WHERE status = 'reserved'
                """,
                (finalized_at,),
            )
            return cancelled + connection.execute(
                """
                UPDATE gateway_sessions SET status = 'aborted', finalized_at = ?
                WHERE status = 'prepared'
                """,
                (finalized_at,),
            ).rowcount
        connection.execute(
            """
            UPDATE budget_reservations SET status = 'released', finalized_at = ?
            WHERE status = 'reserved' AND engagement_id = ?
            """,
            (finalized_at, engagement_id),
        )
        return cancelled + connection.execute(
            """
            UPDATE gateway_sessions SET status = 'aborted', finalized_at = ?
            WHERE status = 'prepared' AND reservation_id IN (
                SELECT reservation_id FROM budget_reservations WHERE engagement_id = ?
            )
            """,
            (finalized_at, engagement_id),
        ).rowcount

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

    def create_program(
        self,
        name: str,
        platform: str | None = None,
        *,
        program_url: str | None = None,
        actor_id: str = "local-session",
    ) -> dict[str, Any]:
        if not name.strip():
            raise DomainError("PROGRAM_NAME_REQUIRED", "program name is required")
        if program_url is not None and not program_url.strip():
            raise DomainError("PROGRAM_URL_INVALID", "program URL cannot be blank")
        program_id = str(uuid4())
        with transaction(self.database_path) as connection:
            connection.execute(
                """
                INSERT INTO programs(id, name, platform, program_url, status)
                VALUES (?, ?, ?, ?, 'draft')
                """,
                (program_id, name.strip(), platform, program_url),
            )
            self._audit(
                connection,
                action="program.created",
                subject_type="program",
                subject_id=program_id,
                actor_type="human",
                actor_id=actor_id,
                data={"name": name.strip(), "platform": platform, "program_url": program_url},
            )
        return {
            "id": program_id,
            "name": name.strip(),
            "platform": platform,
            "program_url": program_url,
            "status": "draft",
            "version": 1,
        }

    def list_programs(self) -> list[dict[str, Any]]:
        with transaction(self.database_path) as connection:
            rows = connection.execute(
                """
                SELECT id, name, platform, program_url, status, created_at, updated_at, version
                FROM programs ORDER BY created_at, id
                """
            ).fetchall()
        return [dict(row) for row in rows]

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
        source_kind: str = "pasted_text",
        media_type: str = "text/plain",
        source_version: str | None = None,
        actor_id: str = "local-session",
    ) -> dict[str, Any]:
        if not content.strip():
            raise DomainError("SOURCE_EMPTY", "source content is required")
        if authority not in _SOURCE_AUTHORITIES:
            raise DomainError("SOURCE_AUTHORITY_INVALID", "source authority is not supported")
        if source_kind not in _SOURCE_KINDS:
            raise DomainError("SOURCE_KIND_INVALID", "source kind is not supported")
        if source_kind != "pasted_text":
            raise DomainError(
                "SOURCE_ACQUISITION_REQUIRED",
                "file and URL sources must be acquired by a dedicated safe importer",
            )
        if not reference.strip():
            raise DomainError("SOURCE_REFERENCE_REQUIRED", "source reference is required")
        if not media_type.strip():
            raise DomainError("SOURCE_MEDIA_TYPE_REQUIRED", "source media type is required")
        if effective_at is not None:
            try:
                effective_at = _timestamp(parse_time(effective_at))
            except ValueError as exc:
                raise DomainError(
                    "SOURCE_EFFECTIVE_AT_INVALID", "source effective time is invalid"
                ) from exc
        return self._persist_source(
            program_id,
            authority=authority,
            reference=reference.strip(),
            content_bytes=content.encode(),
            effective_at=effective_at,
            source_kind="pasted_text",
            media_type=media_type.strip().lower(),
            source_version=source_version,
            actor_id=actor_id,
        )

    def import_file_source(
        self,
        program_id: str,
        *,
        authority: str,
        filename: str,
        content: bytes,
        media_type: str,
        effective_at: str | None = None,
        source_version: str | None = None,
        actor_id: str = "local-session",
    ) -> dict[str, Any]:
        normalized_filename = filename.strip()
        if (
            not normalized_filename
            or len(normalized_filename) > 255
            or "\x00" in normalized_filename
            or "/" in normalized_filename
            or "\\" in normalized_filename
            or PurePath(normalized_filename).name != normalized_filename
            or normalized_filename in {".", ".."}
        ):
            raise DomainError("SOURCE_FILENAME_INVALID", "source filename is invalid")
        if not content:
            raise DomainError("SOURCE_EMPTY", "source content is required")
        if len(content) > _MAX_SOURCE_FILE_BYTES:
            raise DomainError("SOURCE_TOO_LARGE", "source file exceeds the 2 MiB limit")
        normalized_media_type = media_type.strip().lower()
        allowed_extensions = _FILE_MEDIA_EXTENSIONS.get(normalized_media_type)
        extension = PurePath(normalized_filename).suffix.lower()
        if allowed_extensions is None or extension not in allowed_extensions:
            raise DomainError(
                "SOURCE_MEDIA_TYPE_INVALID",
                "source media type and filename extension are not an approved pair",
            )
        if normalized_media_type == "application/pdf":
            if not content.startswith(b"%PDF-"):
                raise DomainError("SOURCE_CONTENT_INVALID", "PDF source signature is invalid")
        else:
            if b"\x00" in content:
                raise DomainError("SOURCE_CONTENT_INVALID", "text source contains binary data")
            try:
                decoded = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DomainError("SOURCE_ENCODING_INVALID", "text source must be UTF-8") from exc
            if normalized_media_type == "application/json":
                try:
                    json.loads(decoded)
                except json.JSONDecodeError as exc:
                    raise DomainError("SOURCE_CONTENT_INVALID", "JSON source is malformed") from exc
        if authority not in _SOURCE_AUTHORITIES:
            raise DomainError("SOURCE_AUTHORITY_INVALID", "source authority is not supported")
        if effective_at is not None:
            try:
                effective_at = _timestamp(parse_time(effective_at))
            except ValueError as exc:
                raise DomainError(
                    "SOURCE_EFFECTIVE_AT_INVALID", "source effective time is invalid"
                ) from exc
        return self._persist_source(
            program_id,
            authority=authority,
            reference=f"file:{normalized_filename}",
            content_bytes=content,
            effective_at=effective_at,
            source_kind="file",
            media_type=normalized_media_type,
            source_version=source_version,
            actor_id=actor_id,
        )

    def import_url_source(
        self,
        program_id: str,
        *,
        authority: str,
        url: str,
        content: bytes,
        media_type: str,
        effective_at: str | None = None,
        source_version: str | None = None,
        actor_id: str = "local-session",
    ) -> dict[str, Any]:
        if authority not in _SOURCE_AUTHORITIES:
            raise DomainError("SOURCE_AUTHORITY_INVALID", "source authority is not supported")
        if not content:
            raise DomainError("SOURCE_EMPTY", "source content is required")
        if len(content) > _MAX_SOURCE_FILE_BYTES:
            raise DomainError("SOURCE_TOO_LARGE", "source response exceeds the 2 MiB limit")
        normalized_media_type = media_type.strip().lower()
        if normalized_media_type == "application/pdf":
            if not content.startswith(b"%PDF-"):
                raise DomainError("SOURCE_CONTENT_INVALID", "PDF source signature is invalid")
        else:
            if normalized_media_type not in _FILE_MEDIA_EXTENSIONS or b"\x00" in content:
                raise DomainError("SOURCE_CONTENT_INVALID", "source content is invalid")
            try:
                decoded = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DomainError("SOURCE_ENCODING_INVALID", "text source must be UTF-8") from exc
            if normalized_media_type == "application/json":
                try:
                    json.loads(decoded)
                except json.JSONDecodeError as exc:
                    raise DomainError("SOURCE_CONTENT_INVALID", "JSON source is malformed") from exc
        if effective_at is not None:
            try:
                effective_at = _timestamp(parse_time(effective_at))
            except ValueError as exc:
                raise DomainError(
                    "SOURCE_EFFECTIVE_AT_INVALID", "source effective time is invalid"
                ) from exc
        return self._persist_source(
            program_id,
            authority=authority,
            reference=url,
            content_bytes=content,
            effective_at=effective_at,
            source_kind="url",
            media_type=normalized_media_type,
            source_version=source_version,
            actor_id=actor_id,
        )

    def _persist_source(
        self,
        program_id: str,
        *,
        authority: str,
        reference: str,
        content_bytes: bytes,
        effective_at: str | None,
        source_kind: str,
        media_type: str,
        source_version: str | None,
        actor_id: str,
    ) -> dict[str, Any]:
        source_id = str(uuid4())
        digest = hashlib.sha256(content_bytes).hexdigest()
        retrieved_at = _timestamp()
        with transaction(self.database_path) as connection:
            program = connection.execute(
                "SELECT id FROM programs WHERE id = ?", (program_id,)
            ).fetchone()
            if program is None:
                raise DomainError("PROGRAM_NOT_FOUND", "program does not exist")
            if self.source_store is None:
                raise DomainError(
                    "SOURCE_STORAGE_UNAVAILABLE", "encrypted source storage is unavailable"
                )
            try:
                blob_reference = self.source_store.store(content_bytes, digest)
            except SourceStoreError as exc:
                raise DomainError("SOURCE_STORAGE_FAILED", str(exc)) from exc
            existing = connection.execute(
                """
                SELECT * FROM source_documents
                WHERE program_id = ? AND authority = ? AND reference = ? AND content_hash = ?
                """,
                (program_id, authority, reference, digest),
            ).fetchone()
            if existing is not None:
                return self._source_record(existing)
            try:
                connection.execute(
                    """
                    INSERT INTO source_documents(
                        id, program_id, authority, reference, retrieved_at, effective_at,
                        content_hash, encrypted_blob_ref, metadata_json, source_kind,
                        media_type, source_version, blob_status, encryption_version,
                        plaintext_size
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, 'available',
                              'aes-256-gcm-v1', ?)
                    """,
                    (
                        source_id,
                        program_id,
                        authority,
                        reference.strip(),
                        retrieved_at,
                        effective_at,
                        digest,
                        blob_reference,
                        source_kind,
                        media_type.strip().lower(),
                        source_version,
                        len(content_bytes),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError(
                    "SOURCE_PERSISTENCE_FAILED", "source could not be stored"
                ) from exc
            record = {
                "id": source_id,
                "program_id": program_id,
                "authority": authority,
                "reference": reference.strip(),
                "retrieved_at": retrieved_at,
                "effective_at": effective_at,
                "content_hash": digest,
                "source_kind": source_kind,
                "media_type": media_type.strip().lower(),
                "source_version": source_version,
                "blob_status": "available",
                "encryption_version": "aes-256-gcm-v1",
                "plaintext_size": len(content_bytes),
            }
            self._audit(
                connection,
                action="source.imported",
                subject_type="source_document",
                subject_id=source_id,
                actor_type="human",
                actor_id=actor_id,
                data={key: value for key, value in record.items() if key != "id"},
                occurred_at=retrieved_at,
            )
        return record

    @staticmethod
    def _source_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "program_id": row["program_id"],
            "authority": row["authority"],
            "reference": row["reference"],
            "retrieved_at": row["retrieved_at"],
            "effective_at": row["effective_at"],
            "content_hash": row["content_hash"],
            "source_kind": row["source_kind"],
            "media_type": row["media_type"],
            "source_version": row["source_version"],
            "blob_status": row["blob_status"],
            "encryption_version": row["encryption_version"],
            "plaintext_size": row["plaintext_size"],
        }

    def list_sources(self, program_id: str) -> list[dict[str, Any]]:
        with transaction(self.database_path) as connection:
            if (
                connection.execute("SELECT 1 FROM programs WHERE id = ?", (program_id,)).fetchone()
                is None
            ):
                raise DomainError("PROGRAM_NOT_FOUND", "program does not exist")
            rows = connection.execute(
                """
                SELECT * FROM source_documents
                WHERE program_id = ? ORDER BY retrieved_at, id
                """,
                (program_id,),
            ).fetchall()
        return [self._source_record(row) for row in rows]

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
                SELECT id, content_hash, version_number FROM manifest_versions
                WHERE engagement_id = ? ORDER BY version_number DESC LIMIT 1
                """,
                (engagement_id,),
            ).fetchone()
            if previous is not None and previous["content_hash"] == digest:
                existing = connection.execute(
                    "SELECT * FROM manifest_versions WHERE id = ?", (previous["id"],)
                ).fetchone()
                return self._manifest_record(existing)
            manifest_id = str(uuid4())
            issues = [issue.as_dict() for issue in validation.issues]
            connection.execute(
                """
                INSERT INTO manifest_versions(
                    id, engagement_id, schema_version, document_json, content_hash,
                    supersedes_id, version_number, validation_status, validation_issues_json
                ) VALUES (?, ?, '2.0.0', ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest_id,
                    engagement_id,
                    canonical_json(canonical),
                    digest,
                    previous["id"] if previous else None,
                    (previous["version_number"] + 1) if previous else 1,
                    "valid" if validation.valid else "invalid",
                    canonical_json(issues),
                ),
            )
            row = connection.execute(
                "SELECT * FROM manifest_versions WHERE id = ?", (manifest_id,)
            ).fetchone()
            return self._manifest_record(row)

    @staticmethod
    def _manifest_record(row: sqlite3.Row) -> dict[str, Any]:
        status = row["validation_status"]
        return {
            "id": row["id"],
            "engagement_id": row["engagement_id"],
            "schema_version": row["schema_version"],
            "version_number": row["version_number"],
            "content_hash": row["content_hash"],
            "document": json.loads(row["document_json"]),
            "valid": status == "valid",
            "validation_status": status,
            "issues": json.loads(row["validation_issues_json"]),
            "supersedes_id": row["supersedes_id"],
            "created_at": row["created_at"],
        }

    def list_manifests(self, engagement_id: str) -> list[dict[str, Any]]:
        with transaction(self.database_path) as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM engagements WHERE id = ?", (engagement_id,)
                ).fetchone()
                is None
            ):
                raise DomainError("ENGAGEMENT_NOT_FOUND", "engagement does not exist")
            rows = connection.execute(
                """SELECT * FROM manifest_versions WHERE engagement_id = ?
                ORDER BY version_number DESC""",
                (engagement_id,),
            ).fetchall()
        return [self._manifest_record(row) for row in rows]

    def manifest_diff(
        self, engagement_id: str, from_manifest_id: str, to_manifest_id: str
    ) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            rows = connection.execute(
                """SELECT * FROM manifest_versions
                WHERE engagement_id = ? AND id IN (?, ?)""",
                (engagement_id, from_manifest_id, to_manifest_id),
            ).fetchall()
        by_id = {row["id"]: row for row in rows}
        if from_manifest_id not in by_id or to_manifest_id not in by_id:
            raise DomainError("MANIFEST_NOT_FOUND", "manifest does not exist in this engagement")
        before = json.loads(by_id[from_manifest_id]["document_json"])
        after = json.loads(by_id[to_manifest_id]["document_json"])
        sections = (
            "scope",
            "techniques",
            "operational_limits",
            "network",
            "data_handling",
            "reporting",
            "agent_controls",
            "unresolved_questions",
        )
        changes = [
            {"section": section, "before": before.get(section), "after": after.get(section)}
            for section in sections
            if before.get(section) != after.get(section)
        ]
        return {
            "from": {
                "id": from_manifest_id,
                "version_number": by_id[from_manifest_id]["version_number"],
                "content_hash": by_id[from_manifest_id]["content_hash"],
            },
            "to": {
                "id": to_manifest_id,
                "version_number": by_id[to_manifest_id]["version_number"],
                "content_hash": by_id[to_manifest_id]["content_hash"],
            },
            "changed_sections": [change["section"] for change in changes],
            "changes": changes,
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
                if self.policy_signer is None:
                    rejection_code = "POLICY_SIGNER_UNAVAILABLE"
                    self._audit(
                        connection,
                        action="policy.rejected",
                        subject_type="manifest",
                        subject_id=manifest_version_id,
                        actor_type="service",
                        actor_id="policy-compiler",
                        data={"reason_codes": [rejection_code]},
                    )
                    policy = None
                else:
                    policy = compile_manifest(manifest, row["content_hash"])
                    unsigned_policy = {
                        key: value for key, value in policy.items() if key != "content_hash"
                    }
                    policy["content_hash"] = content_hash(
                        {
                            "policy": unsigned_policy,
                            "signer_key_id": self.policy_signer.key_id,
                        }
                    )
                    signature_value = self.policy_signer.sign(
                        f"pentai-policy-v1:{policy['content_hash']}".encode("ascii")
                    )
                    policy["signature"] = {
                        "algorithm": "Ed25519",
                        "key_id": self.policy_signer.key_id,
                        "value": signature_value,
                    }
            if rejection_code is None and policy is not None:
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
                            compiler_version, policy_json, content_hash, signature, signer_key_id
                        ) VALUES (?, ?, ?, '1.0.0', ?, ?, ?, ?, ?)
                        """,
                        (
                            policy_id,
                            row["engagement_id"],
                            manifest_version_id,
                            policy["compiler"]["version"],
                            canonical_json(policy),
                            policy["content_hash"],
                            policy["signature"]["value"],
                            policy["signature"]["key_id"],
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
            if self.policy_signer is None:
                raise DomainError("POLICY_SIGNER_UNAVAILABLE", "policy signer is unavailable")
            approval_id = str(uuid4())
            document: dict[str, Any] = {
                "schema_version": "1.2.0",
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
            }
            if reason:
                document["reason"] = reason
            document["signature"] = {
                "algorithm": "Ed25519",
                "key_id": self.policy_signer.key_id,
                "value": self.policy_signer.sign(canonical_json(document).encode()),
            }
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
            policy_signature = policy_document.get("signature", {})
            unsigned_policy = {
                key: value
                for key, value in policy_document.items()
                if key not in {"content_hash", "signature"}
            }
            if (
                self.policy_signer is None
                or content_hash(
                    {
                        "policy": unsigned_policy,
                        "signer_key_id": policy_signature.get("key_id"),
                    }
                )
                != policy["content_hash"]
                or policy_document["manifest_hash"] != policy["manifest_hash"]
                or content_hash(json.loads(policy["document_json"])) != policy["manifest_hash"]
                or policy_signature.get("algorithm") != "Ed25519"
                or policy_signature.get("value") != policy["signature"]
                or policy_signature.get("key_id") != policy["signer_key_id"]
                or not self.policy_signer.verify(
                    f"pentai-policy-v1:{policy['content_hash']}".encode("ascii"),
                    str(policy["signature"]),
                    str(policy["signer_key_id"]),
                )
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
            signature = approval_document.get("signature", {})
            common_fields_valid = (
                approval_document.get("schema_version") == "1.2.0"
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
            unsigned_approval = {
                key: value for key, value in approval_document.items() if key != "signature"
            }
            signature_valid = (
                signature.get("algorithm") == "Ed25519"
                and self.policy_signer is not None
                and self.policy_signer.verify(
                    canonical_json(unsigned_approval).encode(),
                    str(signature.get("value", "")),
                    str(signature.get("key_id", "")),
                )
            )
            if not common_fields_valid or not signature_valid:
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
                    UPDATE action_grants SET revoked_at = ?
                    WHERE engagement_id = ? AND used_at IS NULL AND revoked_at IS NULL
                    """,
                    (activated_at, policy["engagement_id"]),
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
            connection.execute(
                """
                UPDATE network_attestations
                SET status = 'invalidated', invalidated_at = ?
                WHERE engagement_id = ? AND status = 'valid'
                """,
                (activated_at, policy["engagement_id"]),
            )
            self._abort_gateway_sessions(
                connection,
                finalized_at=activated_at,
                engagement_id=policy["engagement_id"],
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
        if not reason.strip():
            raise DomainError("REVOCATION_REASON_REQUIRED", "revocation reason is required")
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
            connection.execute(
                """
                UPDATE action_grants SET revoked_at = ?
                WHERE engagement_id = ? AND used_at IS NULL AND revoked_at IS NULL
                """,
                (revoked_at, policy["engagement_id"]),
            )
            connection.execute(
                """
                UPDATE network_attestations
                SET status = 'invalidated', invalidated_at = ?
                WHERE engagement_id = ? AND status = 'valid'
                """,
                (revoked_at, policy["engagement_id"]),
            )
            self._abort_gateway_sessions(
                connection,
                finalized_at=revoked_at,
                engagement_id=policy["engagement_id"],
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

    def list_policies(self, engagement_id: str) -> list[dict[str, Any]]:
        instant = _timestamp()
        with transaction(self.database_path) as connection:
            rows = connection.execute(
                """
                SELECT p.*,
                    (SELECT COUNT(*) FROM approvals a
                     WHERE a.policy_bundle_id = p.id AND a.decision = 'approved'
                       AND a.invalidated_at IS NULL
                       AND julianday(a.expires_at) > julianday(?)) AS current_approvals
                FROM policy_bundles p WHERE p.engagement_id = ?
                ORDER BY p.rowid DESC
                """,
                (instant, engagement_id),
            ).fetchall()
        history = []
        for row in rows:
            document = json.loads(row["policy_json"])
            if row["revoked_at"] is not None:
                status = "revoked"
            elif row["activated_at"] is not None:
                status = "active"
            elif parse_time(document["validity"]["not_after"]) <= parse_time(instant):
                status = "expired"
            elif row["current_approvals"]:
                status = "approved"
            else:
                status = "awaiting_approval"
            history.append(
                {
                    "id": row["id"],
                    "manifest_version_id": row["manifest_version_id"],
                    "content_hash": row["content_hash"],
                    "compiler_version": row["compiler_version"],
                    "signer_key_id": row["signer_key_id"],
                    "status": status,
                    "activated_at": row["activated_at"],
                    "revoked_at": row["revoked_at"],
                }
            )
        return history

    def evaluate_intent(
        self, engagement_id: str, intent: dict[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            engagement = connection.execute(
                "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
            ).fetchone()
            if engagement is None or engagement["active_policy_id"] is None:
                raise DomainError("POLICY_INACTIVE", "engagement has no active policy")
            if engagement["status"] != "active":
                raise DomainError("ASSESSMENT_PAUSED", "assessment is not active")
            global_state = connection.execute(
                "SELECT global_status FROM safety_state WHERE singleton_id = 1"
            ).fetchone()
            if global_state is None or global_state["global_status"] != "active":
                raise DomainError("GLOBAL_SAFETY_PAUSED", "global safety state is not active")
            policy = connection.execute(
                "SELECT * FROM policy_bundles WHERE id = ?", (engagement["active_policy_id"],)
            ).fetchone()
            policy_document = json.loads(policy["policy_json"])
            signature = policy_document.get("signature", {})
            if (
                self.policy_signer is None
                or signature.get("algorithm") != "Ed25519"
                or not self.policy_signer.verify(
                    f"pentai-policy-v1:{policy['content_hash']}".encode("ascii"),
                    str(signature.get("value", "")),
                    str(signature.get("key_id", "")),
                )
            ):
                raise DomainError("POLICY_SIGNATURE_INVALID", "active policy signature is invalid")
            intent_issues = contract_issues(intent, "action-intent-v1.schema.json")
            if not intent_issues:
                intent_hash = content_hash(intent)
                prior_intent = connection.execute(
                    """
                    SELECT intent_hash FROM action_intents
                    WHERE engagement_id = ? AND idempotency_key = ?
                    """,
                    (engagement_id, intent["idempotency_key"]),
                ).fetchone()
                if prior_intent is not None and prior_intent["intent_hash"] != intent_hash:
                    self._audit(
                        connection,
                        action="action_intent.rejected",
                        subject_type="action_intent",
                        subject_id=str(intent.get("intent_id", "invalid")),
                        actor_type="service",
                        actor_id="authorization-service",
                        data={"reason_codes": ["IDEMPOTENCY_CONFLICT"]},
                    )
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT",
                        "idempotency key is already bound to another intent",
                    )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO action_intents(
                        intent_id, engagement_id, policy_bundle_id, policy_hash,
                        idempotency_key, intent_hash, intent_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        intent["intent_id"],
                        engagement_id,
                        policy["id"],
                        intent["policy_hash"],
                        intent["idempotency_key"],
                        intent_hash,
                        canonical_json(intent),
                        intent["created_at"],
                    ),
                )
                stored_intent = connection.execute(
                    "SELECT intent_hash FROM action_intents WHERE intent_id = ?",
                    (intent["intent_id"],),
                ).fetchone()
                if stored_intent is None or stored_intent["intent_hash"] != intent_hash:
                    raise DomainError(
                        "INTENT_ID_CONFLICT", "intent identifier is already bound"
                    )
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

    def mint_action_grant(
        self, decision_id: str, *, audience: str = "pentai-execution-broker"
    ) -> dict[str, Any]:
        if audience not in {"pentai-execution-broker", "pentai-egress-gateway"}:
            raise DomainError("GRANT_AUDIENCE_INVALID", "grant audience is invalid")
        if self.policy_signer is None:
            raise DomainError("GRANT_SIGNER_UNAVAILABLE", "grant signer is unavailable")
        issued = _now()
        issued_at = _timestamp(issued)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT pe.*, ai.intent_hash, ai.idempotency_key,
                       p.content_hash AS policy_hash,
                       p.policy_json, p.activated_at, p.revoked_at,
                       e.active_policy_id, e.revocation_epoch, e.status AS engagement_status,
                       s.global_status
                FROM policy_evaluations pe
                JOIN action_intents ai ON ai.intent_id = pe.intent_id
                JOIN policy_bundles p ON p.id = pe.policy_bundle_id
                JOIN engagements e ON e.id = pe.engagement_id
                CROSS JOIN safety_state s
                WHERE pe.decision_id = ?
                """,
                (decision_id,),
            ).fetchone()
            if row is None:
                raise DomainError("DECISION_NOT_FOUND", "policy decision does not exist")
            intent = json.loads(row["intent_json"])
            decision = json.loads(row["decision_json"])
            policy = json.loads(row["policy_json"])
            policy_signature = policy.get("signature", {})
            if (
                contract_issues(intent, "action-intent-v1.schema.json")
                or contract_issues(decision, "policy-decision-v1.schema.json")
                or content_hash(intent) != row["intent_hash"]
                or decision.get("outcome") != "allow"
                or decision.get("reason_codes") != ["EXPLICIT_ALLOW"]
                or decision.get("decision_id") != decision_id
                or decision.get("intent_id") != intent.get("intent_id")
                or decision.get("assessment_id") != row["engagement_id"]
                or decision.get("policy_hash") != row["policy_hash"]
                or intent.get("policy_hash") != row["policy_hash"]
                or row["active_policy_id"] != row["policy_bundle_id"]
                or row["activated_at"] is None
                or row["revoked_at"] is not None
                or row["engagement_status"] != "active"
                or row["global_status"] != "active"
                or policy_signature.get("algorithm") != "Ed25519"
                or not self.policy_signer.verify(
                    f"pentai-policy-v1:{row['policy_hash']}".encode("ascii"),
                    str(policy_signature.get("value", "")),
                    str(policy_signature.get("key_id", "")),
                )
            ):
                raise DomainError("GRANT_AUTHORITY_INVALID", "decision cannot authorize a grant")
            existing = connection.execute(
                "SELECT grant_json FROM action_grants WHERE decision_id = ?", (decision_id,)
            ).fetchone()
            if existing is not None:
                existing_grant: dict[str, Any] = json.loads(existing["grant_json"])
                return existing_grant
            expires = min(
                issued + timedelta(seconds=30),
                parse_time(intent["expires_at"]),
                parse_time(policy["validity"]["not_after"]),
            )
            if expires <= issued:
                raise DomainError("GRANT_EXPIRED", "grant authority is already expired")
            requested = intent.get("requested_limits", {})
            http = intent.get("http", {})
            maximum_response_bytes = min(
                int(
                    requested.get(
                        "maximum_response_bytes", policy["budgets"]["maximum_response_bytes"]
                    )
                ),
                int(policy["budgets"]["maximum_response_bytes"]),
            )
            follow_redirects = bool(http.get("follow_redirects", False))
            maximum_redirects = int(http.get("maximum_redirects", 0)) if follow_redirects else 0
            grant: dict[str, Any] = {
                "schema_version": "1.0.0",
                "grant_id": str(uuid4()),
                "intent_id": intent["intent_id"],
                "decision_id": decision_id,
                "assessment_id": row["engagement_id"],
                "policy_hash": row["policy_hash"],
                "revocation_epoch": row["revocation_epoch"],
                "audience": audience,
                "capability": intent["capability"],
                "target_digest": _intent_target_digest(intent),
                "parameters_digest": intent["parameters_digest"],
                "constraints": {
                    "maximum_connections": 1,
                    "maximum_requests": 1,
                    "timeout_seconds": min(int(requested.get("timeout_seconds", 30)), 300),
                    "maximum_response_bytes": maximum_response_bytes,
                    "follow_redirects": follow_redirects,
                    "maximum_redirects": maximum_redirects,
                    "required_route_profile_id": policy["network_constraints"][
                        "route_profile_id"
                    ],
                },
                "issued_at": issued_at,
                "not_before": issued_at,
                "expires_at": _timestamp(expires),
                "nonce": secrets.token_urlsafe(24),
                "single_use": True,
            }
            grant["signature"] = {
                "algorithm": "Ed25519",
                "key_id": self.policy_signer.key_id,
                "value": self.policy_signer.sign(_grant_payload(grant)),
            }
            if contract_issues(grant, "action-grant-v1.schema.json"):
                raise DomainError("GRANT_CONTRACT_INVALID", "generated grant is invalid")
            grant_json = canonical_json(grant)
            grant_hash = content_hash(grant)
            connection.execute(
                """
                INSERT INTO action_grants(
                    grant_id, intent_id, decision_id, engagement_id, policy_bundle_id,
                    policy_hash, revocation_epoch, audience, grant_json, grant_hash,
                    issued_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    grant["grant_id"],
                    grant["intent_id"],
                    decision_id,
                    row["engagement_id"],
                    row["policy_bundle_id"],
                    row["policy_hash"],
                    row["revocation_epoch"],
                    audience,
                    grant_json,
                    grant_hash,
                    issued_at,
                    grant["expires_at"],
                ),
            )
            self._audit(
                connection,
                action="action_grant.issued",
                subject_type="action_grant",
                subject_id=grant["grant_id"],
                actor_type="service",
                actor_id="execution-broker",
                data={
                    "intent_id": grant["intent_id"],
                    "decision_id": decision_id,
                    "policy_hash": grant["policy_hash"],
                    "audience": audience,
                    "grant_hash": grant_hash,
                },
                occurred_at=issued_at,
            )
            return grant

    def consume_action_grant(
        self,
        grant: dict[str, Any],
        intent: dict[str, Any],
        *,
        audience: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        instant = now or _now()
        consumed_at = _timestamp(instant)
        if self.policy_signer is None:
            raise DomainError("GRANT_SIGNER_UNAVAILABLE", "grant signer is unavailable")
        if contract_issues(grant, "action-grant-v1.schema.json"):
            raise DomainError("GRANT_INVALID", "grant contract is invalid")
        signature = grant.get("signature", {})
        if (
            signature.get("algorithm") != "Ed25519"
            or not self.policy_signer.verify(
                _grant_payload(grant),
                str(signature.get("value", "")),
                str(signature.get("key_id", "")),
            )
        ):
            raise DomainError("GRANT_SIGNATURE_INVALID", "grant signature is invalid")
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT ag.*, ai.intent_json, ai.intent_hash,
                       e.active_policy_id, e.revocation_epoch AS current_revocation_epoch,
                       e.status AS engagement_status,
                       p.activated_at, p.revoked_at AS policy_revoked_at,
                       s.global_status
                FROM action_grants ag
                JOIN action_intents ai ON ai.intent_id = ag.intent_id
                JOIN engagements e ON e.id = ag.engagement_id
                JOIN policy_bundles p ON p.id = ag.policy_bundle_id
                CROSS JOIN safety_state s
                WHERE ag.grant_id = ?
                """,
                (grant["grant_id"],),
            ).fetchone()
            if row is None:
                raise DomainError("GRANT_NOT_FOUND", "grant does not exist")
            stored_intent = json.loads(row["intent_json"])
            if (
                canonical_json(grant) != row["grant_json"]
                or content_hash(grant) != row["grant_hash"]
                or canonical_json(intent) != canonical_json(stored_intent)
                or content_hash(intent) != row["intent_hash"]
                or audience != grant["audience"]
                or grant["audience"] != row["audience"]
                or grant["assessment_id"] != row["engagement_id"]
                or grant["policy_hash"] != row["policy_hash"]
                or grant["revocation_epoch"] != row["revocation_epoch"]
                or grant["intent_id"] != intent.get("intent_id")
                or grant["capability"] != intent.get("capability")
                or grant["target_digest"] != _intent_target_digest(intent)
                or grant["parameters_digest"] != intent.get("parameters_digest")
            ):
                raise DomainError("GRANT_BINDING_MISMATCH", "grant binding is invalid")
            if row["used_at"] is not None:
                raise DomainError("GRANT_REPLAYED", "grant was already consumed")
            if row["revoked_at"] is not None:
                raise DomainError("GRANT_REVOKED", "grant is revoked")
            if parse_time(grant["not_before"]) > instant:
                raise DomainError("GRANT_NOT_YET_VALID", "grant is not yet valid")
            if parse_time(grant["expires_at"]) <= instant:
                raise DomainError("GRANT_EXPIRED", "grant has expired")
            if (
                row["active_policy_id"] != row["policy_bundle_id"]
                or row["activated_at"] is None
                or row["policy_revoked_at"] is not None
                or row["engagement_status"] != "active"
                or row["global_status"] != "active"
                or grant["revocation_epoch"] != row["current_revocation_epoch"]
            ):
                raise DomainError("GRANT_REVOKED", "grant authority is no longer active")
            cursor = connection.execute(
                """
                UPDATE action_grants SET used_at = ?
                WHERE grant_id = ? AND used_at IS NULL AND revoked_at IS NULL
                """,
                (consumed_at, grant["grant_id"]),
            )
            if cursor.rowcount != 1:
                raise DomainError("GRANT_REPLAYED", "grant was already consumed")
            self._audit(
                connection,
                action="action_grant.consumed",
                subject_type="action_grant",
                subject_id=grant["grant_id"],
                actor_type="service",
                actor_id=audience,
                data={
                    "intent_id": grant["intent_id"],
                    "decision_id": grant["decision_id"],
                    "policy_hash": grant["policy_hash"],
                    "grant_hash": row["grant_hash"],
                },
                occurred_at=consumed_at,
            )
            return {
                "grant_id": grant["grant_id"],
                "status": "consumed",
                "consumed_at": consumed_at,
                "policy_hash": grant["policy_hash"],
            }

    def safety_state(self) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            row = connection.execute("SELECT * FROM safety_state WHERE singleton_id = 1").fetchone()
        if row is None:
            raise DomainError("SAFETY_STATE_MISSING", "durable safety state is unavailable")
        return {
            "status": row["global_status"],
            "reason": row["reason"],
            "generation": row["generation"],
            "updated_at": row["updated_at"],
            "updated_by": row["updated_by"],
            "network_attested": False,
            "execution_enabled": False,
        }

    def record_network_attestation(
        self, attestation: dict[str, Any], *, attestor_id: str
    ) -> dict[str, Any]:
        if not attestor_id.strip():
            raise DomainError("ATTESTOR_ID_REQUIRED", "network attestor identity is required")
        if contract_issues(attestation, "network-attestation-v1.schema.json"):
            raise DomainError("ATTESTATION_INVALID", "network attestation is malformed")
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            engagement = connection.execute(
                "SELECT * FROM engagements WHERE id = ?", (attestation["assessment_id"],)
            ).fetchone()
            if engagement is None or engagement["active_policy_id"] is None:
                raise DomainError("ATTESTATION_INVALID", "assessment policy is inactive")
            policy_row = connection.execute(
                "SELECT * FROM policy_bundles WHERE id = ?", (engagement["active_policy_id"],)
            ).fetchone()
            safety = connection.execute(
                "SELECT global_status FROM safety_state WHERE singleton_id = 1"
            ).fetchone()
            if (
                policy_row is None
                or policy_row["revoked_at"] is not None
                or engagement["status"] != "active"
                or safety is None
                or safety["global_status"] != "active"
            ):
                raise DomainError("ATTESTATION_INVALID", "authorization state is inactive")
            policy = json.loads(policy_row["policy_json"])
            signature = policy.get("signature", {})
            if (
                policy.get("content_hash") != policy_row["content_hash"]
                or policy.get("engagement_id") != attestation["assessment_id"]
                or policy_row["activated_at"] is None
                or self.policy_signer is None
                or signature.get("algorithm") != "Ed25519"
                or not self.policy_signer.verify(
                    f"pentai-policy-v1:{policy_row['content_hash']}".encode("ascii"),
                    str(signature.get("value", "")),
                    str(signature.get("key_id", "")),
                )
            ):
                raise DomainError("ATTESTATION_INVALID", "assessment policy is unverifiable")
            try:
                validate_attestation(attestation, policy)
            except (KeyError, TypeError, ValueError) as exc:
                raise DomainError(str(exc), "network attestation was denied") from None
            connection.execute(
                """
                UPDATE network_attestations
                SET status = 'invalidated', invalidated_at = ?
                WHERE engagement_id = ? AND status = 'valid'
                """,
                (attestation["observed_at"], attestation["assessment_id"]),
            )
            connection.execute(
                """
                INSERT INTO network_attestations(
                    attestation_id, engagement_id, policy_bundle_id, policy_hash,
                    route_profile_id, source_ipv4, source_ipv6, resolver_mode, resolver_id,
                    observations_json, observed_at, expires_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid')
                """,
                (
                    attestation["attestation_id"], attestation["assessment_id"],
                    policy_row["id"], attestation["policy_hash"],
                    attestation["route_profile_id"], attestation.get("source_ipv4"),
                    attestation.get("source_ipv6"), attestation["resolver_mode"],
                    attestation["resolver_id"],
                    canonical_json(attestation["observations"]), attestation["observed_at"],
                    attestation["expires_at"],
                ),
            )
            self._audit(
                connection,
                action="network.attested",
                subject_type="network_attestation",
                subject_id=attestation["attestation_id"],
                actor_type="service",
                actor_id=attestor_id,
                data={
                    "route_profile_id": attestation["route_profile_id"],
                    "source_ipv4": attestation.get("source_ipv4"),
                    "source_ipv6": attestation.get("source_ipv6"),
                },
            )
        return {**attestation, "status": "valid", "execution_enabled": False}

    def attest_network(
        self,
        engagement_id: str,
        *,
        attestor: NetworkAttestor,
        attestor_id: str,
    ) -> dict[str, Any]:
        try:
            with transaction(self.database_path) as connection:
                row = connection.execute(
                    """
                    SELECT p.content_hash, na.route_profile_id, na.source_ipv4,
                           na.source_ipv6, na.resolver_mode, na.resolver_id
                    FROM engagements e
                    JOIN policy_bundles p ON p.id = e.active_policy_id
                    CROSS JOIN safety_state s
                    LEFT JOIN network_attestations na ON na.attestation_id = (
                        SELECT current.attestation_id FROM network_attestations current
                        WHERE current.engagement_id = e.id AND current.status = 'valid'
                        ORDER BY current.observed_at DESC, current.attestation_id DESC LIMIT 1
                    )
                    WHERE e.id = ? AND e.status = 'active'
                      AND p.activated_at IS NOT NULL AND p.revoked_at IS NULL
                      AND s.global_status = 'active'
                    """,
                    (engagement_id,),
                ).fetchone()
            if row is None:
                raise DomainError("ATTESTATION_INVALID", "assessment policy is inactive")
            attestation = attestor.measure(
                assessment_id=engagement_id,
                policy_hash=row["content_hash"],
            )
            if row["route_profile_id"] is not None and any(
                attestation.get(field) != row[field]
                for field in (
                    "route_profile_id",
                    "source_ipv4",
                    "source_ipv6",
                    "resolver_mode",
                    "resolver_id",
                )
            ):
                raise DomainError(
                    "NETWORK_IDENTITY_CHANGED", "network identity changed during assessment"
                )
            return self.record_network_attestation(attestation, attestor_id=attestor_id)
        except AttestationError as exc:
            failure = DomainError(exc.code, "network attestation failed")
        except DomainError as exc:
            failure = exc
        try:
            self.set_assessment_safety(
                engagement_id,
                status="paused",
                reason=f"network health failure: {failure.code}",
                actor_id=attestor_id,
            )
        except DomainError:
            pass
        raise failure

    def network_authority_assessments(self) -> tuple[str, ...]:
        with transaction(self.database_path) as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT engagement_id FROM network_attestations
                WHERE status = 'valid' ORDER BY engagement_id
                """
            ).fetchall()
        return tuple(str(row["engagement_id"]) for row in rows)

    def has_network_authority(self) -> bool:
        return bool(self.network_authority_assessments())

    def verify_network_identity(
        self,
        engagement_id: str,
        *,
        attestor: NetworkAttestor,
        attestor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not attestor_id.strip():
            raise DomainError("ATTESTOR_ID_REQUIRED", "network attestor identity is required")
        instant = now or _now()
        try:
            with transaction(self.database_path) as connection:
                row = connection.execute(
                    """
                    SELECT na.*, p.policy_json, p.content_hash,
                           p.revoked_at AS policy_revoked_at,
                           e.active_policy_id, e.status AS engagement_status,
                           s.global_status
                    FROM network_attestations na
                    JOIN policy_bundles p ON p.id = na.policy_bundle_id
                    JOIN engagements e ON e.id = na.engagement_id
                    CROSS JOIN safety_state s
                    WHERE na.engagement_id = ? AND na.status = 'valid'
                    ORDER BY na.observed_at DESC, na.attestation_id DESC LIMIT 1
                    """,
                    (engagement_id,),
                ).fetchone()
            if (
                row is None
                or row["policy_revoked_at"] is not None
                or row["active_policy_id"] != row["policy_bundle_id"]
                or row["engagement_status"] != "active"
                or row["global_status"] != "active"
            ):
                raise DomainError(
                    "NETWORK_AUTHORITY_INACTIVE", "network authority is inactive"
                )
            policy = json.loads(row["policy_json"])
            current = self._attestation_document(row)
            try:
                validate_attestation(current, policy, now=instant)
                measured = attestor.measure(
                    assessment_id=engagement_id,
                    policy_hash=row["content_hash"],
                    now=instant,
                )
                validate_attestation(measured, policy, now=instant)
            except AttestationError as exc:
                raise DomainError(exc.code, "network identity verification failed") from exc
            except (KeyError, TypeError, ValueError) as exc:
                code = str(exc) if str(exc) else "ATTESTATION_INVALID"
                raise DomainError(code, "network identity verification failed") from exc
            identity_fields = (
                "route_profile_id",
                "source_ipv4",
                "source_ipv6",
                "resolver_mode",
                "resolver_id",
            )
            if any(current.get(field) != measured.get(field) for field in identity_fields):
                raise DomainError(
                    "NETWORK_IDENTITY_CHANGED", "network identity changed during assessment"
                )
            checked_at = _timestamp(instant)
            with transaction(self.database_path) as connection:
                connection.execute("BEGIN IMMEDIATE")
                unchanged = connection.execute(
                    """
                    SELECT 1 FROM network_attestations na
                    JOIN engagements e ON e.id = na.engagement_id
                    JOIN policy_bundles p ON p.id = na.policy_bundle_id
                    CROSS JOIN safety_state s
                    WHERE na.attestation_id = ? AND na.status = 'valid'
                      AND e.active_policy_id = na.policy_bundle_id
                      AND e.status = 'active' AND p.revoked_at IS NULL
                      AND s.global_status = 'active'
                    """,
                    (row["attestation_id"],),
                ).fetchone()
                if unchanged is None:
                    raise DomainError(
                        "NETWORK_AUTHORITY_CHANGED", "network authority changed during check"
                    )
                self._audit(
                    connection,
                    action="network.identity_checked",
                    subject_type="network_attestation",
                    subject_id=row["attestation_id"],
                    actor_type="service",
                    actor_id=attestor_id,
                    data={"policy_hash": row["content_hash"]},
                    occurred_at=checked_at,
                )
            return {
                "assessment_id": engagement_id,
                "attestation_id": row["attestation_id"],
                "status": "verified",
                "checked_at": checked_at,
                "execution_enabled": False,
            }
        except DomainError as failure:
            try:
                self.set_assessment_safety(
                    engagement_id,
                    status="paused",
                    reason=f"network identity failure: {failure.code}",
                    actor_id=attestor_id,
                )
            except DomainError:
                pass
            raise failure

    @staticmethod
    def _attestation_document(row: Any) -> dict[str, Any]:
        document: dict[str, Any] = {
            "schema_version": "1.0.0",
            "attestation_id": row["attestation_id"],
            "assessment_id": row["engagement_id"],
            "policy_hash": row["policy_hash"],
            "route_profile_id": row["route_profile_id"],
            "resolver_mode": row["resolver_mode"],
            "resolver_id": row["resolver_id"],
            "observations": json.loads(row["observations_json"]),
            "observed_at": row["observed_at"],
            "expires_at": row["expires_at"],
        }
        if row["source_ipv4"] is not None:
            document["source_ipv4"] = row["source_ipv4"]
        if row["source_ipv6"] is not None:
            document["source_ipv6"] = row["source_ipv6"]
        return document

    def commit_gateway_request_start(
        self, session_id: str, *, now: datetime | None = None
    ) -> dict[str, Any]:
        instant = now or _now()
        committed_at = _timestamp(instant)
        if self.policy_signer is None:
            raise DomainError("GATEWAY_REQUEST_DENIED", "grant signer is unavailable")
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT gs.*, br.engagement_id, br.policy_bundle_id,
                       br.response_bytes_limit, br.status AS reservation_status,
                       grr.status AS rate_status, ag.grant_json, ag.grant_hash,
                       ag.audience, ag.revocation_epoch, ag.used_at, ag.revoked_at,
                       ai.intent_json, ai.intent_hash, p.content_hash AS policy_hash,
                       p.activated_at,
                       p.revoked_at AS policy_revoked_at, e.active_policy_id,
                       e.revocation_epoch AS current_epoch,
                       e.status AS engagement_status,
                       e.expires_at AS engagement_expires_at,
                       na.status AS attestation_status,
                       na.expires_at AS attestation_expires_at, da.decision_json,
                       da.decision_hash, s.global_status
                FROM gateway_sessions gs
                JOIN budget_reservations br ON br.reservation_id = gs.reservation_id
                JOIN gateway_rate_reservations grr ON grr.reservation_id = br.reservation_id
                JOIN action_grants ag ON ag.grant_id = gs.grant_id
                JOIN action_intents ai ON ai.intent_id = ag.intent_id
                JOIN policy_bundles p ON p.id = br.policy_bundle_id
                JOIN engagements e ON e.id = br.engagement_id
                JOIN network_attestations na ON na.attestation_id = gs.attestation_id
                JOIN destination_authorizations da
                  ON da.authorization_id = gs.destination_authorization_id
                CROSS JOIN safety_state s
                WHERE gs.session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if row is None:
                raise DomainError("GATEWAY_REQUEST_DENIED", "prepared session is missing")
            if connection.execute(
                "SELECT 1 FROM gateway_request_starts WHERE session_id = ?", (session_id,)
            ).fetchone() is not None:
                raise DomainError("GATEWAY_REQUEST_REPLAYED", "request start is already committed")
            grant = json.loads(row["grant_json"])
            intent = json.loads(row["intent_json"])
            decision = json.loads(row["decision_json"])
            signature = grant.get("signature", {})
            try:
                timeout_seconds = int(grant["constraints"]["timeout_seconds"])
                deadline = min(
                    instant + timedelta(seconds=timeout_seconds),
                    parse_time(grant["expires_at"]),
                    parse_time(row["engagement_expires_at"]),
                    parse_time(row["attestation_expires_at"]),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise DomainError("GATEWAY_REQUEST_DENIED", "request deadline is invalid") from exc
            if (
                row["status"] != "prepared"
                or row["reservation_status"] != "reserved"
                or row["rate_status"] != "reserved"
                or row["used_at"] is not None
                or row["revoked_at"] is not None
                or row["audience"] != "pentai-egress-gateway"
                or contract_issues(grant, "action-grant-v1.schema.json")
                or contract_issues(decision, "destination-decision-v1.schema.json")
                or canonical_json(grant) != row["grant_json"]
                or content_hash(grant) != row["grant_hash"]
                or canonical_json(intent) != row["intent_json"]
                or content_hash(intent) != row["intent_hash"]
                or content_hash(decision) != row["decision_hash"]
                or decision.get("outcome") != "allow"
                or decision.get("execution_enabled") is not False
                or decision.get("grant_id") != row["grant_id"]
                or decision.get("attestation_id") != row["attestation_id"]
                or grant.get("audience") != row["audience"]
                or grant.get("assessment_id") != row["engagement_id"]
                or grant.get("policy_hash") != row["policy_hash"]
                or grant.get("intent_id") != intent.get("intent_id")
                or grant.get("target_digest") != _intent_target_digest(intent)
                or grant.get("parameters_digest") != intent.get("parameters_digest")
                or signature.get("algorithm") != "Ed25519"
                or not self.policy_signer.verify(
                    _grant_payload(grant),
                    str(signature.get("value", "")),
                    str(signature.get("key_id", "")),
                )
                or parse_time(grant["not_before"]) > instant
                or deadline <= instant
                or row["attestation_status"] != "valid"
                or row["active_policy_id"] != row["policy_bundle_id"]
                or row["activated_at"] is None
                or row["policy_revoked_at"] is not None
                or row["revocation_epoch"] != row["current_epoch"]
                or row["engagement_status"] != "active"
                or row["global_status"] != "active"
            ):
                raise DomainError("GATEWAY_REQUEST_DENIED", "runtime authority is inactive")
            start_id = str(uuid4())
            deadline_at = _timestamp(deadline)
            used = connection.execute(
                """
                UPDATE action_grants SET used_at = ?
                WHERE grant_id = ? AND used_at IS NULL AND revoked_at IS NULL
                """,
                (committed_at, row["grant_id"]),
            )
            if used.rowcount != 1:
                raise DomainError("GATEWAY_REQUEST_REPLAYED", "grant is already consumed")
            account = connection.execute(
                """
                UPDATE budget_accounts
                SET reserved_requests = reserved_requests - 1,
                    committed_requests = committed_requests + 1, updated_at = ?
                WHERE engagement_id = ? AND reserved_requests >= 1
                """,
                (committed_at, row["engagement_id"]),
            )
            if account.rowcount != 1:
                raise DomainError("GATEWAY_REQUEST_DENIED", "reserved budget is inconsistent")
            connection.execute(
                """UPDATE budget_reservations SET status = 'committed', finalized_at = ?
                   WHERE reservation_id = ? AND status = 'reserved'""",
                (committed_at, row["reservation_id"]),
            )
            connection.execute(
                """UPDATE gateway_rate_reservations SET status = 'committed', finalized_at = ?
                   WHERE reservation_id = ? AND status = 'reserved'""",
                (committed_at, row["reservation_id"]),
            )
            connection.execute(
                """
                INSERT INTO gateway_request_starts(
                    start_id, session_id, reservation_id, grant_id, committed_at,
                    deadline_at, status, execution_enabled
                ) VALUES (?, ?, ?, ?, ?, ?, 'committed', 0)
                """,
                (
                    start_id,
                    session_id,
                    row["reservation_id"],
                    row["grant_id"],
                    committed_at,
                    deadline_at,
                ),
            )
            document = {
                "schema_version": "1.0.0", "start_id": start_id,
                "session_id": session_id, "reservation_id": row["reservation_id"],
                "grant_id": row["grant_id"], "status": "committed",
                "committed_at": committed_at, "deadline_at": deadline_at,
                "execution_enabled": False,
            }
            if contract_issues(document, "gateway-request-start-v1.schema.json"):
                raise DomainError("GATEWAY_REQUEST_DENIED", "generated request start is invalid")
            self._audit(
                connection, action="gateway.request_start_committed",
                subject_type="gateway_session", subject_id=session_id,
                actor_type="service", actor_id="gateway-control",
                data={"start_id": start_id, "grant_id": row["grant_id"],
                      "reservation_id": row["reservation_id"],
                      "deadline_at": deadline_at, "execution_enabled": False},
                occurred_at=committed_at,
            )
        return document

    def resolve_and_authorize_network_destination(
        self,
        *,
        grant_id: str,
        attestation_id: str,
        candidate_url: str,
        resolver_source: ControlledResolverSource,
        sni_host: str,
        host_header: str,
    ) -> dict[str, Any]:
        return self._resolve_and_authorize_network_destination(
            grant_id=grant_id,
            attestation_id=attestation_id,
            candidate_url=candidate_url,
            resolver_source=resolver_source,
            sni_host=sni_host,
            host_header=host_header,
            redirect_count=0,
            parent_authorization_id=None,
        )

    def resolve_and_authorize_network_redirect(
        self,
        *,
        grant_id: str,
        attestation_id: str,
        parent_authorization_id: str,
        location: str,
        resolver_source: ControlledResolverSource,
        sni_host: str,
        host_header: str,
    ) -> dict[str, Any]:
        if (
            not location
            or len(location) > 2048
            or "\\" in location
            or any(ord(character) <= 32 or ord(character) == 127 for character in location)
        ):
            raise DomainError("REDIRECT_DENIED", "redirect location is invalid")
        with transaction(self.database_path) as connection:
            row = connection.execute(
                """
                SELECT da.*, child.authorization_id AS child_id
                FROM destination_authorizations da
                LEFT JOIN destination_authorizations child
                  ON child.parent_authorization_id = da.authorization_id
                WHERE da.authorization_id = ? AND da.grant_id = ?
                """,
                (parent_authorization_id, grant_id),
            ).fetchone()
        if row is None:
            raise DomainError("REDIRECT_DENIED", "redirect parent is missing")
        try:
            parent = json.loads(row["decision_json"])
            if (
                contract_issues(parent, "destination-decision-v1.schema.json")
                or content_hash(parent) != row["decision_hash"]
                or parent.get("outcome") != "allow"
                or row["attestation_id"] != attestation_id
                or row["child_id"] is not None
            ):
                raise DomainError("REDIRECT_DENIED", "redirect parent is inactive")
            redirect_count = int(row["redirect_count"]) + 1
            if redirect_count > 10:
                raise DomainError("REDIRECT_DENIED", "redirect limit is exceeded")
            parent_url = str(parent["candidate"]["canonical_url"])
            candidate_url = canonicalize_url(urljoin(parent_url, location))["canonical_url"]
        except DomainError:
            raise
        except (
            CanonicalizationError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise DomainError("REDIRECT_DENIED", "redirect location is invalid") from exc
        return self._resolve_and_authorize_network_destination(
            grant_id=grant_id,
            attestation_id=attestation_id,
            candidate_url=str(candidate_url),
            resolver_source=resolver_source,
            sni_host=sni_host,
            host_header=host_header,
            redirect_count=redirect_count,
            parent_authorization_id=parent_authorization_id,
        )

    def _resolve_and_authorize_network_destination(
        self,
        *,
        grant_id: str,
        attestation_id: str,
        candidate_url: str,
        resolver_source: ControlledResolverSource,
        sni_host: str,
        host_header: str,
        redirect_count: int,
        parent_authorization_id: str | None,
    ) -> dict[str, Any]:
        assessment_id, resolver_mode, resolver_id = self._network_resolution_context(
            grant_id=grant_id, attestation_id=attestation_id
        )
        try:
            resolver = resolver_source.for_assessment(assessment_id)
        except DomainError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise DomainError("DNS_INVALID", "controlled DNS composition failed") from exc
        try:
            candidate = canonicalize_url(candidate_url)
            host = candidate["host"]
            port = candidate["port"]
            if not isinstance(host, dict) or not isinstance(port, int):
                raise TypeError
            answer = resolver.resolve(
                str(host["value"]),
                port,
                attestation={
                    "resolver_mode": resolver_mode,
                    "resolver_id": resolver_id,
                },
            )
        except (CanonicalizationError, KeyError, TypeError, ValueError) as exc:
            code = exc.code if isinstance(exc, ControlledDnsError) else "DNS_INVALID"
            raise DomainError(code, "controlled DNS resolution failed") from exc
        return self._authorize_network_destination(
            grant_id=grant_id,
            attestation_id=attestation_id,
            candidate_url=candidate_url,
            addresses=list(answer.addresses),
            cname_chain=list(answer.cname_chain),
            sni_host=sni_host,
            host_header=host_header,
            redirect_count=redirect_count,
            parent_authorization_id=parent_authorization_id,
        )

    def _network_resolution_context(
        self, *, grant_id: str, attestation_id: str
    ) -> tuple[str, str, str]:
        with transaction(self.database_path) as connection:
            row = connection.execute(
                """
                SELECT ag.*, p.policy_json, p.revoked_at AS policy_revoked_at,
                       e.active_policy_id, e.revocation_epoch AS current_epoch,
                       e.status AS engagement_status, s.global_status,
                       na.engagement_id AS attestation_engagement_id,
                       na.policy_bundle_id AS attestation_policy_bundle_id,
                       na.attestation_id, na.policy_hash AS attestation_policy_hash,
                       na.status AS attestation_status,
                       na.resolver_mode, na.resolver_id, na.route_profile_id,
                       na.source_ipv4, na.source_ipv6, na.observations_json,
                       na.observed_at, na.expires_at
                FROM action_grants ag
                JOIN policy_bundles p ON p.id = ag.policy_bundle_id
                JOIN engagements e ON e.id = ag.engagement_id
                JOIN network_attestations na ON na.attestation_id = ?
                CROSS JOIN safety_state s
                WHERE ag.grant_id = ?
                """,
                (attestation_id, grant_id),
            ).fetchone()
        if row is None:
            raise DomainError("NETWORK_AUTHORIZATION_DENIED", "runtime authority is missing")
        try:
            grant = json.loads(row["grant_json"])
            policy = json.loads(row["policy_json"])
            attestation = self._attestation_document(row)
            now = _now()
            invalid = (
                contract_issues(grant, "action-grant-v1.schema.json")
                or content_hash(grant) != row["grant_hash"]
                or parse_time(grant["not_before"]) > now
                or parse_time(grant["expires_at"]) <= now
                or row["used_at"] is not None
                or row["revoked_at"] is not None
                or row["policy_revoked_at"] is not None
                or row["active_policy_id"] != row["policy_bundle_id"]
                or row["revocation_epoch"] != row["current_epoch"]
                or row["engagement_status"] != "active"
                or row["global_status"] != "active"
                or row["audience"] != "pentai-egress-gateway"
                or grant.get("audience") != "pentai-egress-gateway"
                or row["attestation_status"] != "valid"
                or row["attestation_engagement_id"] != row["engagement_id"]
                or row["attestation_policy_bundle_id"] != row["policy_bundle_id"]
                or row["attestation_policy_hash"] != grant["policy_hash"]
                or self.policy_signer is None
                or not self.policy_signer.verify(
                    _grant_payload(grant),
                    str(grant.get("signature", {}).get("value", "")),
                    str(grant.get("signature", {}).get("key_id", "")),
                )
            )
            if invalid:
                raise DomainError(
                    "NETWORK_AUTHORIZATION_DENIED", "runtime authority is inactive"
                )
            validate_attestation(attestation, policy, now=now)
        except DomainError:
            raise
        except (AttestationError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DomainError(
                "NETWORK_AUTHORIZATION_DENIED", "runtime authority is invalid"
            ) from exc
        return str(row["engagement_id"]), str(row["resolver_mode"]), str(row["resolver_id"])

    def _authorize_network_destination(
        self,
        *,
        grant_id: str,
        attestation_id: str,
        candidate_url: str,
        addresses: list[str],
        cname_chain: list[str],
        sni_host: str,
        host_header: str,
        redirect_count: int,
        parent_authorization_id: str | None,
    ) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT ag.*, ai.intent_json, p.policy_json, p.revoked_at AS policy_revoked_at,
                       e.active_policy_id, e.revocation_epoch AS current_epoch,
                       e.status AS engagement_status, s.global_status
                FROM action_grants ag
                JOIN action_intents ai ON ai.intent_id = ag.intent_id
                JOIN policy_bundles p ON p.id = ag.policy_bundle_id
                JOIN engagements e ON e.id = ag.engagement_id
                CROSS JOIN safety_state s WHERE ag.grant_id = ?
                """,
                (grant_id,),
            ).fetchone()
            attestation_row = connection.execute(
                "SELECT * FROM network_attestations WHERE attestation_id = ?", (attestation_id,)
            ).fetchone()
            if row is None or attestation_row is None:
                raise DomainError("NETWORK_AUTHORIZATION_DENIED", "grant or attestation missing")
            grant = json.loads(row["grant_json"])
            now = _now()
            if (
                contract_issues(grant, "action-grant-v1.schema.json")
                or content_hash(grant) != row["grant_hash"]
                or parse_time(grant["not_before"]) > now
                or parse_time(grant["expires_at"]) <= now
                or row["used_at"] is not None or row["revoked_at"] is not None
                or row["policy_revoked_at"] is not None
                or row["active_policy_id"] != row["policy_bundle_id"]
                or row["revocation_epoch"] != row["current_epoch"]
                or row["engagement_status"] != "active" or row["global_status"] != "active"
                or row["audience"] != "pentai-egress-gateway"
                or grant.get("audience") != "pentai-egress-gateway"
                or attestation_row["status"] != "valid"
                or attestation_row["engagement_id"] != row["engagement_id"]
                or attestation_row["policy_bundle_id"] != row["policy_bundle_id"]
                or attestation_row["policy_hash"] != grant["policy_hash"]
                or self.policy_signer is None
                or not self.policy_signer.verify(
                    _grant_payload(grant), str(grant.get("signature", {}).get("value", "")),
                    str(grant.get("signature", {}).get("key_id", "")),
                )
            ):
                raise DomainError("NETWORK_AUTHORIZATION_DENIED", "runtime authority is inactive")
            attestation = {
                "schema_version": "1.0.0",
                "attestation_id": attestation_row["attestation_id"],
                "assessment_id": attestation_row["engagement_id"],
                "policy_hash": attestation_row["policy_hash"],
                "route_profile_id": attestation_row["route_profile_id"],
                "resolver_mode": attestation_row["resolver_mode"],
                "resolver_id": attestation_row["resolver_id"],
                "observations": json.loads(attestation_row["observations_json"]),
                "observed_at": attestation_row["observed_at"],
                "expires_at": attestation_row["expires_at"],
            }
            if attestation_row["source_ipv4"]:
                attestation["source_ipv4"] = attestation_row["source_ipv4"]
            if attestation_row["source_ipv6"]:
                attestation["source_ipv6"] = attestation_row["source_ipv6"]
            previous_row = connection.execute(
                """
                SELECT decision_json FROM destination_authorizations
                WHERE authorization_id = COALESCE(
                    ?,
                    (SELECT authorization_id FROM destination_authorizations
                     WHERE grant_id = ? ORDER BY created_at DESC, authorization_id DESC LIMIT 1)
                )
                """,
                (parent_authorization_id, grant_id),
            ).fetchone()
            previous_pinned = None
            if previous_row is not None:
                previous_decision = json.loads(previous_row["decision_json"])
                previous_candidate = previous_decision.get("candidate", {})
                current_candidate = canonicalize_url(candidate_url)
                if (
                    previous_decision.get("outcome") == "allow"
                    and previous_candidate.get("host") == current_candidate.get("host")
                    and previous_candidate.get("port") == current_candidate.get("port")
                ):
                    previous_pinned = previous_decision.get("pinned_addresses", [])
            decision = authorize_destination(
                grant=grant,
                intent=json.loads(row["intent_json"]),
                policy=json.loads(row["policy_json"]),
                attestation=attestation,
                candidate_url=candidate_url,
                addresses=addresses,
                cname_chain=cname_chain,
                sni_host=sni_host,
                host_header=host_header,
                redirect_count=redirect_count,
                previously_pinned_addresses=previous_pinned,
            )
            if contract_issues(decision, "destination-decision-v1.schema.json"):
                raise DomainError("NETWORK_AUTHORIZATION_DENIED", "destination decision is invalid")
            try:
                connection.execute(
                    """
                    INSERT INTO destination_authorizations(
                        authorization_id, grant_id, attestation_id, candidate_url,
                        decision_json, decision_hash, created_at,
                        parent_authorization_id, redirect_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision["authorization_id"], grant_id, attestation_id,
                        candidate_url, canonical_json(decision), content_hash(decision),
                        decision["created_at"], parent_authorization_id, redirect_count,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if parent_authorization_id is not None:
                    raise DomainError("REDIRECT_DENIED", "redirect parent is already used") from exc
                raise
            self._audit(
                connection, action="network.destination_decided", subject_type="action_grant",
                subject_id=grant_id, actor_type="service", actor_id="network-control",
                data={"outcome": decision["outcome"], "reason_codes": decision["reason_codes"],
                "authorization_id": decision["authorization_id"],
                "parent_authorization_id": parent_authorization_id,
                "redirect_count": redirect_count},
            )
        return decision

    def prepare_gateway_session(
        self,
        *,
        grant_id: str,
        destination_authorization_id: str,
    ) -> dict[str, Any]:
        prepared_instant = _now()
        prepared_at = _timestamp(prepared_instant)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT ag.*, da.attestation_id, da.decision_json, da.decision_hash,
                       na.status AS attestation_status, p.policy_json,
                       p.revoked_at AS policy_revoked_at, e.active_policy_id,
                       e.revocation_epoch AS current_epoch, e.status AS engagement_status,
                       s.global_status
                FROM action_grants ag
                JOIN destination_authorizations da ON da.grant_id = ag.grant_id
                JOIN network_attestations na ON na.attestation_id = da.attestation_id
                JOIN policy_bundles p ON p.id = ag.policy_bundle_id
                JOIN engagements e ON e.id = ag.engagement_id
                CROSS JOIN safety_state s
                WHERE ag.grant_id = ? AND da.authorization_id = ?
                """,
                (grant_id, destination_authorization_id),
            ).fetchone()
            if row is None:
                raise DomainError("GATEWAY_SESSION_DENIED", "runtime authorization is missing")
            existing = connection.execute(
                "SELECT reservation_id FROM budget_reservations WHERE grant_id = ?",
                (grant_id,),
            ).fetchone()
            if existing is not None:
                raise DomainError("GATEWAY_SESSION_REPLAYED", "authority is already reserved")
            grant = json.loads(row["grant_json"])
            decision = json.loads(row["decision_json"])
            policy = json.loads(row["policy_json"])
            now = parse_time(prepared_at)
            if (
                contract_issues(grant, "action-grant-v1.schema.json")
                or contract_issues(decision, "destination-decision-v1.schema.json")
                or content_hash(grant) != row["grant_hash"]
                or content_hash(decision) != row["decision_hash"]
                or decision.get("outcome") != "allow"
                or decision.get("execution_enabled") is not False
                or decision.get("grant_id") != grant_id
                or decision.get("attestation_id") != row["attestation_id"]
                or grant.get("audience") != "pentai-egress-gateway"
                or row["audience"] != "pentai-egress-gateway"
                or row["used_at"] is not None
                or row["revoked_at"] is not None
                or parse_time(grant["not_before"]) > now
                or parse_time(grant["expires_at"]) <= now
                or row["policy_revoked_at"] is not None
                or row["active_policy_id"] != row["policy_bundle_id"]
                or row["revocation_epoch"] != row["current_epoch"]
                or row["engagement_status"] != "active"
                or row["global_status"] != "active"
                or row["attestation_status"] != "valid"
                or self.policy_signer is None
                or not self.policy_signer.verify(
                    _grant_payload(grant),
                    str(grant.get("signature", {}).get("value", "")),
                    str(grant.get("signature", {}).get("key_id", "")),
                )
            ):
                raise DomainError("GATEWAY_SESSION_DENIED", "runtime authority is inactive")
            budgets = policy["budgets"]
            try:
                request_limit = int(budgets["maximum_total_requests"])
                connection_limit = int(budgets["concurrent_connections"])
                global_rps = float(budgets["global_rps"])
                host_rps = float(budgets["per_host_rps"])
                burst = int(budgets["burst"])
                response_limit = min(
                    int(budgets["maximum_response_bytes"]),
                    int(grant["constraints"]["maximum_response_bytes"]),
                )
                host = decision["candidate"]["host"]
                host_key = str(host["value"])
                if (
                    request_limit < 1
                    or connection_limit < 1
                    or not math.isfinite(global_rps)
                    or not math.isfinite(host_rps)
                    or global_rps <= 0
                    or host_rps <= 0
                    or burst < 1
                    or not host_key
                ):
                    raise ValueError
            except (KeyError, TypeError, ValueError) as exc:
                raise DomainError("GATEWAY_SESSION_DENIED", "rate policy is invalid") from exc
            connection.execute(
                """
                INSERT INTO budget_accounts(
                    engagement_id, policy_bundle_id, request_limit, connection_limit,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id) DO UPDATE SET
                    policy_bundle_id = excluded.policy_bundle_id,
                    request_limit = excluded.request_limit,
                    connection_limit = excluded.connection_limit,
                    updated_at = excluded.updated_at
                """,
                (
                    row["engagement_id"],
                    row["policy_bundle_id"],
                    request_limit,
                    connection_limit,
                    prepared_at,
                ),
            )
            reserved = connection.execute(
                """
                UPDATE budget_accounts
                SET reserved_requests = reserved_requests + 1,
                    active_connections = active_connections + 1, updated_at = ?
                WHERE engagement_id = ?
                  AND reserved_requests + committed_requests + 1 <= request_limit
                  AND active_connections + 1 <= connection_limit
                """,
                (prepared_at, row["engagement_id"]),
            )
            if reserved.rowcount != 1:
                raise DomainError("BUDGET_EXHAUSTED", "request or concurrency budget is exhausted")
            reservation_id = str(uuid4())
            session_id = str(uuid4())
            self._reserve_rate_bucket(
                connection,
                engagement_id=row["engagement_id"],
                policy_bundle_id=row["policy_bundle_id"],
                bucket_key="global",
                refill_rate=global_rps,
                capacity=burst,
                reserved_at=prepared_instant,
            )
            self._reserve_rate_bucket(
                connection,
                engagement_id=row["engagement_id"],
                policy_bundle_id=row["policy_bundle_id"],
                bucket_key=f"host:{host_key}",
                refill_rate=host_rps,
                capacity=burst,
                reserved_at=prepared_instant,
            )
            try:
                connection.execute(
                    """
                    INSERT INTO budget_reservations(
                        reservation_id, engagement_id, policy_bundle_id, grant_id,
                        destination_authorization_id, request_count, response_bytes_limit,
                        status, reserved_at
                    ) VALUES (?, ?, ?, ?, ?, 1, ?, 'reserved', ?)
                    """,
                    (
                        reservation_id,
                        row["engagement_id"],
                        row["policy_bundle_id"],
                        grant_id,
                        destination_authorization_id,
                        response_limit,
                        prepared_at,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO gateway_rate_reservations(
                        reservation_id, engagement_id, policy_bundle_id,
                        host_key, status, reserved_at
                    ) VALUES (?, ?, ?, ?, 'reserved', ?)
                    """,
                    (
                        reservation_id,
                        row["engagement_id"],
                        row["policy_bundle_id"],
                        host_key,
                        prepared_at,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO gateway_sessions(
                        session_id, reservation_id, grant_id, attestation_id,
                        destination_authorization_id, status, prepared_at,
                        execution_enabled
                    ) VALUES (?, ?, ?, ?, ?, 'prepared', ?, 0)
                    """,
                    (
                        session_id,
                        reservation_id,
                        grant_id,
                        row["attestation_id"],
                        destination_authorization_id,
                        prepared_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError(
                    "GATEWAY_SESSION_REPLAYED", "authority is already reserved"
                ) from exc
            document = {
                "schema_version": "1.0.0",
                "session_id": session_id,
                "reservation_id": reservation_id,
                "grant_id": grant_id,
                "attestation_id": row["attestation_id"],
                "destination_authorization_id": destination_authorization_id,
                "status": "prepared",
                "request_count": 1,
                "response_bytes_limit": response_limit,
                "prepared_at": prepared_at,
                "execution_enabled": False,
            }
            if contract_issues(document, "gateway-session-v1.schema.json"):
                raise DomainError("GATEWAY_SESSION_DENIED", "generated session is invalid")
            self._audit(
                connection,
                action="gateway.session_prepared",
                subject_type="gateway_session",
                subject_id=session_id,
                actor_type="service",
                actor_id="gateway-control",
                data={
                    "reservation_id": reservation_id,
                    "grant_id": grant_id,
                    "destination_authorization_id": destination_authorization_id,
                    "execution_enabled": False,
                },
                occurred_at=prepared_at,
            )
        return document

    def abort_gateway_session(self, session_id: str, *, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise DomainError("SESSION_REASON_REQUIRED", "session abort reason is required")
        finalized_at = _timestamp()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT gs.*, br.engagement_id FROM gateway_sessions gs
                JOIN budget_reservations br ON br.reservation_id = gs.reservation_id
                WHERE gs.session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if row is None:
                raise DomainError("GATEWAY_SESSION_NOT_FOUND", "gateway session does not exist")
            if row["status"] != "prepared":
                raise DomainError("GATEWAY_SESSION_FINALIZED", "gateway session is already final")
            if connection.execute(
                "SELECT 1 FROM gateway_request_starts WHERE session_id = ?", (session_id,)
            ).fetchone() is not None:
                raise DomainError(
                    "GATEWAY_REQUEST_COMMITTED", "committed request capacity cannot be refunded"
                )
            self._release_rate_reservation(
                connection,
                reservation_id=row["reservation_id"],
                finalized_at=parse_time(finalized_at),
            )
            connection.execute(
                """
                UPDATE budget_accounts
                SET reserved_requests = reserved_requests - 1,
                    active_connections = active_connections - 1, updated_at = ?
                WHERE engagement_id = ?
                """,
                (finalized_at, row["engagement_id"]),
            )
            connection.execute(
                """
                UPDATE budget_reservations SET status = 'released', finalized_at = ?
                WHERE reservation_id = ? AND status = 'reserved'
                """,
                (finalized_at, row["reservation_id"]),
            )
            connection.execute(
                """
                UPDATE gateway_sessions SET status = 'aborted', finalized_at = ?
                WHERE session_id = ? AND status = 'prepared'
                """,
                (finalized_at, session_id),
            )
            self._audit(
                connection,
                action="gateway.session_aborted",
                subject_type="gateway_session",
                subject_id=session_id,
                actor_type="service",
                actor_id="gateway-control",
                data={"reason": reason.strip()},
                occurred_at=finalized_at,
            )
        return {
            "session_id": session_id,
            "status": "aborted",
            "finalized_at": finalized_at,
            "execution_enabled": False,
        }

    def recover_startup(self) -> dict[str, Any]:
        recovered_at = _timestamp()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            revoked = connection.execute(
                """
                UPDATE action_grants SET revoked_at = ?
                WHERE used_at IS NULL AND revoked_at IS NULL
                """,
                (recovered_at,),
            ).rowcount
            affected = connection.execute(
                """
                UPDATE engagements
                SET status = 'paused', revocation_epoch = revocation_epoch + 1
                WHERE status = 'active'
                """
            ).rowcount
            invalidated = connection.execute(
                """
                UPDATE network_attestations
                SET status = 'invalidated', invalidated_at = ?
                WHERE status = 'valid'
                """,
                (recovered_at,),
            ).rowcount
            aborted_sessions = self._abort_gateway_sessions(
                connection, finalized_at=recovered_at
            )
            connection.execute(
                """
                UPDATE safety_state
                SET global_status = 'paused', reason = 'startup recovery requires human resume',
                    generation = generation + 1, updated_at = ?, updated_by = 'startup-recovery'
                WHERE singleton_id = 1
                """,
                (recovered_at,),
            )
            self._audit(
                connection,
                action="safety.startup_recovery",
                subject_type="safety_state",
                subject_id="global",
                actor_type="service",
                actor_id="startup-recovery",
                data={
                    "revoked_grants": revoked,
                    "paused_assessments": affected,
                    "invalidated_attestations": invalidated,
                    "aborted_gateway_sessions": aborted_sessions,
                },
                occurred_at=recovered_at,
            )
        return {
            "status": "paused",
            "revoked_grants": revoked,
            "paused_assessments": affected,
            "invalidated_attestations": invalidated,
            "aborted_gateway_sessions": aborted_sessions,
        }

    def set_global_safety(self, *, status: str, reason: str, actor_id: str) -> dict[str, Any]:
        if status not in {"active", "paused", "stopped"}:
            raise DomainError("SAFETY_STATE_INVALID", "global safety state is invalid")
        if not reason.strip():
            raise DomainError("SAFETY_REASON_REQUIRED", "safety reason is required")
        changed_at = _timestamp()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            revoked = 0
            affected = 0
            invalidated = 0
            aborted_sessions = 0
            if status in {"paused", "stopped"}:
                revoked = connection.execute(
                    """
                    UPDATE action_grants SET revoked_at = ?
                    WHERE used_at IS NULL AND revoked_at IS NULL
                    """,
                    (changed_at,),
                ).rowcount
                affected = connection.execute(
                    """
                    UPDATE engagements
                    SET status = 'paused', revocation_epoch = revocation_epoch + 1
                    WHERE status = 'active'
                    """
                ).rowcount
                invalidated = connection.execute(
                    """
                    UPDATE network_attestations
                    SET status = 'invalidated', invalidated_at = ?
                    WHERE status = 'valid'
                    """,
                    (changed_at,),
                ).rowcount
                aborted_sessions = self._abort_gateway_sessions(
                    connection, finalized_at=changed_at
                )
            connection.execute(
                """
                UPDATE safety_state
                SET global_status = ?, reason = ?, generation = generation + 1,
                    updated_at = ?, updated_by = ? WHERE singleton_id = 1
                """,
                (status, reason.strip(), changed_at, actor_id),
            )
            self._audit(
                connection,
                action=f"safety.global_{status}",
                subject_type="safety_state",
                subject_id="global",
                actor_type="human",
                actor_id=actor_id,
                data={
                    "reason": reason.strip(),
                    "revoked_grants": revoked,
                    "paused_assessments": affected,
                    "invalidated_attestations": invalidated,
                    "aborted_gateway_sessions": aborted_sessions,
                },
                occurred_at=changed_at,
            )
        return self.safety_state()

    def set_assessment_safety(
        self, engagement_id: str, *, status: str, reason: str, actor_id: str
    ) -> dict[str, Any]:
        if status not in {"active", "paused"}:
            raise DomainError("ASSESSMENT_STATE_INVALID", "assessment safety state is invalid")
        if not reason.strip():
            raise DomainError("SAFETY_REASON_REQUIRED", "safety reason is required")
        changed_at = _timestamp()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            engagement = connection.execute(
                "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
            ).fetchone()
            if engagement is None:
                raise DomainError("ENGAGEMENT_NOT_FOUND", "engagement does not exist")
            global_state = connection.execute(
                "SELECT global_status FROM safety_state WHERE singleton_id = 1"
            ).fetchone()
            if status == "active" and (
                global_state is None
                or global_state["global_status"] != "active"
                or engagement["active_policy_id"] is None
            ):
                raise DomainError("SAFETY_RESUME_DENIED", "assessment cannot safely resume")
            if status == "active":
                policy = connection.execute(
                    "SELECT * FROM policy_bundles WHERE id = ?",
                    (engagement["active_policy_id"],),
                ).fetchone()
                if (
                    policy is None
                    or policy["activated_at"] is None
                    or policy["revoked_at"] is not None
                ):
                    raise DomainError("SAFETY_RESUME_DENIED", "assessment policy is not active")
                try:
                    policy_document = json.loads(policy["policy_json"])
                    signature = policy_document.get("signature", {})
                    policy_expired = parse_time(
                        policy_document["validity"]["not_after"]
                    ) <= parse_time(changed_at)
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    raise DomainError(
                        "SAFETY_RESUME_DENIED", "assessment policy is malformed"
                    ) from None
                if (
                    policy_expired
                    or self.policy_signer is None
                    or signature.get("algorithm") != "Ed25519"
                    or not self.policy_signer.verify(
                        f"pentai-policy-v1:{policy['content_hash']}".encode("ascii"),
                        str(signature.get("value", "")),
                        str(signature.get("key_id", "")),
                    )
                ):
                    raise DomainError("SAFETY_RESUME_DENIED", "assessment policy is unverifiable")
            revoked = 0
            invalidated = 0
            aborted_sessions = 0
            if status == "paused":
                revoked = connection.execute(
                    """
                    UPDATE action_grants SET revoked_at = ?
                    WHERE engagement_id = ? AND used_at IS NULL AND revoked_at IS NULL
                    """,
                    (changed_at, engagement_id),
                ).rowcount
                connection.execute(
                    """
                    UPDATE engagements SET status = 'paused',
                        revocation_epoch = revocation_epoch + 1 WHERE id = ?
                    """,
                    (engagement_id,),
                )
                invalidated = connection.execute(
                    """
                    UPDATE network_attestations
                    SET status = 'invalidated', invalidated_at = ?
                    WHERE engagement_id = ? AND status = 'valid'
                    """,
                    (changed_at, engagement_id),
                ).rowcount
                aborted_sessions = self._abort_gateway_sessions(
                    connection, finalized_at=changed_at, engagement_id=engagement_id
                )
            else:
                connection.execute(
                    "UPDATE engagements SET status = 'active' WHERE id = ?", (engagement_id,)
                )
            self._audit(
                connection,
                action=f"safety.assessment_{status}",
                subject_type="engagement",
                subject_id=engagement_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "reason": reason.strip(),
                    "revoked_grants": revoked,
                    "invalidated_attestations": invalidated,
                    "aborted_gateway_sessions": aborted_sessions,
                },
                occurred_at=changed_at,
            )
        return {"id": engagement_id, "status": status, "changed_at": changed_at}

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

    def save_network_profile_proposal(self, proposal: dict[str, Any]) -> dict[str, Any]:
        if contract_issues(proposal, "network-profile-proposal-v1.schema.json"):
            raise DomainError("NETWORK_PROFILE_PROPOSAL_INVALID", "network proposal is invalid")
        try:
            interface = proposal["route_interface"]
            gateway = (
                ip_address(proposal["route_gateway"]).compressed
                if proposal["route_gateway"] is not None
                else None
            )
            resolvers = tuple(
                sorted({ip_address(value).compressed for value in proposal["resolver_addresses"]})
            )
            observed_at = parse_time(proposal["observed_at"])
            expires_at = parse_time(proposal["expires_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise DomainError(
                "NETWORK_PROFILE_PROPOSAL_INVALID", "network proposal is invalid"
            ) from exc
        route_identity = {
            "interface": interface,
            "gateway": gateway,
            "resolver_addresses": resolvers,
        }
        expected_route_id = f"route-{content_hash(route_identity)[:24]}"
        expected_resolver_id = f"resolver-{content_hash(resolvers)[:24]}"
        if (
            interface != interface.strip()
            or proposal["route_gateway"] != gateway
            or proposal["resolver_addresses"] != list(resolvers)
            or proposal["route_profile_id"] != expected_route_id
            or proposal["resolver_id"] != expected_resolver_id
        ):
            raise DomainError("NETWORK_PROFILE_PROPOSAL_INVALID", "network proposal is invalid")
        now = _now()
        if (
            expires_at <= observed_at
            or expires_at - observed_at > timedelta(minutes=10)
            or observed_at > now
            or expires_at <= now
        ):
            raise DomainError("NETWORK_PROFILE_PROPOSAL_STALE", "network proposal has expired")
        serialized = canonical_json(proposal)
        proposal_hash = content_hash(proposal)
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            stale_ids = [
                row["proposal_id"]
                for row in connection.execute(
                    """
                    SELECT proposal_id, expires_at FROM network_profile_proposals
                    WHERE status = 'pending'
                    """
                ).fetchall()
                if parse_time(row["expires_at"]) <= now
            ]
            connection.executemany(
                "UPDATE network_profile_proposals SET status = 'expired' WHERE proposal_id = ?",
                ((proposal_id,) for proposal_id in stale_ids),
            )
            existing = connection.execute(
                """
                SELECT document_json, content_hash, status FROM network_profile_proposals
                WHERE proposal_id = ?
                """,
                (proposal["proposal_id"],),
            ).fetchone()
            if existing is not None:
                identity_matches = (
                    existing["document_json"] == serialized
                    and existing["content_hash"] == proposal_hash
                )
                if not identity_matches:
                    raise DomainError(
                        "NETWORK_PROFILE_PROPOSAL_CONFLICT", "network proposal identity conflicts"
                    )
                if existing["status"] != "pending":
                    raise DomainError(
                        "NETWORK_PROFILE_PROPOSAL_USED", "network proposal is no longer pending"
                    )
                return proposal
            pending_count = connection.execute(
                "SELECT COUNT(*) AS amount FROM network_profile_proposals WHERE status = 'pending'"
            ).fetchone()
            if pending_count is None or pending_count["amount"] >= 64:
                raise DomainError(
                    "NETWORK_PROFILE_PROPOSAL_CAPACITY",
                    "too many network proposals await confirmation",
                )
            connection.execute(
                """
                INSERT INTO network_profile_proposals(
                    proposal_id, document_json, content_hash, route_profile_id,
                    observed_at, expires_at, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
                """,
                (
                    proposal["proposal_id"],
                    serialized,
                    proposal_hash,
                    proposal["route_profile_id"],
                    proposal["observed_at"],
                    proposal["expires_at"],
                    _timestamp(),
                ),
            )
        return proposal

    def activate_network_profile(
        self,
        proposal_id: str,
        *,
        confirm_route: bool,
        resolver_mode: str,
        registered_source_ipv4: list[str],
        registered_source_ipv6: list[str],
        ipv6_mode: str,
        actor_id: str,
    ) -> dict[str, Any]:
        if not confirm_route:
            raise DomainError(
                "NETWORK_PROFILE_CONFIRMATION_REQUIRED", "route confirmation is required"
            )
        if resolver_mode not in {"tunnel_resolver", "approved_resolver"}:
            raise DomainError("NETWORK_PROFILE_RESOLVER_INVALID", "resolver mode is invalid")
        if ipv6_mode not in {"disabled", "approved_only"}:
            raise DomainError("NETWORK_PROFILE_IPV6_INVALID", "IPv6 mode is invalid")
        if not actor_id.strip() or len(actor_id) > 128:
            raise DomainError("NETWORK_PROFILE_ACTOR_INVALID", "actor identity is invalid")
        ipv4 = _canonical_registered_sources(registered_source_ipv4, version=4)
        ipv6 = _canonical_registered_sources(registered_source_ipv6, version=6)
        if ipv6_mode == "disabled" and ipv6:
            raise DomainError(
                "NETWORK_PROFILE_IPV6_CONFLICT", "disabled IPv6 cannot have registered addresses"
            )
        if ipv6_mode == "approved_only" and not ipv6:
            raise DomainError(
                "NETWORK_PROFILE_IPV6_REQUIRED", "approved IPv6 requires a registered address"
            )
        if not ipv4 and not ipv6:
            raise DomainError(
                "NETWORK_PROFILE_SOURCE_REQUIRED", "a registered public source IP is required"
            )
        confirmed_at = _timestamp()
        profile_id = str(uuid4())
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            proposal_row = connection.execute(
                "SELECT * FROM network_profile_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if proposal_row is None:
                raise DomainError(
                    "NETWORK_PROFILE_PROPOSAL_MISSING", "network proposal does not exist"
                )
            if proposal_row["status"] != "pending":
                raise DomainError(
                    "NETWORK_PROFILE_PROPOSAL_USED", "network proposal is no longer pending"
                )
            if parse_time(proposal_row["expires_at"]) <= parse_time(confirmed_at):
                raise DomainError("NETWORK_PROFILE_PROPOSAL_STALE", "network proposal has expired")
            if connection.execute(
                "SELECT 1 FROM network_profiles WHERE status = 'active'"
            ).fetchone():
                raise DomainError(
                    "NETWORK_PROFILE_ACTIVE_CONFLICT",
                    "revoke the active network profile before activating another",
                )
            proposal = json.loads(proposal_row["document_json"])
            profile = {
                "schema_version": "1.0.0",
                "profile_id": profile_id,
                "proposal_id": proposal_id,
                "route_profile_id": proposal["route_profile_id"],
                "route_interface": proposal["route_interface"],
                "route_gateway": proposal["route_gateway"],
                "resolver_mode": resolver_mode,
                "resolver_id": proposal["resolver_id"],
                "resolver_addresses": proposal["resolver_addresses"],
                "registered_source_ipv4": list(ipv4),
                "registered_source_ipv6": list(ipv6),
                "ipv6_mode": ipv6_mode,
                "status": "active",
                "confirmed_by": actor_id,
                "confirmed_at": confirmed_at,
                "revoked_at": None,
                "revocation_reason": None,
                "execution_enabled": False,
            }
            if contract_issues(profile, "network-profile-v1.schema.json"):
                raise DomainError("NETWORK_PROFILE_INVALID", "network profile is invalid")
            connection.execute(
                """
                INSERT INTO network_profiles(
                    profile_id, proposal_id, route_profile_id, route_interface,
                    route_gateway, resolver_mode, resolver_id, resolver_addresses_json,
                    registered_source_ipv4_json, registered_source_ipv6_json, ipv6_mode,
                    status, confirmed_by, confirmed_at, revoked_at, revocation_reason,
                    execution_enabled
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL, NULL, 0)
                """,
                (
                    profile_id,
                    proposal_id,
                    profile["route_profile_id"],
                    profile["route_interface"],
                    profile["route_gateway"],
                    resolver_mode,
                    profile["resolver_id"],
                    canonical_json(profile["resolver_addresses"]),
                    canonical_json(profile["registered_source_ipv4"]),
                    canonical_json(profile["registered_source_ipv6"]),
                    ipv6_mode,
                    actor_id,
                    confirmed_at,
                ),
            )
            connection.execute(
                "UPDATE network_profile_proposals SET status = 'confirmed' WHERE proposal_id = ?",
                (proposal_id,),
            )
            self._audit(
                connection,
                action="network_profile.activated",
                subject_type="network_profile",
                subject_id=profile_id,
                actor_type="human",
                actor_id=actor_id,
                data={
                    "proposal_id": proposal_id,
                    "profile_hash": content_hash(profile),
                    "route_profile_id": profile["route_profile_id"],
                    "resolver_id": profile["resolver_id"],
                    "resolver_mode": resolver_mode,
                    "ipv4_source_count": len(ipv4),
                    "ipv6_source_count": len(ipv6),
                    "execution_enabled": False,
                },
                occurred_at=confirmed_at,
            )
        return profile

    def list_network_profiles(self) -> list[dict[str, Any]]:
        with transaction(self.database_path) as connection:
            rows = connection.execute(
                "SELECT * FROM network_profiles ORDER BY confirmed_at, profile_id"
            ).fetchall()
        return [_network_profile_from_row(row) for row in rows]

    def network_profile_for_assessment(self, engagement_id: str) -> dict[str, Any]:
        with transaction(self.database_path) as connection:
            row = connection.execute(
                """
                SELECT np.*, p.policy_json
                FROM engagements e
                JOIN policy_bundles p ON p.id = e.active_policy_id
                JOIN network_profiles np ON np.status = 'active'
                WHERE e.id = ? AND e.status = 'active'
                  AND p.activated_at IS NOT NULL AND p.revoked_at IS NULL
                """,
                (engagement_id,),
            ).fetchone()
        if row is None:
            raise DomainError(
                "NETWORK_PROFILE_BINDING_MISSING",
                "active policy has no confirmed network profile",
            )
        profile = _network_profile_from_row(row)
        if contract_issues(profile, "network-profile-v1.schema.json"):
            raise DomainError("NETWORK_PROFILE_INVALID", "network profile is invalid")
        try:
            network = json.loads(row["policy_json"])["network_constraints"]
            matches = (
                network["route_profile_id"] == profile["route_profile_id"]
                and network["dns_mode"] == profile["resolver_mode"]
                and network["ipv6_mode"] == profile["ipv6_mode"]
                and set(network["registered_source_ipv4"])
                == set(profile["registered_source_ipv4"])
                and set(network["registered_source_ipv6"])
                == set(profile["registered_source_ipv6"])
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DomainError(
                "NETWORK_PROFILE_POLICY_MISMATCH",
                "active policy and network profile do not match",
            ) from exc
        if not matches:
            raise DomainError(
                "NETWORK_PROFILE_POLICY_MISMATCH",
                "active policy and network profile do not match",
            )
        return profile

    def revoke_network_profile(
        self, profile_id: str, *, reason: str, actor_id: str
    ) -> dict[str, Any]:
        if not reason.strip() or len(reason) > 500:
            raise DomainError("NETWORK_PROFILE_REASON_INVALID", "revocation reason is invalid")
        revoked_at = _timestamp()
        with transaction(self.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM network_profiles WHERE profile_id = ?", (profile_id,)
            ).fetchone()
            if row is None:
                raise DomainError("NETWORK_PROFILE_MISSING", "network profile does not exist")
            if row["status"] != "active":
                raise DomainError("NETWORK_PROFILE_REVOKED", "network profile is not active")
            connection.execute(
                """
                UPDATE network_profiles
                SET status = 'revoked', revoked_at = ?, revocation_reason = ?
                WHERE profile_id = ?
                """,
                (revoked_at, reason.strip(), profile_id),
            )
            self._audit(
                connection,
                action="network_profile.revoked",
                subject_type="network_profile",
                subject_id=profile_id,
                actor_type="human",
                actor_id=actor_id,
                data={"reason": reason.strip(), "execution_enabled": False},
                occurred_at=revoked_at,
            )
            updated = connection.execute(
                "SELECT * FROM network_profiles WHERE profile_id = ?", (profile_id,)
            ).fetchone()
        assert updated is not None
        return _network_profile_from_row(updated)

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
