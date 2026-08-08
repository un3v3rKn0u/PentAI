from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.migrate import migrate
from pentai_core.source_store import EncryptedSourceStore, SourceStoreError


class SourceIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        migrate(self.database)
        self.store = EncryptedSourceStore(Path(self.temporary.name) / "sources", b"k" * 32)
        self.service = AuthorizationService(self.database, source_store=self.store)
        self.program = self.service.create_program(
            "Synthetic intake", "local-fixture", program_url="https://example.invalid/program"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def import_source(self) -> dict[str, object]:
        return self.service.import_source(
            self.program["id"],
            authority="contract",
            reference="synthetic://owned-local-fixture",
            content="Synthetic authorization for a non-routable fixture.",
            effective_at="2026-08-08T10:00:00+01:00",
            source_version="fixture-v1",
        )

    def test_pasted_source_is_hashed_listed_idempotently_and_audited(self) -> None:
        first = self.import_source()
        second = self.import_source()

        self.assertEqual(first, second)
        self.assertEqual(first["effective_at"], "2026-08-08T09:00:00Z")
        self.assertEqual(first["source_kind"], "pasted_text")
        self.assertEqual(first["blob_status"], "available")
        self.assertEqual(first["encryption_version"], "aes-256-gcm-v1")
        self.assertEqual(
            self.store.load(str(first["content_hash"])),
            b"Synthetic authorization for a non-routable fixture.",
        )
        self.assertEqual(self.service.list_sources(self.program["id"]), [first])
        events = self.service.audit_events()
        self.assertEqual(
            [event["action"] for event in events],
            ["program.created", "source.imported"],
        )
        self.assertNotIn("Synthetic authorization", str(events))
        self.assertTrue(self.service.verify_audit_chain()["valid"])

    def test_missing_or_ambiguous_provenance_denies(self) -> None:
        cases = (
            ({"authority": "unknown"}, "SOURCE_AUTHORITY_INVALID"),
            ({"reference": "  "}, "SOURCE_REFERENCE_REQUIRED"),
            ({"content": "  "}, "SOURCE_EMPTY"),
            ({"effective_at": "not-a-time"}, "SOURCE_EFFECTIVE_AT_INVALID"),
            ({"source_kind": "file"}, "SOURCE_ACQUISITION_REQUIRED"),
            ({"source_kind": "url"}, "SOURCE_ACQUISITION_REQUIRED"),
        )
        defaults = {
            "authority": "contract",
            "reference": "synthetic://fixture",
            "content": "synthetic",
        }
        for override, expected in cases:
            with self.subTest(expected=expected), self.assertRaises(DomainError) as raised:
                self.service.import_source(self.program["id"], **(defaults | override))
            self.assertEqual(raised.exception.code, expected)

        with self.assertRaises(DomainError) as raised:
            self.service.import_source(str(uuid4()), **defaults)
        self.assertEqual(raised.exception.code, "PROGRAM_NOT_FOUND")

    def test_source_rows_are_immutable(self) -> None:
        source = self.import_source()
        with sqlite3.connect(self.database) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE source_documents SET authority = 'internal_note' WHERE id = ?",
                    (source["id"],),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute("DELETE FROM source_documents WHERE id = ?", (source["id"],))

    def test_tampered_blob_and_wrong_key_fail_authentication(self) -> None:
        source = self.import_source()
        digest = str(source["content_hash"])
        blob = self.store.root / digest[:2] / f"{digest}.blob"
        payload = bytearray(blob.read_bytes())
        payload[-1] ^= 1
        blob.write_bytes(payload)
        with self.assertRaisesRegex(SourceStoreError, "authentication failed"):
            self.store.load(digest)
        with self.assertRaises(DomainError) as raised:
            self.import_source()
        self.assertEqual(raised.exception.code, "SOURCE_STORAGE_FAILED")

        second = self.service.import_source(
            self.program["id"],
            authority="contract",
            reference="synthetic://second",
            content="Different synthetic source",
        )
        with self.assertRaisesRegex(SourceStoreError, "authentication failed"):
            EncryptedSourceStore(self.store.root, b"z" * 32).load(
                str(second["content_hash"])
            )

    def test_missing_encryption_key_denies_before_persistence(self) -> None:
        service = AuthorizationService(self.database)
        with self.assertRaises(DomainError) as raised:
            service.import_source(
                self.program["id"],
                authority="contract",
                reference="synthetic://unavailable",
                content="must not be persisted",
            )
        self.assertEqual(raised.exception.code, "SOURCE_STORAGE_UNAVAILABLE")
        self.assertEqual(len(self.service.list_sources(self.program["id"])), 0)

    def test_atomic_write_failure_leaves_no_partial_blob(self) -> None:
        blocked_root = Path(self.temporary.name) / "not-a-directory"
        blocked_root.write_text("synthetic blocker", encoding="utf-8")
        store = EncryptedSourceStore(blocked_root, b"x" * 32)
        content = b"synthetic atomic failure"
        digest = hashlib.sha256(content).hexdigest()
        with self.assertRaisesRegex(SourceStoreError, "could not be persisted"):
            store.store(content, digest)
        self.assertEqual(list(Path(self.temporary.name).glob("**/*.tmp")), [])

    def test_store_rejects_digest_mismatch_and_invalid_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            EncryptedSourceStore(self.store.root, b"short")
        with self.assertRaisesRegex(SourceStoreError, "does not match provenance"):
            self.store.store(b"synthetic", "0" * 64)
    def test_program_and_source_timestamps_are_current_utc(self) -> None:
        source = self.import_source()
        retrieved = datetime.fromisoformat(str(source["retrieved_at"]).replace("Z", "+00:00"))
        self.assertEqual(retrieved.tzinfo, UTC)


if __name__ == "__main__":
    unittest.main()
