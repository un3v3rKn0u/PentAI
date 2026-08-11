from __future__ import annotations

import base64
import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.evidence import EvidenceError, EvidenceService
from pentai_core.evidence_store import EncryptedEvidenceStore, EvidenceStoreError
from pentai_core.migrate import migrate


def evidence_fixture(tmp_path: Path) -> tuple[Path, str, EvidenceService, EncryptedEvidenceStore]:
    database = tmp_path / "pentai.db"
    migrate(database)
    program_id = str(uuid4())
    engagement_id = str(uuid4())
    manifest_id = str(uuid4())
    policy_id = str(uuid4())
    workflow_id = str(uuid4())
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            "INSERT INTO programs(id, name, status) VALUES (?, 'Synthetic evidence', 'active')",
            (program_id,),
        )
        connection.execute(
            """INSERT INTO engagements(
                id, program_id, status, effective_from, expires_at, timezone
            ) VALUES (?, ?, 'active', '2026-08-01T00:00:00Z',
                      '2026-09-01T00:00:00Z', 'UTC')""",
            (engagement_id, program_id),
        )
        connection.execute(
            """INSERT INTO manifest_versions(
                id, engagement_id, schema_version, document_json, content_hash
            ) VALUES (?, ?, '2.0.0', '{}', ?)""",
            (manifest_id, engagement_id, "a" * 64),
        )
        connection.execute(
            """INSERT INTO policy_bundles(
                id, engagement_id, manifest_version_id, schema_version,
                compiler_version, policy_json, content_hash, activated_at
            ) VALUES (?, ?, ?, '1.0.0', 'test', '{}', ?, '2026-08-01T00:00:00Z')""",
            (policy_id, engagement_id, manifest_id, "b" * 64),
        )
        connection.execute(
            "UPDATE engagements SET active_policy_id = ? WHERE id = ?",
            (policy_id, engagement_id),
        )
        connection.execute(
            """INSERT INTO assessment_workflows(
                workflow_id, engagement_id, policy_bundle_id, idempotency_key,
                status, version, created_at, updated_at, execution_enabled
            ) VALUES (?, ?, ?, 'workflow-fixture-key', 'ready', 2,
                      '2026-08-11T00:00:00Z', '2026-08-11T00:00:00Z', 0)""",
            (workflow_id, engagement_id, policy_id),
        )
    store = EncryptedEvidenceStore(tmp_path / "evidence", b"k" * 32)
    return database, workflow_id, EvidenceService(database, store), store


def capture(service: EvidenceService, workflow_id: str, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "content": b"Synthetic local evidence only.",
        "evidence_kind": "note",
        "media_type": "text/plain",
        "classification": "restricted",
        "idempotency_key": "evidence-fixture-0001",
        "actor_id": "local-reviewer",
    }
    values.update(overrides)
    return service.create_original(workflow_id, **values)  # type: ignore[arg-type]


def test_original_is_encrypted_content_addressed_and_fully_audited(tmp_path: Path) -> None:
    database, workflow_id, service, store = evidence_fixture(tmp_path)
    evidence = capture(service, workflow_id)
    digest = str(evidence["sha256"])
    blob = store.root / digest[:2] / f"{digest}.blob"

    assert blob.read_bytes() != b"Synthetic local evidence only."
    assert store.load(digest) == b"Synthetic local evidence only."
    assert (
        service.load_original(str(evidence["evidence_id"]), actor_id="local-reviewer")
        == b"Synthetic local evidence only."
    )
    metadata = service.metadata(str(evidence["evidence_id"]), actor_id="local-reviewer")
    assert metadata["evidence"] == evidence

    with closing(sqlite3.connect(database)) as connection:
        actions = [
            row[0]
            for row in connection.execute("SELECT action FROM audit_events ORDER BY sequence")
        ]
        custody = [
            row[0]
            for row in connection.execute(
                "SELECT action FROM evidence_custody_events ORDER BY sequence"
            )
        ]
    assert actions == [
        "evidence.original_stored",
        "evidence.content_accessed",
        "evidence.metadata_accessed",
    ]
    assert custody == ["stored", "content_accessed", "metadata_accessed"]


def test_original_and_custody_records_are_database_immutable(tmp_path: Path) -> None:
    database, workflow_id, service, _ = evidence_fixture(tmp_path)
    evidence = capture(service, workflow_id)
    with closing(sqlite3.connect(database)) as connection, connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE evidence_objects SET classification = 'internal' WHERE evidence_id = ?",
                (evidence["evidence_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute(
                "DELETE FROM evidence_custody_events WHERE evidence_id = ?",
                (evidence["evidence_id"],),
            )


def test_tamper_wrong_key_and_idempotency_conflict_fail_closed(tmp_path: Path) -> None:
    _, workflow_id, service, store = evidence_fixture(tmp_path)
    evidence = capture(service, workflow_id)
    with pytest.raises(EvidenceError) as conflict:
        capture(service, workflow_id, content=b"different")
    assert conflict.value.code == "EVIDENCE_IDEMPOTENCY_CONFLICT"
    with pytest.raises(EvidenceError) as metadata_conflict:
        capture(service, workflow_id, classification="internal")
    assert metadata_conflict.value.code == "EVIDENCE_IDEMPOTENCY_CONFLICT"
    digest = str(evidence["sha256"])
    with pytest.raises(EvidenceStoreError, match="authentication failed"):
        EncryptedEvidenceStore(store.root, b"z" * 32).load(digest)
    blob = store.root / digest[:2] / f"{digest}.blob"
    payload = bytearray(blob.read_bytes())
    payload[-1] ^= 1
    blob.write_bytes(payload)
    with pytest.raises(EvidenceError, match="failed closed") as raised:
        service.load_original(str(evidence["evidence_id"]), actor_id="local-reviewer")
    assert raised.value.code == "EVIDENCE_STORAGE_FAILED"


def test_missing_key_and_invalid_inputs_deny_without_plaintext_persistence(tmp_path: Path) -> None:
    database, workflow_id, _, _ = evidence_fixture(tmp_path)
    failures: list[str] = []
    service = EvidenceService(
        database, None, storage_failure_handler=lambda: failures.append("stop")
    )
    with pytest.raises(EvidenceError) as raised:
        capture(service, workflow_id)
    assert raised.value.code == "EVIDENCE_KEY_UNAVAILABLE"
    assert failures == ["stop"]

    _, invalid_workflow_id, service, _ = evidence_fixture(tmp_path / "invalid")
    cases = (
        ({"content": b""}, "EVIDENCE_SIZE_INVALID"),
        ({"evidence_kind": "unknown"}, "EVIDENCE_KIND_INVALID"),
        ({"classification": "public"}, "EVIDENCE_CLASSIFICATION_INVALID"),
        ({"media_type": "text/plain; secret=x"}, "EVIDENCE_MEDIA_TYPE_INVALID"),
    )
    for override, code in cases:
        with pytest.raises(EvidenceError) as invalid:
            capture(service, invalid_workflow_id, **override)
        assert invalid.value.code == code


def test_base64_fixture_is_bounded_synthetic_content() -> None:
    encoded = base64.b64encode(b"synthetic").decode("ascii")
    assert base64.b64decode(encoded, validate=True) == b"synthetic"
