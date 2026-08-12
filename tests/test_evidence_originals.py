from __future__ import annotations

import base64
import sqlite3
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pentai_core.evidence import EvidenceError, EvidenceService
from pentai_core.evidence_store import EncryptedEvidenceStore, EvidenceStoreError
from pentai_core.migrate import migrate
from pentai_policy.document import parse_time

EVIDENCE_ASSET_RULE_ID = "10000000-0000-4000-8000-000000000001"
EVIDENCE_CAPABILITY_RULE_ID = "20000000-0000-4000-8000-000000000001"


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
            ) VALUES (?, ?, '2.0.0', ?, ?)""",
            (
                manifest_id,
                engagement_id,
                '{"data_handling":{"retention_days":1}}',
                "a" * 64,
            ),
        )
        connection.execute(
            """INSERT INTO policy_bundles(
                id, engagement_id, manifest_version_id, schema_version,
                compiler_version, policy_json, content_hash, activated_at
            ) VALUES (?, ?, ?, '1.0.0', 'test', ?, ?, '2026-08-01T00:00:00Z')""",
            (
                policy_id,
                engagement_id,
                manifest_id,
                '{"asset_rules":[{"asset_type":"domain","effect":"allow",'
                f'"rule_id":"{EVIDENCE_ASSET_RULE_ID}"}}],'
                '"capability_rules":[{"capability":"http.get","effect":"allow",'
                f'"rule_id":"{EVIDENCE_CAPABILITY_RULE_ID}",'
                f'"applicable_asset_rule_ids":["{EVIDENCE_ASSET_RULE_ID}"]}}]}}',
                "b" * 64,
            ),
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


def test_redaction_derivative_is_encrypted_immutable_and_plain_text_previewed(
    tmp_path: Path,
) -> None:
    database, workflow_id, service, store = evidence_fixture(tmp_path)
    original = capture(
        service,
        workflow_id,
        content=b"<script>alert(1)</script> token=synthetic-secret",
        media_type="text/html",
    )
    source = "<script>alert(1)</script> token=synthetic-secret"
    start = source.index("synthetic-secret")
    derivative = service.create_redaction(
        str(original["evidence_id"]),
        redactions=[{"start": start, "end": len(source), "reason": "secret"}],
        classification="internal",
        confirm_classification=True,
        idempotency_key="redaction-fixture-0001",
        actor_id="local-reviewer",
    )
    assert derivative["source_sha256"] == original["sha256"]
    assert derivative["sha256"] != original["sha256"]
    assert derivative["media_type"] == "text/plain"
    assert derivative["redactions"] == [
        {
            "start": start,
            "end": len(source),
            "reason": "secret",
            "replacement": "[REDACTED]",
        }
    ]
    digest = str(derivative["sha256"])
    assert store.load(digest) == b"<script>alert(1)</script> token=[REDACTED]"

    preview = service.preview_redaction(str(derivative["derivative_id"]), actor_id="local-reviewer")
    assert preview["render_mode"] == "plain_text"
    assert preview["media_type"] == "text/plain"
    assert preview["active_content_disabled"] is True
    assert preview["content"] == "<script>alert(1)</script> token=[REDACTED]"

    with closing(sqlite3.connect(database)) as connection:
        actions = [
            row[0]
            for row in connection.execute("SELECT action FROM audit_events ORDER BY sequence")
        ]
        events = [
            row[0]
            for row in connection.execute(
                "SELECT action FROM evidence_derivative_events ORDER BY sequence"
            )
        ]
    assert actions == [
        "evidence.original_stored",
        "evidence.content_accessed",
        "evidence.redaction_stored",
        "evidence.redaction_previewed",
    ]
    assert events == ["stored", "previewed"]

    blob = store.root / digest[:2] / f"{digest}.blob"
    payload = bytearray(blob.read_bytes())
    payload[-1] ^= 1
    blob.write_bytes(payload)
    with pytest.raises(EvidenceError) as tampered:
        service.preview_redaction(str(derivative["derivative_id"]), actor_id="local-reviewer")
    assert tampered.value.code == "EVIDENCE_STORAGE_FAILED"


def test_redaction_replay_and_database_history_are_immutable(tmp_path: Path) -> None:
    database, workflow_id, service, _ = evidence_fixture(tmp_path)
    original = capture(service, workflow_id, content=b"keep secret")
    arguments = {
        "redactions": [{"start": 5, "end": 11, "reason": "secret"}],
        "classification": "internal",
        "confirm_classification": True,
        "idempotency_key": "redaction-fixture-0002",
        "actor_id": "local-reviewer",
    }
    first = service.create_redaction(str(original["evidence_id"]), **arguments)  # type: ignore[arg-type]
    second = service.create_redaction(str(original["evidence_id"]), **arguments)  # type: ignore[arg-type]
    assert second == first
    with pytest.raises(EvidenceError) as conflict:
        service.create_redaction(
            str(original["evidence_id"]),
            **(arguments | {"classification": "public"}),  # type: ignore[arg-type]
        )
    assert conflict.value.code == "EVIDENCE_IDEMPOTENCY_CONFLICT"

    with closing(sqlite3.connect(database)) as connection, connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE evidence_derivatives SET classification = 'public' WHERE derivative_id = ?",
                (first["derivative_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute(
                "DELETE FROM evidence_derivative_events WHERE derivative_id = ?",
                (first["derivative_id"],),
            )


def test_redaction_and_preview_reject_unsafe_or_ambiguous_inputs(tmp_path: Path) -> None:
    _, workflow_id, service, _ = evidence_fixture(tmp_path)
    original = capture(service, workflow_id, content=b"0123456789")
    with pytest.raises(EvidenceError) as unconfirmed:
        service.create_redaction(
            str(original["evidence_id"]),
            redactions=[{"start": 0, "end": 1, "reason": "operator_selected"}],
            classification="public",
            confirm_classification=False,
            idempotency_key="redaction-unconfirmed-01",
            actor_id="local-reviewer",
        )
    assert unconfirmed.value.code == "EVIDENCE_CLASSIFICATION_CONFIRMATION_REQUIRED"
    cases = (
        ([], "EVIDENCE_REDACTION_INVALID"),
        (
            [
                {"start": 4, "end": 7, "reason": "secret"},
                {"start": 6, "end": 9, "reason": "secret"},
            ],
            "EVIDENCE_REDACTION_RANGE_INVALID",
        ),
        ([{"start": 2, "end": 99, "reason": "secret"}], "EVIDENCE_REDACTION_RANGE_INVALID"),
        ([{"start": 2, "end": 4, "reason": "unknown"}], "EVIDENCE_REDACTION_RANGE_INVALID"),
    )
    for index, (redactions, code) in enumerate(cases):
        with pytest.raises(EvidenceError) as raised:
            service.create_redaction(
                str(original["evidence_id"]),
                redactions=redactions,
                classification="internal",
                confirm_classification=True,
                idempotency_key=f"redaction-invalid-{index:04d}",
                actor_id="local-reviewer",
            )
        assert raised.value.code == code

    binary = capture(
        service,
        workflow_id,
        content=b"synthetic image",
        evidence_kind="screenshot",
        media_type="image/png",
        idempotency_key="evidence-fixture-0002",
    )
    with pytest.raises(EvidenceError) as unsupported:
        service.create_redaction(
            str(binary["evidence_id"]),
            redactions=[{"start": 0, "end": 1, "reason": "operator_selected"}],
            classification="internal",
            confirm_classification=True,
            idempotency_key="redaction-unsupported-01",
            actor_id="local-reviewer",
        )
    assert unsupported.value.code == "EVIDENCE_REDACTION_UNSUPPORTED"

    invalid_text = capture(
        service,
        workflow_id,
        content=b"\xff\xfe",
        media_type="text/plain",
        idempotency_key="evidence-fixture-0003",
    )
    with pytest.raises(EvidenceError) as invalid_utf8:
        service.create_redaction(
            str(invalid_text["evidence_id"]),
            redactions=[{"start": 0, "end": 1, "reason": "operator_selected"}],
            classification="internal",
            confirm_classification=True,
            idempotency_key="redaction-invalid-utf8",
            actor_id="local-reviewer",
        )
    assert invalid_utf8.value.code == "EVIDENCE_REDACTION_UNSUPPORTED"

    with pytest.raises(EvidenceError) as original_preview:
        service.preview_redaction(str(original["evidence_id"]), actor_id="local-reviewer")
    assert original_preview.value.code == "EVIDENCE_DERIVATIVE_NOT_FOUND"


def test_retention_deletion_unlinks_last_blob_and_preserves_audit_metadata(
    tmp_path: Path,
) -> None:
    database, workflow_id, service, store = evidence_fixture(tmp_path)
    original = capture(service, workflow_id)
    digest = str(original["sha256"])
    deletion = service.delete_artifact(
        "original",
        str(original["evidence_id"]),
        expected_sha256=digest,
        reason="Synthetic fixture retention expired",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
        now=parse_time(str(original["created_at"])) + timedelta(days=2),
    )
    assert deletion["status"] == "completed"
    assert deletion["blob_disposition"] == "unlinked"
    assert deletion["forensic_erase_guaranteed"] is False
    assert not (store.root / digest[:2] / f"{digest}.blob").exists()
    with pytest.raises(EvidenceError) as unavailable:
        service.load_original(str(original["evidence_id"]), actor_id="local-reviewer")
    assert unavailable.value.code == "EVIDENCE_CONTENT_DELETED"
    assert (
        service.metadata(str(original["evidence_id"]), actor_id="local-reviewer")["evidence"]
        == original
    )

    with closing(sqlite3.connect(database)) as connection:
        actions = [
            row[0]
            for row in connection.execute("SELECT action FROM audit_events ORDER BY sequence")
        ]
    assert actions == [
        "evidence.original_stored",
        "evidence.deletion_requested",
        "evidence.deletion_started",
        "evidence.deletion_completed",
        "evidence.metadata_accessed",
    ]
    with closing(sqlite3.connect(database)) as connection, connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE evidence_deletions SET reason = 'changed' WHERE deletion_id = ?",
                (deletion["deletion_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            connection.execute(
                "DELETE FROM evidence_deletions WHERE deletion_id = ?",
                (deletion["deletion_id"],),
            )


def test_retention_and_confirmation_fail_closed_before_request_persistence(
    tmp_path: Path,
) -> None:
    database, workflow_id, service, store = evidence_fixture(tmp_path)
    original = capture(service, workflow_id)
    digest = str(original["sha256"])
    cases = (
        (
            {"confirm_permanent_deletion": False},
            "EVIDENCE_DELETION_CONFIRMATION_REQUIRED",
        ),
        ({"expected_sha256": "0" * 64}, "EVIDENCE_DELETION_DIGEST_MISMATCH"),
        ({"artifact_type": "unknown"}, "EVIDENCE_ARTIFACT_TYPE_INVALID"),
    )
    defaults = {
        "artifact_type": "original",
        "artifact_id": str(original["evidence_id"]),
        "expected_sha256": digest,
        "reason": "Synthetic fixture cleanup",
        "confirm_permanent_deletion": True,
        "actor_id": "local-reviewer",
        "now": parse_time(str(original["created_at"])) + timedelta(days=2),
    }
    for override, code in cases:
        with pytest.raises(EvidenceError) as raised:
            service.delete_artifact(**(defaults | override))  # type: ignore[arg-type]
        assert raised.value.code == code

    with pytest.raises(EvidenceError) as active:
        service.delete_artifact(
            **(defaults | {"now": parse_time(str(original["created_at"])) + timedelta(hours=12)})  # type: ignore[arg-type]
        )
    assert active.value.code == "EVIDENCE_RETENTION_ACTIVE"
    assert store.load(digest) == b"Synthetic local evidence only."
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM evidence_deletions").fetchone()[0] == 0


def test_shared_blob_is_retained_until_every_reference_is_deleted(tmp_path: Path) -> None:
    _, workflow_id, service, store = evidence_fixture(tmp_path)
    first = capture(service, workflow_id)
    second = capture(service, workflow_id, idempotency_key="evidence-fixture-0002")
    digest = str(first["sha256"])
    instant = parse_time(str(first["created_at"])) + timedelta(days=2)

    first_deletion = service.delete_artifact(
        "original",
        str(first["evidence_id"]),
        expected_sha256=digest,
        reason="Delete first synthetic reference",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
        now=instant,
    )
    assert first_deletion["blob_disposition"] == "retained_shared"
    assert (
        service.load_original(str(second["evidence_id"]), actor_id="local-reviewer")
        == b"Synthetic local evidence only."
    )

    second_deletion = service.delete_artifact(
        "original",
        str(second["evidence_id"]),
        expected_sha256=digest,
        reason="Delete final synthetic reference",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
        now=instant,
    )
    assert second_deletion["blob_disposition"] == "unlinked"
    with pytest.raises(EvidenceStoreError, match="unavailable"):
        store.load(digest)


def test_interrupted_deletion_recovers_without_restoring_content(tmp_path: Path) -> None:
    database, workflow_id, service, store = evidence_fixture(tmp_path)
    original = capture(service, workflow_id)
    digest = str(original["sha256"])

    def interrupt() -> None:
        raise RuntimeError("synthetic crash after unlink")

    interrupted = EvidenceService(database, store, deletion_after_blob_handler=interrupt)
    with pytest.raises(RuntimeError, match="synthetic crash"):
        interrupted.delete_artifact(
            "original",
            str(original["evidence_id"]),
            expected_sha256=digest,
            reason="Synthetic crash recovery",
            confirm_permanent_deletion=True,
            actor_id="local-reviewer",
            now=parse_time(str(original["created_at"])) + timedelta(days=2),
        )
    with closing(sqlite3.connect(database)) as connection:
        assert (
            connection.execute("SELECT status FROM evidence_deletions").fetchone()[0]
            == "processing"
        )
    assert not (store.root / digest[:2] / f"{digest}.blob").exists()

    recovered = EvidenceService(database, store)
    assert recovered.recover_deletions() == {"recovered": 1}
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            "SELECT status, blob_disposition FROM evidence_deletions"
        ).fetchone()
    assert row == ("completed", "already_absent")
    with pytest.raises(EvidenceError) as unavailable:
        recovered.load_original(str(original["evidence_id"]), actor_id="local-reviewer")
    assert unavailable.value.code == "EVIDENCE_CONTENT_DELETED"


def test_redaction_deletion_denies_preview_without_deleting_original(tmp_path: Path) -> None:
    _, workflow_id, service, _ = evidence_fixture(tmp_path)
    original = capture(service, workflow_id, content=b"keep secret")
    derivative = service.create_redaction(
        str(original["evidence_id"]),
        redactions=[{"start": 5, "end": 11, "reason": "secret"}],
        classification="internal",
        confirm_classification=True,
        idempotency_key="redaction-deletion-0001",
        actor_id="local-reviewer",
    )
    deletion = service.delete_artifact(
        "redaction",
        str(derivative["derivative_id"]),
        expected_sha256=str(derivative["sha256"]),
        reason="Synthetic redaction retention expired",
        confirm_permanent_deletion=True,
        actor_id="local-reviewer",
        now=parse_time(str(derivative["created_at"])) + timedelta(days=2),
    )
    assert deletion["blob_disposition"] == "unlinked"
    with pytest.raises(EvidenceError) as preview:
        service.preview_redaction(str(derivative["derivative_id"]), actor_id="local-reviewer")
    assert preview.value.code == "EVIDENCE_CONTENT_DELETED"
    assert (
        service.load_original(str(original["evidence_id"]), actor_id="local-reviewer")
        == b"keep secret"
    )
