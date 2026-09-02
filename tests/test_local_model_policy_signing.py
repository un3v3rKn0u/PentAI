from __future__ import annotations

import copy
import sqlite3
import tempfile
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.migrate import migrate
from pentai_core.policy_signing import PolicySigner, policy_signature_payload
from pentai_core.source_store import EncryptedSourceStore
from pentai_policy import content_hash
from test_authorization_slice import timestamp
from test_local_model_policy_representation import local_manifest


@pytest.fixture
def authorization_state():
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / "pentai.db"
        migrate(database)
        service = AuthorizationService(
            database,
            source_store=EncryptedSourceStore(Path(directory) / "sources", b"k" * 32),
            policy_signer=PolicySigner(b"s" * 32),
        )
        program = service.create_program("Synthetic local policy program")
        engagement = service.create_engagement(
            program["id"],
            effective_from=timestamp(timedelta(hours=-1)),
            expires_at=timestamp(timedelta(hours=2)),
            timezone="UTC",
        )
        source = service.import_source(
            program["id"],
            authority="contract",
            reference="synthetic://local-policy-signing",
            content="Synthetic local policy authorization.",
        )
        yield service, {"engagement": engagement, "source": source}


def _stored_v3(authorization_state):
    service, state = authorization_state
    candidate = local_manifest()
    candidate["engagement"] = {
        **candidate["engagement"],
        "id": state["engagement"]["id"],
        "effective_from": state["engagement"]["effective_from"],
        "expires_at": state["engagement"]["expires_at"],
    }
    candidate["sources"] = [
        {
            "source_id": state["source"]["id"],
            "reference": state["source"]["reference"],
            "authority": state["source"]["authority"],
            "retrieved_at": state["source"]["retrieved_at"],
            "content_hash": state["source"]["content_hash"],
        }
    ]
    for references in candidate["field_provenance"].values():
        references[0] = {
            "source_id": state["source"]["id"],
            "content_hash": state["source"]["content_hash"],
        }
    candidate["scope"]["assets"][0]["source_reference"] = state["source"]["id"]
    return service, state, candidate, service.save_manifest(
        state["engagement"]["id"], candidate
    )


def test_policy_ir_v2_is_signed_persisted_and_replayed_inactive(authorization_state) -> None:
    service, state, candidate, version = _stored_v3(authorization_state)
    first = service.compile_policy(version["id"])
    second = service.compile_policy(version["id"])

    assert version["schema_version"] == "3.0.0"
    assert first == second
    assert first["policy"]["schema_version"] == "2.0.0"
    signature = first["policy"]["signature"]
    assert service.policy_signer.verify(
        policy_signature_payload("2.0.0", first["content_hash"]),
        signature["value"],
        signature["key_id"],
    )
    recovered = service.get_policy(state["engagement"]["id"], first["id"])
    assert recovered["status"] == "inactive"
    assert recovered["policy"] == first["policy"]

    with pytest.raises(DomainError, match="approval lifecycle") as approval:
        service.approve_policy(first["id"], approver_id="synthetic-reviewer")
    assert approval.value.code == "POLICY_VERSION_INACTIVE"
    with pytest.raises(DomainError, match="cannot be activated") as activation:
        service.activate_policy(first["id"], actor_id="synthetic-reviewer")
    assert activation.value.code == "POLICY_VERSION_INACTIVE"

    changed = copy.deepcopy(candidate)
    changed["techniques"]["allowed_capabilities"] = ["network.http.get"]
    changed_version = service.save_manifest(state["engagement"]["id"], changed)
    assert changed_version["id"] != version["id"]
    assert service.compile_policy(changed_version["id"])["content_hash"] != first["content_hash"]


def test_policy_ir_v2_requires_signer_and_immutable_manifest_lineage(
    authorization_state,
) -> None:
    service, state, _candidate, version = _stored_v3(authorization_state)
    unsigned = AuthorizationService(service.database_path, source_store=service.source_store)
    with pytest.raises(DomainError) as unavailable:
        unsigned.compile_policy(version["id"])
    assert unavailable.value.code == "POLICY_SIGNER_UNAVAILABLE"

    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="manifest versions are immutable"):
            connection.execute(
                "UPDATE manifest_versions SET content_hash = ? WHERE id = ?",
                ("f" * 64, version["id"]),
            )


def test_policy_ir_v2_storage_guards_deny_mutation_activation_and_delete(
    authorization_state,
) -> None:
    service, _state, _candidate, version = _stored_v3(authorization_state)
    bundle = service.compile_policy(version["id"])
    with closing(sqlite3.connect(service.database_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE policy_bundles SET activated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (bundle["id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM policy_bundles WHERE id = ?", (bundle["id"],))


def test_policy_signature_domains_are_version_exact() -> None:
    signer = PolicySigner(b"s" * 32)
    digest = content_hash({"synthetic": True})
    signature = signer.sign(policy_signature_payload("2.0.0", digest))
    assert signer.verify(policy_signature_payload("2.0.0", digest), signature, signer.key_id)
    assert not signer.verify(policy_signature_payload("1.0.0", digest), signature, signer.key_id)
    with pytest.raises(ValueError, match="unsupported"):
        policy_signature_payload("3.0.0", digest)
