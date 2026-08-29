from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues


def _requester() -> dict[str, str]:
    return {
        "actor_type": "human",
        "actor_id": "local-desktop-session",
        "session_id": str(uuid4()),
    }


def _command() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "snapshot_id": str(uuid4()),
        "registry_id": str(uuid4()),
        "registry_revision": 4,
        "registry_digest": "sha256:" + "a" * 64,
        "providers_digest": "sha256:" + "b" * 64,
        "requester": _requester(),
        "authentication_context": "local_core_authenticated_session",
        "purpose": "record_provider_registry_snapshot",
        "requested_at": "2026-08-29T21:30:00Z",
        "expires_at": "2026-08-29T21:35:00Z",
        "production_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def test_snapshot_command_requires_authenticated_local_principal_and_is_inert() -> None:
    command = _command()
    assert contract_issues(
        command, "ai-provider-registry-snapshot-command-v1.schema.json"
    ) == ()
    for key, value in (
        ("schema_version", "2.0.0"),
        ("authentication_context", "caller_assertion"),
        ("purpose", "activate_provider_registry"),
        ("production_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = copy.deepcopy(command)
        malformed[key] = value
        assert contract_issues(
            malformed, "ai-provider-registry-snapshot-command-v1.schema.json"
        )
    for actor in ("caller-selected", "pentai-core", "worker-runtime"):
        malformed = copy.deepcopy(command)
        malformed["requester"]["actor_id"] = actor
        assert contract_issues(
            malformed, "ai-provider-registry-snapshot-command-v1.schema.json"
        )


def test_snapshot_command_rejects_missing_identity_and_unrestricted_payloads() -> None:
    for field in ("actor_id", "session_id"):
        malformed = _command()
        del malformed["requester"][field]
        assert contract_issues(
            malformed, "ai-provider-registry-snapshot-command-v1.schema.json"
        )
    for field in (
        "registry_document",
        "secret_ref",
        "signature",
        "provider_response",
        "diagnostic",
    ):
        malformed = _command()
        malformed[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed, "ai-provider-registry-snapshot-command-v1.schema.json"
        )


def test_snapshot_receipt_v2_binds_command_and_authentication_without_authority() -> None:
    command = _command()
    receipt = {
        "schema_version": "2.0.0",
        "snapshot_id": command["snapshot_id"],
        "snapshot_digest": "sha256:" + "c" * 64,
        "command_id": command["command_id"],
        "command_digest": "sha256:" + "d" * 64,
        "registry_id": command["registry_id"],
        "registry_revision": command["registry_revision"],
        "registry_digest": command["registry_digest"],
        "providers_digest": command["providers_digest"],
        "requester": command["requester"],
        "authentication_context": command["authentication_context"],
        "state": "inactive",
        "activation_enabled": False,
        "revocation_enabled": False,
        "production_enabled": False,
        "recorded_at": "2026-08-29T21:30:01Z",
        "authority": "none",
        "execution_enabled": False,
    }
    assert contract_issues(
        receipt, "ai-provider-registry-snapshot-receipt-v2.schema.json"
    ) == ()
    for field in ("activation", "revocation", "meter", "provider_request", "payload"):
        malformed = copy.deepcopy(receipt)
        malformed[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed, "ai-provider-registry-snapshot-receipt-v2.schema.json"
        )
