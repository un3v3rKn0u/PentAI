from __future__ import annotations

import copy
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues


def command() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "snapshot_id": str(uuid4()),
        "snapshot_digest": "sha256:" + "a" * 64,
        "snapshot_receipt_digest": "sha256:" + "b" * 64,
        "registry_id": str(uuid4()),
        "registry_revision": 4,
        "registry_digest": "sha256:" + "c" * 64,
        "providers_digest": "sha256:" + "d" * 64,
        "requester": {
            "actor_type": "human",
            "actor_id": "local-desktop-session",
            "session_id": str(uuid4()),
        },
        "authentication_context": "local_core_authenticated_session",
        "purpose": "activate_provider_registry_snapshot",
        "requested_at": "2026-08-30T10:00:00Z",
        "expires_at": "2026-08-30T10:05:00Z",
        "activation_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def receipt(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "activation_id": str(uuid4()),
        "command_id": source["command_id"],
        "command_digest": "sha256:" + "f" * 64,
        "snapshot_id": source["snapshot_id"],
        "snapshot_digest": source["snapshot_digest"],
        "snapshot_receipt_digest": source["snapshot_receipt_digest"],
        "registry_id": source["registry_id"],
        "registry_revision": source["registry_revision"],
        "registry_digest": source["registry_digest"],
        "providers_digest": source["providers_digest"],
        "requester": source["requester"],
        "authentication_context": source["authentication_context"],
        "state": "active",
        "configuration_snapshot_enabled": False,
        "revocation_enabled": False,
        "activated_at": "2026-08-30T10:00:01Z",
        "expires_at": "2026-09-13T10:00:00Z",
        "authority": "none",
        "execution_enabled": False,
    }


def test_activation_contracts_bind_exact_snapshot_lineage_without_authority() -> None:
    request = command()
    assert contract_issues(request, "ai-provider-registry-activation-command-v1.schema.json") == ()
    assert (
        contract_issues(receipt(request), "ai-provider-registry-activation-receipt-v1.schema.json")
        == ()
    )


def test_activation_command_rejects_mixed_versions_and_caller_privilege() -> None:
    for field, value in (
        ("schema_version", "2.0.0"),
        ("authentication_context", "caller_assertion"),
        ("purpose", "invoke_provider"),
        ("activation_enabled", True),
        ("authority", "provider"),
        ("execution_enabled", True),
    ):
        malformed = copy.deepcopy(command())
        malformed[field] = value
        assert contract_issues(malformed, "ai-provider-registry-activation-command-v1.schema.json")
    malformed = command()
    malformed["requester"]["actor_id"] = "caller-selected"
    assert contract_issues(malformed, "ai-provider-registry-activation-command-v1.schema.json")


def test_activation_receipt_rejects_downstream_behavior_and_payloads() -> None:
    source = command()
    for field in ("configuration_snapshot_enabled", "revocation_enabled", "execution_enabled"):
        malformed = receipt(source)
        malformed[field] = True
        assert contract_issues(malformed, "ai-provider-registry-activation-receipt-v1.schema.json")
    for field in ("provider_request", "secret_reference", "payload", "diagnostic"):
        malformed = receipt(source)
        malformed[field] = "synthetic but forbidden"
        assert contract_issues(malformed, "ai-provider-registry-activation-receipt-v1.schema.json")


def test_activation_contracts_require_complete_digest_lineage() -> None:
    for field in (
        "snapshot_digest",
        "snapshot_receipt_digest",
        "registry_digest",
        "providers_digest",
    ):
        malformed_command = command()
        del malformed_command[field]
        assert contract_issues(
            malformed_command, "ai-provider-registry-activation-command-v1.schema.json"
        )
        malformed_receipt = receipt(command())
        del malformed_receipt[field]
        assert contract_issues(
            malformed_receipt, "ai-provider-registry-activation-receipt-v1.schema.json"
        )
