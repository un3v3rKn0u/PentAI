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


def _command(*, remote: bool = True) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "command_id": str(uuid4()),
        "snapshot_id": str(uuid4()),
        "configuration_id": str(uuid4()),
        "configuration_hash": "a" * 64,
        "activation_id": str(uuid4()),
        "activation_receipt_digest": "sha256:" + "b" * 64,
        "registry_snapshot_id": str(uuid4()),
        "registry_snapshot_digest": "sha256:" + "c" * 64,
        "registry_snapshot_receipt_digest": "sha256:" + "d" * 64,
        "registry_id": str(uuid4()),
        "registry_revision": 5,
        "registry_digest": "sha256:" + "e" * 64,
        "providers_digest": "sha256:" + "f" * 64,
        "provider_type": "approved_remote" if remote else "local_runtime",
        "provider_id": "synthetic-remote" if remote else "synthetic-local",
        "model_id": "synthetic-model-v1",
        "secret_reference_digest": "sha256:" + "1" * 64 if remote else None,
        "requester": _requester(),
        "authentication_context": "local_core_authenticated_session",
        "purpose": "record_provider_configuration_snapshot",
        "requested_at": "2026-08-30T11:00:00Z",
        "expires_at": "2026-08-30T11:05:00Z",
        "production_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


def _receipt(command: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "2.0.0",
        "snapshot_id": command["snapshot_id"],
        "snapshot_digest": "sha256:" + "2" * 64,
        "command_id": command["command_id"],
        "command_digest": "sha256:" + "3" * 64,
        "configuration_id": command["configuration_id"],
        "configuration_hash": command["configuration_hash"],
        "activation_id": command["activation_id"],
        "activation_receipt_digest": command["activation_receipt_digest"],
        "registry_snapshot_id": command["registry_snapshot_id"],
        "registry_snapshot_digest": command["registry_snapshot_digest"],
        "registry_snapshot_receipt_digest": command[
            "registry_snapshot_receipt_digest"
        ],
        "registry_id": command["registry_id"],
        "registry_revision": command["registry_revision"],
        "registry_digest": command["registry_digest"],
        "providers_digest": command["providers_digest"],
        "provider_type": command["provider_type"],
        "provider_id": command["provider_id"],
        "model_id": command["model_id"],
        "secret_reference_digest": command["secret_reference_digest"],
        "requester": command["requester"],
        "authentication_context": command["authentication_context"],
        "state": "inactive",
        "meter_binding_enabled": False,
        "production_enabled": False,
        "recorded_at": "2026-08-30T11:00:01Z",
        "authority": "none",
        "execution_enabled": False,
    }


def test_production_command_binds_activation_and_authenticated_source() -> None:
    for command in (_command(), _command(remote=False)):
        assert contract_issues(
            command, "ai-provider-configuration-snapshot-command-v1.schema.json"
        ) == ()
    for field, value in (
        ("schema_version", "2.0.0"),
        ("authentication_context", "caller_assertion"),
        ("purpose", "activate_provider_configuration"),
        ("production_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = _command()
        malformed[field] = value
        assert contract_issues(
            malformed, "ai-provider-configuration-snapshot-command-v1.schema.json"
        )


def test_production_command_rejects_secret_and_lineage_substitution() -> None:
    for field in (
        "secret_ref",
        "credential",
        "registry_document",
        "configuration_document",
        "provider_response",
        "diagnostic",
    ):
        malformed = _command()
        malformed[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed, "ai-provider-configuration-snapshot-command-v1.schema.json"
        )
    local_with_secret = _command(remote=False)
    local_with_secret["secret_reference_digest"] = "sha256:" + "4" * 64
    assert contract_issues(
        local_with_secret, "ai-provider-configuration-snapshot-command-v1.schema.json"
    )
    remote_without_secret = _command()
    remote_without_secret["secret_reference_digest"] = None
    assert contract_issues(
        remote_without_secret, "ai-provider-configuration-snapshot-command-v1.schema.json"
    )
    caller = _command()
    caller["requester"]["actor_id"] = "caller-selected"
    assert contract_issues(
        caller, "ai-provider-configuration-snapshot-command-v1.schema.json"
    )


def test_production_receipt_v2_is_inert_and_version_exact() -> None:
    for command in (_command(), _command(remote=False)):
        receipt = _receipt(command)
        assert contract_issues(
            receipt, "ai-provider-configuration-snapshot-receipt-v2.schema.json"
        ) == ()
    for field, value in (
        ("schema_version", "1.0.0"),
        ("state", "active"),
        ("meter_binding_enabled", True),
        ("production_enabled", True),
        ("authority", "grant"),
        ("execution_enabled", True),
    ):
        malformed = _receipt(_command())
        malformed[field] = value
        assert contract_issues(
            malformed, "ai-provider-configuration-snapshot-receipt-v2.schema.json"
        )
    for field in ("prompt", "provider_response", "secret_ref", "payload"):
        malformed = copy.deepcopy(_receipt(_command()))
        malformed[field] = "synthetic but forbidden"
        assert contract_issues(
            malformed, "ai-provider-configuration-snapshot-receipt-v2.schema.json"
        )
