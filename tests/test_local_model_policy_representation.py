from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pentai_policy import (
    CompilationError,
    compile_manifest,
    compile_manifest_v2,
    content_hash,
    validate_and_canonicalize_manifest,
    validate_and_canonicalize_manifest_v3,
)
from pentai_policy.document import contract_issues
from test_authorization_slice import manifest_for

NOW = datetime(2026, 9, 2, 8, 0, tzinfo=UTC)


def local_manifest() -> dict[str, object]:
    engagement: dict[str, object] = {
        "id": str(uuid4()),
        "effective_from": (NOW - timedelta(hours=1)).isoformat(),
        "expires_at": (NOW + timedelta(hours=1)).isoformat(),
    }
    source: dict[str, object] = {
        "id": str(uuid4()),
        "reference": "synthetic://local-model-policy",
        "authority": "contract",
        "retrieved_at": (NOW - timedelta(hours=2)).isoformat(),
        "content_hash": "a" * 64,
    }
    document = manifest_for(engagement, source)
    document["schema_version"] = "3.0.0"
    techniques = document["techniques"]
    assert isinstance(techniques, dict)
    techniques["allowed_capabilities"] = ["network.http.get", "ai.local.generate"]
    return document


def test_v3_compiles_explicit_local_model_policy_without_runtime_claims() -> None:
    candidate = local_manifest()
    validation = validate_and_canonicalize_manifest_v3(candidate, now=NOW)

    assert validation.valid
    assert validation.document is not None
    policy = compile_manifest_v2(validation.document, content_hash(validation.document))
    assert contract_issues(policy, "policy-ir-v2.schema.json") == ()
    assert policy["schema_version"] == "2.0.0"
    local_rules = [
        rule for rule in policy["capability_rules"] if rule["capability"] == "ai.local.generate"
    ]
    assert len(local_rules) == 1
    assert local_rules[0]["effect"] == "allow"
    serialized = str(policy)
    assert "llama.cpp" not in serialized
    assert "Qwen" not in serialized
    assert "execution_enabled" not in serialized


def test_v3_local_policy_is_deterministic_and_supports_closed_effects() -> None:
    first = local_manifest()
    second = copy.deepcopy(first)
    techniques = second["techniques"]
    assert isinstance(techniques, dict)
    techniques["allowed_capabilities"] = list(
        reversed(techniques["allowed_capabilities"])
    )
    first_valid = validate_and_canonicalize_manifest_v3(first, now=NOW)
    second_valid = validate_and_canonicalize_manifest_v3(second, now=NOW)
    assert first_valid.document == second_valid.document
    assert first_valid.document is not None
    assert second_valid.document is not None
    assert compile_manifest_v2(
        first_valid.document, content_hash(first_valid.document)
    ) == compile_manifest_v2(second_valid.document, content_hash(second_valid.document))

    denied = local_manifest()
    denied_techniques = denied["techniques"]
    assert isinstance(denied_techniques, dict)
    denied_techniques["allowed_capabilities"] = ["network.http.get"]
    denied_techniques["denied_capabilities"] = ["ai.local.generate"]
    denied_result = validate_and_canonicalize_manifest_v3(denied, now=NOW)
    assert denied_result.valid

    conditional = local_manifest()
    conditional_techniques = conditional["techniques"]
    assert isinstance(conditional_techniques, dict)
    conditional_techniques["allowed_capabilities"] = ["network.http.get"]
    conditional_techniques["conditional_capabilities"] = [
        {
            "capability": "ai.local.generate",
            "approval_type": "local_model_generation",
            "conditions": ["human review required"],
        }
    ]
    conditional_result = validate_and_canonicalize_manifest_v3(conditional, now=NOW)
    assert conditional_result.valid


def test_v3_rejects_unknown_conflicting_mixed_and_runtime_bearing_input() -> None:
    unknown = local_manifest()
    unknown_techniques = unknown["techniques"]
    assert isinstance(unknown_techniques, dict)
    unknown_techniques["allowed_capabilities"] = ["network.http.get", "ai.unknown"]
    assert not validate_and_canonicalize_manifest_v3(unknown, now=NOW).valid
    with pytest.raises(CompilationError):
        compile_manifest_v2(unknown, content_hash(unknown))

    conflicting = local_manifest()
    conflicting_techniques = conflicting["techniques"]
    assert isinstance(conflicting_techniques, dict)
    conflicting_techniques["denied_capabilities"] = ["ai.local.generate"]
    assert not validate_and_canonicalize_manifest_v3(conflicting, now=NOW).valid

    mixed = local_manifest()
    mixed["schema_version"] = "2.0.0"
    assert not validate_and_canonicalize_manifest_v3(mixed, now=NOW).valid

    runtime_bearing = local_manifest()
    runtime_techniques = runtime_bearing["techniques"]
    assert isinstance(runtime_techniques, dict)
    runtime_techniques["runtime"] = "llama.cpp"
    assert not validate_and_canonicalize_manifest_v3(runtime_bearing, now=NOW).valid


def test_existing_manifest_and_policy_versions_remain_unchanged() -> None:
    candidate = local_manifest()
    candidate["schema_version"] = "2.0.0"
    techniques = candidate["techniques"]
    assert isinstance(techniques, dict)
    techniques["allowed_capabilities"] = ["network.http.get"]
    validation = validate_and_canonicalize_manifest(candidate, now=NOW)
    assert validation.valid
    assert validation.document is not None
    policy = compile_manifest(validation.document, content_hash(validation.document))
    assert policy["schema_version"] == "1.0.0"
    assert contract_issues(policy, "policy-ir-v1.schema.json") == ()

    candidate["techniques"]["allowed_capabilities"] = [  # type: ignore[index]
        "network.http.get",
        "ai.local.generate",
    ]
    assert not validate_and_canonicalize_manifest(candidate, now=NOW).valid
