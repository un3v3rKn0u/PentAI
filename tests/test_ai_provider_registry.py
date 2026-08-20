from __future__ import annotations

import copy
import unittest
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pentai_core.ai_provider_config import (
    ProviderConfigurationError,
    validate_provider_configuration,
)
from pentai_core.ai_provider_registry import ProviderRegistryError, build_provider_policy
from pentai_policy.document import contract_issues

NOW = datetime(2026, 8, 20, 14, 0, tzinfo=UTC)


def registry() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "registry_id": str(uuid4()),
        "revision": 7,
        "providers": [
            {
                "provider_id": "remote-approved",
                "provider_type": "approved_remote",
                "models": ["remote-model-v1"],
                "allowed_input_classifications": ["public", "internal"],
                "state": "enabled",
            },
            {
                "provider_id": "local-approved",
                "provider_type": "local_runtime",
                "models": ["local-model-q4"],
                "allowed_input_classifications": ["public", "internal", "confidential"],
                "state": "enabled",
            },
        ],
        "budget_ceilings": {
            "max_input_tokens": 16_000,
            "max_output_tokens": 4_000,
            "max_requests": 20,
            "max_cost_microusd": 500_000,
            "max_runtime_seconds": 300,
        },
        "remote_providers_enabled": True,
        "configured_at": (NOW - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(days=14)).isoformat().replace("+00:00", "Z"),
        "execution_enabled": False,
    }


def remote_configuration() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "configuration_id": str(uuid4()),
        "provider_type": "approved_remote",
        "provider_id": "remote-approved",
        "model_id": "remote-model-v1",
        "secret_ref": f"secretref://provider/remote-approved/{uuid4()}",
        "privacy_classification": "remote_third_party",
        "allowed_input_classifications": ["public", "internal"],
        "budgets": {
            "max_input_tokens": 16_000,
            "max_output_tokens": 4_000,
            "max_requests": 20,
            "max_cost_microusd": 500_000,
            "max_runtime_seconds": 300,
        },
        "remote_provider_opt_in": True,
        "configured_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "execution_enabled": False,
    }


def assert_denied(test: unittest.TestCase, document: dict[str, object], code: str) -> None:
    with test.assertRaises(ProviderRegistryError) as raised:
        build_provider_policy(document, now=NOW)
    test.assertEqual(raised.exception.code, code)


class AIProviderRegistryTests(unittest.TestCase):
    def test_compiles_exact_immutable_policy_and_composes_with_configuration(self) -> None:
        document = registry()
        self.assertEqual(contract_issues(document, "ai-provider-registry-v1.schema.json"), ())
        policy = build_provider_policy(document, now=NOW)
        self.assertEqual(policy.registry_id, document["registry_id"])
        self.assertEqual(policy.registry_revision, 7)
        self.assertEqual(policy.registry_expires_at, NOW + timedelta(days=14))
        self.assertEqual(policy.approved_models["remote-approved"], {"remote-model-v1"})
        self.assertFalse(hasattr(policy, "execution_enabled"))
        validate_provider_configuration(remote_configuration(), policy=policy, now=NOW)

        providers = document["providers"]
        assert isinstance(providers, list)
        remote = providers[0]
        assert isinstance(remote, dict)
        remote["models"] = ["tampered-model"]
        self.assertEqual(policy.approved_models["remote-approved"], {"remote-model-v1"})
        with self.assertRaises(TypeError):
            policy.approved_models["new-provider"] = frozenset({"model"})  # type: ignore[index]

    def test_missing_malformed_and_execution_enabled_registries_deny(self) -> None:
        missing = registry()
        missing.pop("revision")
        malformed = registry()
        malformed["registry_id"] = "not-a-uuid"
        enabled = registry()
        enabled["execution_enabled"] = True
        for document in (missing, malformed, enabled):
            with self.subTest(document=document):
                assert_denied(self, document, "AI_PROVIDER_REGISTRY_MALFORMED")

    def test_future_expired_and_overlong_registries_deny(self) -> None:
        future = registry()
        future["configured_at"] = (NOW + timedelta(seconds=1)).isoformat()
        expired = registry()
        expired["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
        overlong = registry()
        overlong["expires_at"] = (NOW + timedelta(days=31)).isoformat()
        for document in (future, expired, overlong):
            with self.subTest(document=document):
                assert_denied(self, document, "AI_PROVIDER_REGISTRY_STALE")

    def test_duplicate_provider_identity_denies_even_when_one_is_disabled(self) -> None:
        document = registry()
        providers = document["providers"]
        assert isinstance(providers, list)
        duplicate = copy.deepcopy(providers[0])
        assert isinstance(duplicate, dict)
        duplicate["state"] = "disabled"
        providers.append(duplicate)
        assert_denied(self, document, "AI_PROVIDER_REGISTRY_AMBIGUOUS")

    def test_registry_with_no_enabled_provider_denies(self) -> None:
        document = registry()
        providers = document["providers"]
        assert isinstance(providers, list)
        for provider in providers:
            assert isinstance(provider, dict)
            provider["state"] = "disabled"
        assert_denied(self, document, "AI_PROVIDER_REGISTRY_EMPTY")

    def test_forbidden_input_classes_deny_even_on_disabled_entries(self) -> None:
        for classification in ("secret", "restricted_raw_evidence"):
            document = registry()
            providers = document["providers"]
            assert isinstance(providers, list)
            provider = providers[0]
            assert isinstance(provider, dict)
            provider["state"] = "disabled"
            provider["allowed_input_classifications"] = [classification]
            with self.subTest(classification=classification):
                assert_denied(
                    document=document,
                    test=self,
                    code="AI_PROVIDER_REGISTRY_PRIVACY_DENIED",
                )

    def test_disabled_provider_and_unlisted_model_cannot_validate_configuration(self) -> None:
        document = registry()
        providers = document["providers"]
        assert isinstance(providers, list)
        remote = providers[0]
        assert isinstance(remote, dict)
        remote["state"] = "disabled"
        policy = build_provider_policy(document, now=NOW)
        with self.assertRaises(ProviderConfigurationError) as disabled:
            validate_provider_configuration(remote_configuration(), policy=policy, now=NOW)
        self.assertEqual(disabled.exception.code, "AI_PROVIDER_UNKNOWN")

        enabled_policy = build_provider_policy(registry(), now=NOW)
        configuration = remote_configuration()
        configuration["model_id"] = "unlisted-model"
        with self.assertRaises(ProviderConfigurationError) as unlisted:
            validate_provider_configuration(configuration, policy=enabled_policy, now=NOW)
        self.assertEqual(unlisted.exception.code, "AI_MODEL_UNKNOWN")

    def test_configuration_cannot_outlive_or_reuse_expired_registry(self) -> None:
        policy = build_provider_policy(registry(), now=NOW)
        outlives_registry = remote_configuration()
        outlives_registry["configured_at"] = (NOW + timedelta(days=10)).isoformat()
        outlives_registry["expires_at"] = (NOW + timedelta(days=15)).isoformat()
        with self.assertRaises(ProviderConfigurationError) as outlives:
            validate_provider_configuration(
                outlives_registry, policy=policy, now=NOW + timedelta(days=10)
            )
        self.assertEqual(outlives.exception.code, "AI_PROVIDER_REGISTRY_STALE")
        after_expiry = remote_configuration()
        after_expiry["configured_at"] = (NOW + timedelta(days=15)).isoformat()
        after_expiry["expires_at"] = (NOW + timedelta(days=16)).isoformat()
        with self.assertRaises(ProviderConfigurationError) as expired:
            validate_provider_configuration(
                after_expiry, policy=policy, now=NOW + timedelta(days=15)
            )
        self.assertEqual(expired.exception.code, "AI_PROVIDER_REGISTRY_STALE")

    def test_malformed_duplicate_models_and_budget_bounds_deny_at_schema(self) -> None:
        duplicate_model = registry()
        providers = duplicate_model["providers"]
        assert isinstance(providers, list)
        provider = providers[0]
        assert isinstance(provider, dict)
        provider["models"] = ["same-model", "same-model"]

        excessive_budget = registry()
        ceilings = excessive_budget["budget_ceilings"]
        assert isinstance(ceilings, dict)
        ceilings["max_requests"] = 10_001
        for document in (duplicate_model, excessive_budget):
            with self.subTest(document=document):
                assert_denied(self, document, "AI_PROVIDER_REGISTRY_MALFORMED")


if __name__ == "__main__":
    unittest.main()
