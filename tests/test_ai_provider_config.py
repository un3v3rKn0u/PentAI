from __future__ import annotations

import copy
import unittest
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pentai_core.ai_provider_config import (
    ProviderBudgetCeilings,
    ProviderConfigurationError,
    ProviderPolicy,
    validate_provider_configuration,
)
from pentai_policy.document import contract_issues

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


def configuration(*, remote: bool = True) -> dict[str, object]:
    provider_id = "approved-remote" if remote else "local-runtime"
    return {
        "schema_version": "1.0.0",
        "configuration_id": str(uuid4()),
        "provider_type": "approved_remote" if remote else "local_runtime",
        "provider_id": provider_id,
        "model_id": "model-exact-v1" if remote else "local-model-q4",
        "secret_ref": (
            f"secretref://provider/{provider_id}/{uuid4()}" if remote else None
        ),
        "privacy_classification": "remote_third_party" if remote else "local_device",
        "allowed_input_classifications": (
            ["public", "internal"] if remote else ["public", "internal", "confidential"]
        ),
        "budgets": {
            "max_input_tokens": 8_000,
            "max_output_tokens": 2_000,
            "max_requests": 10,
            "max_cost_microusd": 250_000 if remote else 0,
            "max_runtime_seconds": 120,
        },
        "remote_provider_opt_in": remote,
        "configured_at": (NOW - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "execution_enabled": False,
    }


def provider_policy(*, remote_enabled: bool = True) -> ProviderPolicy:
    return ProviderPolicy(
        approved_models={
            "approved-remote": frozenset({"model-exact-v1"}),
            "local-runtime": frozenset({"local-model-q4"}),
        },
        provider_types={
            "approved-remote": "approved_remote",
            "local-runtime": "local_runtime",
        },
        allowed_input_classifications={
            "approved-remote": frozenset({"public", "internal"}),
            "local-runtime": frozenset({"public", "internal", "confidential"}),
        },
        budget_ceilings=ProviderBudgetCeilings(
            max_input_tokens=8_000,
            max_output_tokens=2_000,
            max_requests=10,
            max_cost_microusd=250_000,
            max_runtime_seconds=120,
        ),
        remote_providers_enabled=remote_enabled,
    )


def assert_denied(
    test: unittest.TestCase,
    document: dict[str, object],
    code: str,
    *,
    policy: ProviderPolicy | None = None,
) -> None:
    with test.assertRaises(ProviderConfigurationError) as raised:
        validate_provider_configuration(document, policy=policy or provider_policy(), now=NOW)
    test.assertEqual(raised.exception.code, code)


class AIProviderConfigurationTests(unittest.TestCase):
    def test_remote_and_local_contracts_validate_without_enabling_execution(self) -> None:
        for document in (configuration(remote=True), configuration(remote=False)):
            with self.subTest(provider=document["provider_id"]):
                self.assertEqual(
                    contract_issues(document, "ai-provider-configuration-v1.schema.json"), ()
                )
                validate_provider_configuration(document, policy=provider_policy(), now=NOW)
                self.assertFalse(document["execution_enabled"])

    def test_missing_malformed_and_ambiguous_documents_deny(self) -> None:
        cases: list[dict[str, object]] = []
        missing = configuration()
        missing.pop("model_id")
        cases.append(missing)
        malformed = configuration()
        malformed["provider_id"] = " Approved Remote "
        cases.append(malformed)
        ambiguous = configuration()
        ambiguous["provider_type"] = "local_runtime"
        cases.append(ambiguous)
        enabled = configuration()
        enabled["execution_enabled"] = True
        cases.append(enabled)
        for document in cases:
            with self.subTest(document=document):
                assert_denied(self, document, "AI_PROVIDER_CONFIGURATION_MALFORMED")

    def test_stale_future_and_overlong_configuration_windows_deny(self) -> None:
        expired = configuration()
        expired["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
        future = configuration()
        future["configured_at"] = (NOW + timedelta(seconds=1)).isoformat()
        overlong = configuration()
        overlong["expires_at"] = (NOW + timedelta(days=31)).isoformat()
        for document in (expired, future, overlong):
            with self.subTest(document=document):
                assert_denied(self, document, "AI_PROVIDER_CONFIGURATION_STALE")

    def test_unknown_provider_model_and_provider_type_deny(self) -> None:
        unknown_provider = configuration()
        unknown_provider["provider_id"] = "not-approved"
        unknown_model = configuration()
        unknown_model["model_id"] = "model-exact-v2"
        type_mismatch = configuration(remote=False)
        mismatch_policy = provider_policy()
        mismatch_policy = ProviderPolicy(
            approved_models=mismatch_policy.approved_models,
            provider_types=mismatch_policy.provider_types | {"local-runtime": "approved_remote"},
            allowed_input_classifications=mismatch_policy.allowed_input_classifications,
            budget_ceilings=mismatch_policy.budget_ceilings,
            remote_providers_enabled=True,
        )
        assert_denied(self, unknown_provider, "AI_PROVIDER_UNKNOWN")
        assert_denied(self, unknown_model, "AI_MODEL_UNKNOWN")
        assert_denied(
            self, type_mismatch, "AI_PROVIDER_TYPE_MISMATCH", policy=mismatch_policy
        )

    def test_remote_provider_requires_both_contract_and_policy_opt_in(self) -> None:
        assert_denied(
            self,
            configuration(),
            "AI_REMOTE_PROVIDER_DISABLED",
            policy=provider_policy(remote_enabled=False),
        )
        missing_opt_in = configuration()
        missing_opt_in["remote_provider_opt_in"] = False
        assert_denied(self, missing_opt_in, "AI_PROVIDER_CONFIGURATION_MALFORMED")

    def test_raw_secrets_and_cross_provider_secret_references_deny(self) -> None:
        raw_secret = configuration()
        raw_secret["api_key"] = "placeholder"
        assert_denied(self, raw_secret, "AI_PROVIDER_CONFIGURATION_MALFORMED")

        wrong_reference = configuration()
        wrong_reference["secret_ref"] = f"secretref://provider/other-provider/{uuid4()}"
        assert_denied(self, wrong_reference, "AI_SECRET_REFERENCE_INVALID")

        local_secret = configuration(remote=False)
        local_secret["secret_ref"] = f"secretref://provider/local-runtime/{uuid4()}"
        assert_denied(self, local_secret, "AI_PROVIDER_CONFIGURATION_MALFORMED")

    def test_privacy_violations_deny_for_every_provider_type(self) -> None:
        for remote in (True, False):
            for classification in ("secret", "restricted_raw_evidence"):
                document = configuration(remote=remote)
                document["allowed_input_classifications"] = [classification]
                with self.subTest(remote=remote, classification=classification):
                    assert_denied(self, document, "AI_PRIVACY_CLASSIFICATION_DENIED")

        remote_confidential = configuration()
        remote_confidential["allowed_input_classifications"] = ["confidential"]
        assert_denied(
            self, remote_confidential, "AI_PRIVACY_CLASSIFICATION_DENIED"
        )

    def test_budget_boundaries_allow_exact_ceiling_and_deny_one_above(self) -> None:
        boundary = configuration()
        validate_provider_configuration(boundary, policy=provider_policy(), now=NOW)
        for field in (
            "max_input_tokens",
            "max_output_tokens",
            "max_requests",
            "max_cost_microusd",
            "max_runtime_seconds",
        ):
            document = copy.deepcopy(boundary)
            budgets = document["budgets"]
            assert isinstance(budgets, dict)
            value = budgets[field]
            assert isinstance(value, int)
            budgets[field] = value + 1
            with self.subTest(field=field):
                assert_denied(self, document, "AI_PROVIDER_BUDGET_EXCEEDED")


if __name__ == "__main__":
    unittest.main()
