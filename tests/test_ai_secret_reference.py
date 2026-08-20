from __future__ import annotations

import copy
import unittest
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pentai_core.ai_provider_config import ProviderPolicy
from pentai_core.ai_provider_registry import build_provider_policy
from pentai_core.ai_secret_reference import SecretReferenceError, validate_secret_reference
from pentai_policy.document import contract_issues

NOW = datetime(2026, 8, 20, 16, 0, tzinfo=UTC)


def provider_policy() -> ProviderPolicy:
    registry: dict[str, object] = {
        "schema_version": "1.0.0",
        "registry_id": str(uuid4()),
        "revision": 2,
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
                "allowed_input_classifications": ["public", "internal"],
                "state": "enabled",
            },
        ],
        "budget_ceilings": {
            "max_input_tokens": 8_000,
            "max_output_tokens": 2_000,
            "max_requests": 10,
            "max_cost_microusd": 250_000,
            "max_runtime_seconds": 120,
        },
        "remote_providers_enabled": True,
        "configured_at": (NOW - timedelta(days=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=20)).isoformat(),
        "execution_enabled": False,
    }
    return build_provider_policy(registry, now=NOW)


def configuration(*, remote: bool = True) -> dict[str, object]:
    provider_id = "remote-approved" if remote else "local-approved"
    return {
        "schema_version": "1.0.0",
        "configuration_id": str(uuid4()),
        "provider_type": "approved_remote" if remote else "local_runtime",
        "provider_id": provider_id,
        "model_id": "remote-model-v1" if remote else "local-model-q4",
        "secret_ref": (
            f"secretref://provider/{provider_id}/{uuid4()}" if remote else None
        ),
        "privacy_classification": "remote_third_party" if remote else "local_device",
        "allowed_input_classifications": ["public", "internal"],
        "budgets": {
            "max_input_tokens": 8_000,
            "max_output_tokens": 2_000,
            "max_requests": 10,
            "max_cost_microusd": 250_000 if remote else 0,
            "max_runtime_seconds": 120,
        },
        "remote_provider_opt_in": remote,
        "configured_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(days=7)).isoformat(),
        "execution_enabled": False,
    }


def secret_reference(configuration_document: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "secret_ref": configuration_document["secret_ref"],
        "configuration_id": configuration_document["configuration_id"],
        "provider_id": configuration_document["provider_id"],
        "purpose": "provider_authentication",
        "state": "active",
        "created_at": (NOW - timedelta(days=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=8)).isoformat(),
        "revoked_at": None,
        "resolution_enabled": False,
    }


def assert_denied(
    test: unittest.TestCase,
    document: dict[str, object],
    code: str,
    *,
    configuration_document: dict[str, object] | None = None,
) -> None:
    target_configuration = configuration_document or configuration()
    with test.assertRaises(SecretReferenceError) as raised:
        validate_secret_reference(
            document,
            configuration=target_configuration,
            policy=provider_policy(),
            now=NOW,
        )
    test.assertEqual(raised.exception.code, code)


class AISecretReferenceTests(unittest.TestCase):
    def test_validates_opaque_non_resolving_provider_bound_reference(self) -> None:
        provider_configuration = configuration()
        document = secret_reference(provider_configuration)
        self.assertEqual(contract_issues(document, "ai-secret-reference-v1.schema.json"), ())
        validate_secret_reference(
            document,
            configuration=provider_configuration,
            policy=provider_policy(),
            now=NOW,
        )
        self.assertFalse(document["resolution_enabled"])
        self.assertNotIn("secret_value", document)

    def test_missing_malformed_raw_secret_and_resolution_enablement_deny(self) -> None:
        provider_configuration = configuration()
        missing = secret_reference(provider_configuration)
        missing.pop("purpose")
        malformed = secret_reference(provider_configuration)
        malformed["secret_ref"] = str(uuid4())
        raw_secret = secret_reference(provider_configuration)
        raw_secret["secret_value"] = str(uuid4())
        enabled = secret_reference(provider_configuration)
        enabled["resolution_enabled"] = True
        wrong_purpose = secret_reference(provider_configuration)
        wrong_purpose["purpose"] = "report_export"
        for document in (missing, malformed, raw_secret, enabled, wrong_purpose):
            with self.subTest(document=document):
                assert_denied(
                    self,
                    document,
                    "AI_SECRET_REFERENCE_MALFORMED",
                    configuration_document=provider_configuration,
                )

    def test_configuration_provider_and_reference_reuse_mismatch_deny(self) -> None:
        provider_configuration = configuration()
        cases = []
        wrong_configuration = secret_reference(provider_configuration)
        wrong_configuration["configuration_id"] = str(uuid4())
        cases.append(wrong_configuration)
        wrong_provider = secret_reference(provider_configuration)
        wrong_provider["provider_id"] = "another-provider"
        cases.append(wrong_provider)
        wrong_reference = secret_reference(provider_configuration)
        wrong_reference["secret_ref"] = f"secretref://provider/remote-approved/{uuid4()}"
        cases.append(wrong_reference)
        for document in cases:
            with self.subTest(document=document):
                assert_denied(
                    self,
                    document,
                    "AI_SECRET_REFERENCE_BINDING_MISMATCH",
                    configuration_document=provider_configuration,
                )

    def test_cross_provider_reference_is_rejected_as_ambiguous_binding(self) -> None:
        provider_configuration = configuration()
        cross_provider = secret_reference(provider_configuration)
        cross_provider["secret_ref"] = f"secretref://provider/other-provider/{uuid4()}"
        provider_configuration["secret_ref"] = cross_provider["secret_ref"]
        assert_denied(
            self,
            cross_provider,
            "AI_SECRET_REFERENCE_BINDING_MISMATCH",
            configuration_document=provider_configuration,
        )

    def test_future_expired_reversed_and_overlong_reference_denies(self) -> None:
        provider_configuration = configuration()
        future = secret_reference(provider_configuration)
        future["created_at"] = (NOW + timedelta(seconds=1)).isoformat()
        expired = secret_reference(provider_configuration)
        expired["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
        reversed_window = secret_reference(provider_configuration)
        reversed_window["expires_at"] = (NOW - timedelta(days=2)).isoformat()
        overlong = secret_reference(provider_configuration)
        overlong["created_at"] = (NOW - timedelta(days=1)).isoformat()
        overlong["expires_at"] = (NOW + timedelta(days=30)).isoformat()
        for document in (future, expired, reversed_window, overlong):
            with self.subTest(document=document):
                assert_denied(
                    self,
                    document,
                    "AI_SECRET_REFERENCE_STALE",
                    configuration_document=provider_configuration,
                )

    def test_reference_must_cover_exact_configuration_lifetime(self) -> None:
        provider_configuration = configuration()
        provider_configuration["configured_at"] = (NOW - timedelta(hours=1)).isoformat()
        created_late = secret_reference(provider_configuration)
        created_late["created_at"] = (NOW - timedelta(minutes=30)).isoformat()
        expires_early = secret_reference(provider_configuration)
        expires_early["expires_at"] = (NOW + timedelta(days=6)).isoformat()
        assert_denied(
            self,
            created_late,
            "AI_SECRET_REFERENCE_LIFETIME_MISMATCH",
            configuration_document=provider_configuration,
        )
        assert_denied(
            self,
            expires_early,
            "AI_SECRET_REFERENCE_LIFETIME_MISMATCH",
            configuration_document=provider_configuration,
        )

    def test_revoked_reference_denies(self) -> None:
        provider_configuration = configuration()
        revoked = secret_reference(provider_configuration)
        revoked["state"] = "revoked"
        revoked["revoked_at"] = (NOW - timedelta(seconds=1)).isoformat()
        assert_denied(
            self,
            revoked,
            "AI_SECRET_REFERENCE_REVOKED",
            configuration_document=provider_configuration,
        )

    def test_local_runtime_cannot_accept_secret_reference(self) -> None:
        local_configuration = configuration(remote=False)
        synthetic = copy.deepcopy(secret_reference(configuration()))
        synthetic["configuration_id"] = local_configuration["configuration_id"]
        synthetic["provider_id"] = local_configuration["provider_id"]
        synthetic["secret_ref"] = f"secretref://provider/local-approved/{uuid4()}"
        with self.assertRaises(SecretReferenceError) as raised:
            validate_secret_reference(
                synthetic,
                configuration=local_configuration,
                policy=provider_policy(),
                now=NOW,
            )
        self.assertEqual(raised.exception.code, "AI_SECRET_REFERENCE_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
