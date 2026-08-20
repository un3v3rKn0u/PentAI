from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any

from pentai_policy.document import contract_issues, parse_time


class ProviderConfigurationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ProviderBudgetCeilings:
    max_input_tokens: int
    max_output_tokens: int
    max_requests: int
    max_cost_microusd: int
    max_runtime_seconds: int


@dataclass(frozen=True)
class ProviderPolicy:
    """Trusted allowlist and routing policy supplied by the deterministic core."""

    registry_id: str
    registry_revision: int
    registry_expires_at: datetime
    approved_models: Mapping[str, frozenset[str]]
    provider_types: Mapping[str, str]
    allowed_input_classifications: Mapping[str, frozenset[str]]
    budget_ceilings: ProviderBudgetCeilings
    remote_providers_enabled: bool = False
    max_configuration_lifetime: timedelta = timedelta(days=30)

    def __post_init__(self) -> None:
        object.__setattr__(self, "approved_models", MappingProxyType(dict(self.approved_models)))
        object.__setattr__(self, "provider_types", MappingProxyType(dict(self.provider_types)))
        object.__setattr__(
            self,
            "allowed_input_classifications",
            MappingProxyType(dict(self.allowed_input_classifications)),
        )


_FORBIDDEN_MODEL_INPUTS = frozenset({"secret", "restricted_raw_evidence"})


def validate_provider_configuration(
    document: dict[str, Any],
    *,
    policy: ProviderPolicy,
    now: datetime | None = None,
) -> None:
    """Fail closed without resolving secrets, loading models, or contacting providers."""
    if contract_issues(document, "ai-provider-configuration-v1.schema.json"):
        raise ProviderConfigurationError(
            "AI_PROVIDER_CONFIGURATION_MALFORMED", "provider configuration is malformed"
        )

    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ProviderConfigurationError("AI_PROVIDER_CLOCK_INVALID", "validation clock is invalid")
    instant = instant.astimezone(UTC)
    configured_at = parse_time(document["configured_at"])
    expires_at = parse_time(document["expires_at"])
    if configured_at > instant or expires_at <= instant:
        raise ProviderConfigurationError(
            "AI_PROVIDER_CONFIGURATION_STALE", "provider configuration is not current"
        )
    if (
        expires_at <= configured_at
        or expires_at - configured_at > policy.max_configuration_lifetime
    ):
        raise ProviderConfigurationError(
            "AI_PROVIDER_CONFIGURATION_STALE", "provider configuration lifetime is invalid"
        )
    if policy.registry_expires_at <= instant or expires_at > policy.registry_expires_at:
        raise ProviderConfigurationError(
            "AI_PROVIDER_REGISTRY_STALE", "trusted provider registry is not current"
        )

    provider_id = document["provider_id"]
    model_id = document["model_id"]
    approved_models = policy.approved_models.get(provider_id)
    expected_type = policy.provider_types.get(provider_id)
    if approved_models is None or expected_type is None:
        raise ProviderConfigurationError(
            "AI_PROVIDER_UNKNOWN", "provider is not present in the trusted allowlist"
        )
    if expected_type != document["provider_type"]:
        raise ProviderConfigurationError(
            "AI_PROVIDER_TYPE_MISMATCH", "provider type does not match the trusted allowlist"
        )
    if model_id not in approved_models:
        raise ProviderConfigurationError(
            "AI_MODEL_UNKNOWN", "model is not present in the trusted provider allowlist"
        )

    if document["provider_type"] == "approved_remote":
        if not policy.remote_providers_enabled or document["remote_provider_opt_in"] is not True:
            raise ProviderConfigurationError(
                "AI_REMOTE_PROVIDER_DISABLED", "remote provider use is not enabled"
            )
        expected_secret_prefix = f"secretref://provider/{provider_id}/"
        if not document["secret_ref"].startswith(expected_secret_prefix):
            raise ProviderConfigurationError(
                "AI_SECRET_REFERENCE_INVALID", "secret reference is not provider-bound"
            )

    requested_inputs = frozenset(document["allowed_input_classifications"])
    if requested_inputs & _FORBIDDEN_MODEL_INPUTS:
        raise ProviderConfigurationError(
            "AI_PRIVACY_CLASSIFICATION_DENIED",
            "secrets and restricted raw evidence cannot enter model contexts",
        )
    permitted_inputs = policy.allowed_input_classifications.get(provider_id)
    if permitted_inputs is None or not requested_inputs <= permitted_inputs:
        raise ProviderConfigurationError(
            "AI_PRIVACY_CLASSIFICATION_DENIED",
            "input classification is not permitted for this provider",
        )

    budgets = document["budgets"]
    ceilings = policy.budget_ceilings
    for field in (
        "max_input_tokens",
        "max_output_tokens",
        "max_requests",
        "max_cost_microusd",
        "max_runtime_seconds",
    ):
        if budgets[field] > getattr(ceilings, field):
            raise ProviderConfigurationError(
                "AI_PROVIDER_BUDGET_EXCEEDED", f"{field} exceeds the trusted policy ceiling"
            )

    if document["execution_enabled"] is not False:
        raise ProviderConfigurationError(
            "AI_PROVIDER_EXECUTION_FORBIDDEN", "provider execution is disabled in this contract"
        )
