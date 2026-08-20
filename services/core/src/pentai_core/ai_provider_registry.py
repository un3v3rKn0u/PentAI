from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pentai_policy.document import contract_issues, parse_time

from pentai_core.ai_provider_config import ProviderBudgetCeilings, ProviderPolicy


class ProviderRegistryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_MAX_REGISTRY_LIFETIME = timedelta(days=30)
_FORBIDDEN_MODEL_INPUTS = frozenset({"secret", "restricted_raw_evidence"})


def build_provider_policy(
    document: dict[str, Any], *, now: datetime | None = None
) -> ProviderPolicy:
    """Compile a trusted, immutable allowlist without enabling provider execution."""
    if contract_issues(document, "ai-provider-registry-v1.schema.json"):
        raise ProviderRegistryError("AI_PROVIDER_REGISTRY_MALFORMED", "registry is malformed")

    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ProviderRegistryError("AI_PROVIDER_REGISTRY_CLOCK_INVALID", "clock is invalid")
    instant = instant.astimezone(UTC)
    configured_at = parse_time(document["configured_at"])
    expires_at = parse_time(document["expires_at"])
    if configured_at > instant or expires_at <= instant:
        raise ProviderRegistryError("AI_PROVIDER_REGISTRY_STALE", "registry is not current")
    if expires_at <= configured_at or expires_at - configured_at > _MAX_REGISTRY_LIFETIME:
        raise ProviderRegistryError(
            "AI_PROVIDER_REGISTRY_STALE", "registry lifetime is invalid"
        )

    approved_models: dict[str, frozenset[str]] = {}
    provider_types: dict[str, str] = {}
    allowed_inputs: dict[str, frozenset[str]] = {}
    observed_provider_ids: set[str] = set()
    for provider in document["providers"]:
        provider_id = provider["provider_id"]
        if provider_id in observed_provider_ids:
            raise ProviderRegistryError(
                "AI_PROVIDER_REGISTRY_AMBIGUOUS", "provider identity is duplicated"
            )
        observed_provider_ids.add(provider_id)
        requested_inputs = frozenset(provider["allowed_input_classifications"])
        if requested_inputs & _FORBIDDEN_MODEL_INPUTS:
            raise ProviderRegistryError(
                "AI_PROVIDER_REGISTRY_PRIVACY_DENIED",
                "registry cannot route secrets or restricted raw evidence",
            )
        if provider["state"] == "disabled":
            continue
        approved_models[provider_id] = frozenset(provider["models"])
        provider_types[provider_id] = provider["provider_type"]
        allowed_inputs[provider_id] = requested_inputs

    if not approved_models:
        raise ProviderRegistryError(
            "AI_PROVIDER_REGISTRY_EMPTY", "registry has no enabled provider"
        )

    ceilings = document["budget_ceilings"]
    return ProviderPolicy(
        registry_id=document["registry_id"],
        registry_revision=document["revision"],
        registry_expires_at=expires_at,
        approved_models=approved_models,
        provider_types=provider_types,
        allowed_input_classifications=allowed_inputs,
        budget_ceilings=ProviderBudgetCeilings(
            max_input_tokens=ceilings["max_input_tokens"],
            max_output_tokens=ceilings["max_output_tokens"],
            max_requests=ceilings["max_requests"],
            max_cost_microusd=ceilings["max_cost_microusd"],
            max_runtime_seconds=ceilings["max_runtime_seconds"],
        ),
        remote_providers_enabled=document["remote_providers_enabled"],
        max_configuration_lifetime=min(
            _MAX_REGISTRY_LIFETIME, expires_at - configured_at
        ),
    )
