from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from pentai_policy.document import contract_issues, parse_time

from pentai_core.ai_provider_config import ProviderPolicy, validate_provider_configuration


class SecretReferenceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_MAX_REFERENCE_LIFETIME = timedelta(days=30)


def validate_secret_reference(
    document: dict[str, Any],
    *,
    configuration: dict[str, Any],
    policy: ProviderPolicy,
    now: datetime | None = None,
) -> None:
    """Validate opaque reference metadata without resolving or loading a secret."""
    if contract_issues(document, "ai-secret-reference-v1.schema.json"):
        raise SecretReferenceError("AI_SECRET_REFERENCE_MALFORMED", "secret reference is malformed")

    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise SecretReferenceError("AI_SECRET_REFERENCE_CLOCK_INVALID", "clock is invalid")
    instant = instant.astimezone(UTC)
    expected_prefix = f"secretref://provider/{document['provider_id']}/"
    if not document["secret_ref"].startswith(expected_prefix):
        raise SecretReferenceError(
            "AI_SECRET_REFERENCE_BINDING_MISMATCH", "secret reference provider is ambiguous"
        )
    validate_provider_configuration(configuration, policy=policy, now=instant)
    if configuration["provider_type"] != "approved_remote":
        raise SecretReferenceError(
            "AI_SECRET_REFERENCE_UNSUPPORTED", "local runtimes cannot use provider secrets"
        )

    if (
        document["configuration_id"] != configuration["configuration_id"]
        or document["provider_id"] != configuration["provider_id"]
        or document["secret_ref"] != configuration["secret_ref"]
    ):
        raise SecretReferenceError(
            "AI_SECRET_REFERENCE_BINDING_MISMATCH",
            "secret reference does not match the exact provider configuration",
        )
    created_at = parse_time(document["created_at"])
    expires_at = parse_time(document["expires_at"])
    if created_at > instant or expires_at <= instant:
        raise SecretReferenceError("AI_SECRET_REFERENCE_STALE", "secret reference is not current")
    if expires_at <= created_at or expires_at - created_at > _MAX_REFERENCE_LIFETIME:
        raise SecretReferenceError(
            "AI_SECRET_REFERENCE_STALE", "secret reference lifetime is invalid"
        )
    configuration_created_at = parse_time(configuration["configured_at"])
    configuration_expires_at = parse_time(configuration["expires_at"])
    if created_at > configuration_created_at or expires_at < configuration_expires_at:
        raise SecretReferenceError(
            "AI_SECRET_REFERENCE_LIFETIME_MISMATCH",
            "secret reference does not cover the provider configuration lifetime",
        )
    if document["state"] != "active":
        raise SecretReferenceError("AI_SECRET_REFERENCE_REVOKED", "secret reference is revoked")
    if document["resolution_enabled"] is not False:
        raise SecretReferenceError(
            "AI_SECRET_RESOLUTION_FORBIDDEN", "secret resolution is disabled in this contract"
        )
