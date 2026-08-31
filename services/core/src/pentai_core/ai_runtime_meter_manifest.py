from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues


class RuntimeMeterImplementationManifestError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CompiledRuntimeMeterImplementationManifest:
    """Canonical inert provenance for a future code-owned manifest registry."""

    manifest_id: str
    manifest_revision: int
    implementation_id: str
    implementation_version: int
    implementation_artifact_digest: str
    provider_types: frozenset[str]
    supported_dimensions: frozenset[str]
    normalized_manifest_json: str
    manifest_digest: str


def compile_runtime_meter_implementation_manifest(
    document: dict[str, Any],
) -> CompiledRuntimeMeterImplementationManifest:
    """Validate and canonicalize metadata without trusting or activating its source."""
    if contract_issues(document, "ai-runtime-meter-implementation-manifest-v1.schema.json"):
        raise RuntimeMeterImplementationManifestError(
            "AI_RUNTIME_METER_IMPLEMENTATION_MANIFEST_MALFORMED",
            "runtime meter implementation manifest is malformed",
        )

    normalized = copy.deepcopy(document)
    normalized["provider_types"] = sorted(normalized["provider_types"])
    normalized["supported_dimensions"] = sorted(normalized["supported_dimensions"])
    return CompiledRuntimeMeterImplementationManifest(
        manifest_id=normalized["manifest_id"],
        manifest_revision=normalized["manifest_revision"],
        implementation_id=normalized["implementation_id"],
        implementation_version=normalized["implementation_version"],
        implementation_artifact_digest=normalized["implementation_artifact_digest"],
        provider_types=frozenset(normalized["provider_types"]),
        supported_dimensions=frozenset(normalized["supported_dimensions"]),
        normalized_manifest_json=canonical_json(normalized),
        manifest_digest="sha256:" + content_hash(normalized),
    )
