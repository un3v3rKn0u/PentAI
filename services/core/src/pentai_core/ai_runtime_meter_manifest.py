from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
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


@dataclass(frozen=True)
class _CompiledRuntimeMeterImplementationManifestRegistry:
    by_implementation: Mapping[
        tuple[str, int], CompiledRuntimeMeterImplementationManifest
    ]
    registry_digest: str

    def resolve(
        self,
        *,
        implementation_id: str,
        implementation_version: int,
        implementation_artifact_digest: str,
    ) -> CompiledRuntimeMeterImplementationManifest:
        _validate_manifest_selector(
            implementation_id=implementation_id,
            implementation_version=implementation_version,
            implementation_artifact_digest=implementation_artifact_digest,
        )
        manifest = self.by_implementation.get((implementation_id, implementation_version))
        if (
            manifest is None
            or manifest.implementation_artifact_digest != implementation_artifact_digest
        ):
            raise RuntimeMeterImplementationManifestError(
                "AI_RUNTIME_METER_IMPLEMENTATION_MANIFEST_UNAVAILABLE",
                "runtime meter implementation manifest is unavailable",
            )
        return manifest


_IMPLEMENTATION_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SHA256_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_BUILT_IN_RUNTIME_METER_MANIFESTS: tuple[dict[str, Any], ...] = ()


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


def _compile_built_in_runtime_meter_manifest_registry(
    documents: Sequence[dict[str, Any]],
) -> _CompiledRuntimeMeterImplementationManifestRegistry:
    compiled = [compile_runtime_meter_implementation_manifest(document) for document in documents]
    compiled.sort(
        key=lambda manifest: (
            manifest.implementation_id,
            manifest.implementation_version,
            manifest.manifest_id,
        )
    )
    by_implementation: dict[
        tuple[str, int], CompiledRuntimeMeterImplementationManifest
    ] = {}
    manifest_ids: set[str] = set()
    for manifest in compiled:
        key = (manifest.implementation_id, manifest.implementation_version)
        if key in by_implementation or manifest.manifest_id in manifest_ids:
            raise RuntimeMeterImplementationManifestError(
                "AI_RUNTIME_METER_IMPLEMENTATION_MANIFEST_AMBIGUOUS",
                "runtime meter implementation manifest registry is ambiguous",
            )
        by_implementation[key] = manifest
        manifest_ids.add(manifest.manifest_id)
    normalized_manifests = [json.loads(item.normalized_manifest_json) for item in compiled]
    return _CompiledRuntimeMeterImplementationManifestRegistry(
        by_implementation=MappingProxyType(by_implementation),
        registry_digest="sha256:" + content_hash(normalized_manifests),
    )


def _validate_manifest_selector(
    *,
    implementation_id: str,
    implementation_version: int,
    implementation_artifact_digest: str,
) -> None:
    if (
        not isinstance(implementation_id, str)
        or _IMPLEMENTATION_ID.fullmatch(implementation_id) is None
        or isinstance(implementation_version, bool)
        or not isinstance(implementation_version, int)
        or not 1 <= implementation_version <= 2_147_483_647
        or not isinstance(implementation_artifact_digest, str)
        or _SHA256_DIGEST.fullmatch(implementation_artifact_digest) is None
    ):
        raise RuntimeMeterImplementationManifestError(
            "AI_RUNTIME_METER_IMPLEMENTATION_SELECTOR_MALFORMED",
            "runtime meter implementation selector is malformed",
        )


_BUILT_IN_RUNTIME_METER_MANIFEST_REGISTRY = (
    _compile_built_in_runtime_meter_manifest_registry(_BUILT_IN_RUNTIME_METER_MANIFESTS)
)


def resolve_built_in_runtime_meter_implementation_manifest(
    *,
    implementation_id: str,
    implementation_version: int,
    implementation_artifact_digest: str,
) -> CompiledRuntimeMeterImplementationManifest:
    """Resolve only repository-owned manifests; the built-in registry is empty by default."""
    return _BUILT_IN_RUNTIME_METER_MANIFEST_REGISTRY.resolve(
        implementation_id=implementation_id,
        implementation_version=implementation_version,
        implementation_artifact_digest=implementation_artifact_digest,
    )
