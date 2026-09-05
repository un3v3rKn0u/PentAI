from __future__ import annotations

import copy
import json
from dataclasses import FrozenInstanceError
from typing import cast

import pytest
from pentai_core.local_model_artifact_manifest import (
    LocalModelArtifactManifestError,
    compile_local_model_artifact_manifest,
    resolve_built_in_local_model_artifact_manifest,
)
from pentai_policy.document import contract_issues


def manifest() -> dict[str, object]:
    return cast(
        dict[str, object],
        json.loads(
            resolve_built_in_local_model_artifact_manifest().normalized_manifest_json
        ),
    )


def test_built_in_manifest_is_exact_inactive_and_non_authorizing() -> None:
    document = manifest()
    compiled = resolve_built_in_local_model_artifact_manifest()

    assert not contract_issues(document, "local-model-artifact-manifest-v1.schema.json")
    assert compiled.provider_id == "llama.cpp"
    assert compiled.model_id == "Qwen/Qwen2.5-Coder-3B-Instruct-GGUF:Q4_K_M"
    assert compiled.platform_os == "macos"
    assert compiled.platform_architecture == "arm64"
    assert len(compiled.runtime_components) == 12
    runtime = cast(dict[str, object], document["runtime"])
    assert sum(component.size_bytes for component in compiled.runtime_components) <= cast(
        int, runtime["max_closure_bytes"]
    )
    assert compiled.activation_enabled is False
    assert compiled.verification_enabled is False
    assert compiled.receipt_enabled is False
    assert compiled.authority == "none"
    assert compiled.execution_enabled is False


def test_compilation_is_deterministic_without_mutating_input() -> None:
    document = manifest()
    original = copy.deepcopy(document)

    first = compile_local_model_artifact_manifest(document)
    second = compile_local_model_artifact_manifest(copy.deepcopy(document))

    assert document == original
    assert first == second
    assert first.manifest_digest == second.manifest_digest
    assert json.loads(first.normalized_manifest_json) == original


def test_compiled_manifest_and_components_are_immutable() -> None:
    compiled = resolve_built_in_local_model_artifact_manifest()

    with pytest.raises(FrozenInstanceError):
        compiled.execution_enabled = True  # type: ignore[misc]
    with pytest.raises(TypeError):
        compiled.runtime_components[0] = compiled.runtime_components[0]  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        compiled.runtime_components[0].sha256 = "sha256:" + "0" * 64  # type: ignore[misc]


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("schema_version",), "2.0.0"),
        (("platform", "os"), "linux"),
        (("platform", "architecture"), "x86_64"),
        (("platform", "filesystem"), "unknown"),
        (("runtime", "release_tag"), "latest"),
        (("runtime", "archive_size_bytes"), 11_089_824),
        (("runtime", "archive_sha256"), "sha256:" + "0" * 64),
        (("runtime", "max_closure_bytes"), 33_554_433),
        (("model", "revision"), "main"),
        (("model", "filename"), "caller.gguf"),
        (("model", "format_version"), 4),
        (("model", "quantization"), "Q5_K_M"),
        (("model", "size_bytes"), 2_104_932_801),
        (("model", "sha256"), "sha256:" + "0" * 64),
        (("installation", "root_source"), "caller_path"),
        (("installation", "runtime_relative_directory"), "../runtime"),
        (("installation", "symlinks_allowed"), True),
        (("installation", "hard_links_allowed"), True),
        (("verification", "hash_buffer_bytes"), 2_097_152),
        (("lifecycle", "state"), "active"),
        (("lifecycle", "review_period_days"), 181),
        (("activation_enabled",), True),
        (("verification_enabled",), True),
        (("receipt_enabled",), True),
        (("authority",), "grant"),
        (("execution_enabled",), True),
    ),
)
def test_substitution_and_privilege_widening_deny(
    path: tuple[str, ...], value: object
) -> None:
    document = manifest()
    target: dict[str, object] = document
    for key in path[:-1]:
        target = target[key]  # type: ignore[assignment]
    target[path[-1]] = value

    with pytest.raises(LocalModelArtifactManifestError) as raised:
        compile_local_model_artifact_manifest(document)
    assert raised.value.code == "LOCAL_MODEL_ARTIFACT_MANIFEST_MALFORMED"


def test_missing_extra_reordered_or_duplicate_components_deny() -> None:
    variants = []
    missing = manifest()
    missing["runtime"]["components"].pop()  # type: ignore[index]
    variants.append(missing)

    extra = manifest()
    extra["runtime"]["components"].append(  # type: ignore[index]
        copy.deepcopy(extra["runtime"]["components"][0])  # type: ignore[index]
    )
    variants.append(extra)

    reordered = manifest()
    reordered["runtime"]["components"].reverse()  # type: ignore[index]
    variants.append(reordered)

    changed = manifest()
    changed["runtime"]["components"][0]["sha256"] = "sha256:" + "0" * 64  # type: ignore[index]
    variants.append(changed)

    for document in variants:
        with pytest.raises(LocalModelArtifactManifestError):
            compile_local_model_artifact_manifest(document)


def test_unknown_or_removed_fields_deny() -> None:
    unknown = manifest()
    unknown["caller_path"] = "caller-selected-path"
    missing = manifest()
    missing.pop("source")

    for document in (unknown, missing):
        with pytest.raises(LocalModelArtifactManifestError):
            compile_local_model_artifact_manifest(document)


def test_resolver_accepts_no_caller_selector() -> None:
    with pytest.raises(TypeError):
        resolve_built_in_local_model_artifact_manifest(  # type: ignore[call-arg]
            manifest_id="caller-selected"
        )
