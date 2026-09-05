from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from pentai_policy import canonical_json, content_hash
from pentai_policy.document import contract_issues


class LocalModelArtifactManifestError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RuntimeArtifactComponent:
    installed_filename: str
    archive_filename: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class CompiledLocalModelArtifactManifest:
    """Immutable, inactive artifact identity; never a verification or grant."""

    manifest_id: str
    manifest_revision: int
    provider_id: str
    model_id: str
    platform_os: str
    platform_architecture: str
    runtime_components: tuple[RuntimeArtifactComponent, ...]
    normalized_manifest_json: str
    manifest_digest: str
    activation_enabled: bool
    verification_enabled: bool
    receipt_enabled: bool
    authority: str
    execution_enabled: bool


_BUILT_IN_LOCAL_MODEL_ARTIFACT_MANIFEST_JSON = canonical_json({
    "schema_version": "1.0.0",
    "manifest_id": "macos-arm64-llama-b10516-qwen25-coder-3b-q4km",
    "manifest_revision": 1,
    "platform": {
        "os": "macos",
        "architecture": "arm64",
        "filesystem": "apfs",
        "assurance": "owned_local_development",
    },
    "runtime": {
        "provider_id": "llama.cpp",
        "release_tag": "b10516",
        "source_commit": "b95502ba9aa0eb73a2f4fc8878d7fbe6a847a0b9",
        "archive_filename": "llama-b10516-bin-macos-arm64.tar.gz",
        "archive_size_bytes": 11_089_823,
        "archive_sha256": (
            "sha256:ee3324327d621026ae80c24031670e65fa62a0b23a3a027dbe2f65f240affd30"
        ),
        "entrypoint": "llama-cli",
        "max_closure_bytes": 33_554_432,
        "components": [
            {
                "installed_filename": "llama-cli",
                "archive_filename": "llama-cli",
                "size_bytes": 49_960,
                "sha256": "sha256:e298c3bd3cfec99e62b2a7f091178a4799b44fafa5917fa226a05dac11d94dd6",
            },
            {
                "installed_filename": "libllama-cli-impl.dylib",
                "archive_filename": "libllama-cli-impl.dylib",
                "size_bytes": 394_632,
                "sha256": "sha256:aaeb47a5a9367f7b72faf716936a9df67a3596bbfd529e1a6239803b0646b7c2",
            },
            {
                "installed_filename": "libllama-server-impl.dylib",
                "archive_filename": "libllama-server-impl.dylib",
                "size_bytes": 9_549_112,
                "sha256": "sha256:5d55fc43a8c43f7cbe0848fbb8af033cb5c173fe5b5cd3b7f07cd277aba9dfdd",
            },
            {
                "installed_filename": "libmtmd.0.dylib",
                "archive_filename": "libmtmd.0.1.2.dylib",
                "size_bytes": 1_337_744,
                "sha256": "sha256:afac5bf0760f4728034e94ce9543a17e17fd6063a116027e4fdec87112a0ecd6",
            },
            {
                "installed_filename": "libllama-common.0.dylib",
                "archive_filename": "libllama-common.0.1.2.dylib",
                "size_bytes": 7_931_288,
                "sha256": "sha256:88a97aafdbb66c2f599252de37d0d0dcc1b8856c87865219220b9cfcb46538ca",
            },
            {
                "installed_filename": "libllama.0.dylib",
                "archive_filename": "libllama.0.1.2.dylib",
                "size_bytes": 2_911_648,
                "sha256": "sha256:905c80dcdcf86c2eba9e5c16d57cefabbc5401b1a8eb135114f4cb609c270ae3",
            },
            {
                "installed_filename": "libggml.0.dylib",
                "archive_filename": "libggml.0.20.2.dylib",
                "size_bytes": 59_872,
                "sha256": "sha256:ba2c2e16d64f978cb1647b748dd38e22810209dcf893d6d58339a8585b5bc97e",
            },
            {
                "installed_filename": "libggml-base.0.dylib",
                "archive_filename": "libggml-base.0.20.2.dylib",
                "size_bytes": 730_280,
                "sha256": "sha256:6b8c464537103f8d84378cfd380c778d0caad7e688874fa31ec1153129639e51",
            },
            {
                "installed_filename": "libggml-cpu.0.dylib",
                "archive_filename": "libggml-cpu.0.20.2.dylib",
                "size_bytes": 918_064,
                "sha256": "sha256:8cb0168cc3103ae992ef52bbb50d4a942cfb058bdaf43041aae198cd58c038f2",
            },
            {
                "installed_filename": "libggml-blas.0.dylib",
                "archive_filename": "libggml-blas.0.20.2.dylib",
                "size_bytes": 58_776,
                "sha256": "sha256:fab45ce5b26a5b3d61b8b66507a3b0c5957b795ae7540c105f316c56ddcfabb6",
            },
            {
                "installed_filename": "libggml-metal.0.dylib",
                "archive_filename": "libggml-metal.0.20.2.dylib",
                "size_bytes": 900_968,
                "sha256": "sha256:639977e0cc973aa94ce62cf657fea904835c0de4281a8daa1b7c0d1465f152b1",
            },
            {
                "installed_filename": "libggml-rpc.0.dylib",
                "archive_filename": "libggml-rpc.0.20.2.dylib",
                "size_bytes": 133_792,
                "sha256": "sha256:a0338158f8be419186a11c0173116e3ee70ba9c55cd3165ecea93bce9146be90",
            },
        ],
    },
    "model": {
        "model_id": "Qwen/Qwen2.5-Coder-3B-Instruct-GGUF:Q4_K_M",
        "repository": "Qwen/Qwen2.5-Coder-3B-Instruct-GGUF",
        "revision": "aebf6a0f72261b12fb8199bc580fe172fe86c901",
        "filename": "qwen2.5-coder-3b-instruct-q4_k_m.gguf",
        "format": "gguf",
        "format_version": 3,
        "quantization": "Q4_K_M",
        "size_bytes": 2_104_932_800,
        "sha256": "sha256:724fb256bec1ff062b2f65e4569e871ad2e95ab2a3989723d1769c54294730b7",
    },
    "installation": {
        "root_source": "native_user_application_support",
        "runtime_relative_directory": (
            "PentAI/artifacts/runtime/llama.cpp/b10516/macos-arm64"
        ),
        "model_relative_directory": (
            "PentAI/artifacts/models/qwen2.5-coder-3b-instruct/"
            "aebf6a0f72261b12fb8199bc580fe172fe86c901"
        ),
        "directory_mode": "0700",
        "runtime_file_mode": "0500",
        "data_file_mode": "0400",
        "owner": "effective_user",
        "regular_files_only": True,
        "link_count": 1,
        "symlinks_allowed": False,
        "hard_links_allowed": False,
        "writable_ancestors_allowed": False,
    },
    "verification": {
        "open_read_only": True,
        "close_on_exec": True,
        "no_follow": True,
        "hash_open_descriptor": True,
        "hash_buffer_bytes": 1_048_576,
        "stable_identity_fields": [
            "device",
            "inode",
            "size",
            "mtime",
            "ctime",
            "birthtime",
        ],
        "gguf_magic": "GGUF",
        "gguf_version": 3,
        "quantization": "Q4_K_M",
    },
    "lifecycle": {
        "state": "inactive",
        "decision_date": "2026-09-05",
        "review_period_days": 180,
        "activation_required": True,
        "replacement_invalidates_receipts": True,
        "startup_advancement_enabled": False,
    },
    "source": "adr_0008_reviewed_decision",
    "activation_enabled": False,
    "verification_enabled": False,
    "receipt_enabled": False,
    "authority": "none",
    "execution_enabled": False,
})


def compile_local_model_artifact_manifest(
    document: dict[str, Any],
) -> CompiledLocalModelArtifactManifest:
    """Validate exact v1 identity; validation does not make a caller authoritative."""
    if contract_issues(document, "local-model-artifact-manifest-v1.schema.json"):
        raise LocalModelArtifactManifestError(
            "LOCAL_MODEL_ARTIFACT_MANIFEST_MALFORMED",
            "local model artifact manifest is malformed or unsupported",
        )
    normalized = copy.deepcopy(document)
    components = tuple(
        RuntimeArtifactComponent(
            installed_filename=item["installed_filename"],
            archive_filename=item["archive_filename"],
            size_bytes=item["size_bytes"],
            sha256=item["sha256"],
        )
        for item in normalized["runtime"]["components"]
    )
    normalized_json = canonical_json(normalized)
    return CompiledLocalModelArtifactManifest(
        manifest_id=normalized["manifest_id"],
        manifest_revision=normalized["manifest_revision"],
        provider_id=normalized["runtime"]["provider_id"],
        model_id=normalized["model"]["model_id"],
        platform_os=normalized["platform"]["os"],
        platform_architecture=normalized["platform"]["architecture"],
        runtime_components=components,
        normalized_manifest_json=normalized_json,
        manifest_digest="sha256:" + content_hash(normalized),
        activation_enabled=normalized["activation_enabled"],
        verification_enabled=normalized["verification_enabled"],
        receipt_enabled=normalized["receipt_enabled"],
        authority=normalized["authority"],
        execution_enabled=normalized["execution_enabled"],
    )


_COMPILED_BUILT_IN_LOCAL_MODEL_ARTIFACT_MANIFEST = (
    compile_local_model_artifact_manifest(
        json.loads(_BUILT_IN_LOCAL_MODEL_ARTIFACT_MANIFEST_JSON)
    )
)


def resolve_built_in_local_model_artifact_manifest() -> CompiledLocalModelArtifactManifest:
    """Return the one repository-owned inactive manifest without caller selection."""
    return _COMPILED_BUILT_IN_LOCAL_MODEL_ARTIFACT_MANIFEST
