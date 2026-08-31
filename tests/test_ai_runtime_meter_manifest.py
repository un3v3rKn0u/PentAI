from __future__ import annotations

import copy
import unittest
from typing import Any
from uuid import uuid4

from pentai_core.ai_runtime_meter_manifest import (
    RuntimeMeterImplementationManifestError,
    compile_runtime_meter_implementation_manifest,
)


def manifest() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "manifest_id": str(uuid4()),
        "manifest_revision": 1,
        "implementation_id": "synthetic-meter",
        "implementation_version": 1,
        "implementation_artifact_digest": "sha256:" + "a" * 64,
        "provider_types": ["approved_remote", "local_runtime"],
        "supported_dimensions": ["requests", "runtime_seconds"],
        "source": "built_in_reviewed_manifest",
        "state": "inactive",
        "capability_production_enabled": False,
        "identity_binding_enabled": False,
        "attestation_enabled": False,
        "measurement_enabled": False,
        "authority": "none",
        "execution_enabled": False,
    }


class RuntimeMeterImplementationManifestTests(unittest.TestCase):
    def test_compiles_closed_inert_manifest_without_mutating_input(self) -> None:
        document = manifest()
        original = copy.deepcopy(document)

        compiled = compile_runtime_meter_implementation_manifest(document)

        self.assertEqual(document, original)
        self.assertEqual(compiled.manifest_id, document["manifest_id"])
        self.assertEqual(compiled.manifest_revision, 1)
        self.assertEqual(compiled.implementation_id, "synthetic-meter")
        self.assertEqual(compiled.implementation_version, 1)
        self.assertEqual(compiled.provider_types, {"approved_remote", "local_runtime"})
        self.assertEqual(compiled.supported_dimensions, {"requests", "runtime_seconds"})
        self.assertRegex(compiled.manifest_digest, r"^sha256:[a-f0-9]{64}$")

    def test_canonical_digest_is_order_independent(self) -> None:
        document = manifest()
        reordered = copy.deepcopy(document)
        reordered["provider_types"].reverse()
        reordered["supported_dimensions"].reverse()

        first = compile_runtime_meter_implementation_manifest(document)
        second = compile_runtime_meter_implementation_manifest(reordered)

        self.assertEqual(first.manifest_digest, second.manifest_digest)
        self.assertEqual(first.normalized_manifest_json, second.normalized_manifest_json)

    def test_digest_binds_artifact_and_capability_semantics(self) -> None:
        baseline = compile_runtime_meter_implementation_manifest(manifest())
        for field, value in (
            ("implementation_artifact_digest", "sha256:" + "b" * 64),
            ("implementation_version", 2),
            ("provider_types", ["local_runtime"]),
            ("supported_dimensions", ["requests"]),
        ):
            changed = manifest()
            changed["manifest_id"] = baseline.manifest_id
            changed[field] = value
            compiled = compile_runtime_meter_implementation_manifest(changed)
            self.assertNotEqual(baseline.manifest_digest, compiled.manifest_digest)

    def test_missing_malformed_and_privilege_expanding_manifests_deny(self) -> None:
        invalid: list[dict[str, Any]] = []
        for field, value in (
            ("schema_version", "2.0.0"),
            ("implementation_artifact_digest", "caller-artifact"),
            ("source", "caller_assertion"),
            ("state", "active"),
            ("capability_production_enabled", True),
            ("identity_binding_enabled", True),
            ("attestation_enabled", True),
            ("measurement_enabled", True),
            ("authority", "grant"),
            ("execution_enabled", True),
        ):
            malformed = manifest()
            malformed[field] = value
            invalid.append(malformed)
        missing = manifest()
        missing.pop("implementation_id")
        invalid.append(missing)

        for document in invalid:
            with self.subTest(document=document):
                with self.assertRaises(RuntimeMeterImplementationManifestError) as raised:
                    compile_runtime_meter_implementation_manifest(document)
                self.assertEqual(
                    raised.exception.code,
                    "AI_RUNTIME_METER_IMPLEMENTATION_MANIFEST_MALFORMED",
                )

    def test_duplicate_unsupported_and_payload_bearing_manifests_deny(self) -> None:
        for field, value in (
            ("provider_types", []),
            ("provider_types", ["local_runtime", "local_runtime"]),
            ("provider_types", ["caller_provider"]),
            ("supported_dimensions", []),
            ("supported_dimensions", ["requests", "requests"]),
            ("supported_dimensions", ["caller_usage"]),
        ):
            malformed = manifest()
            malformed[field] = value
            with self.assertRaises(RuntimeMeterImplementationManifestError):
                compile_runtime_meter_implementation_manifest(malformed)

        for field in (
            "credential",
            "secret_reference",
            "prompt",
            "provider_response",
            "usage",
            "pricing",
            "tokenizer",
            "diagnostic",
            "payload",
        ):
            malformed = manifest()
            malformed[field] = "synthetic but forbidden"
            with self.assertRaises(RuntimeMeterImplementationManifestError):
                compile_runtime_meter_implementation_manifest(malformed)
