from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/security/phase1_completion_manifest.json"
SCHEMA_PATH = ROOT / "schemas/v1/phase1-completion-manifest-v1.schema.json"
REQUIRED_IDS = {
    "P1-POLICY-001",
    "P1-AUTH-001",
    "P1-GATEWAY-001",
    "P1-WORKER-001",
    "P1-NETWORK-001",
    "P1-WORKFLOW-001",
    "P1-EVIDENCE-001",
    "P1-REPORT-001",
    "P1-RECOVERY-001",
}


def _documents() -> tuple[dict[str, object], dict[str, object]]:
    return (
        json.loads(MANIFEST_PATH.read_text(encoding="utf-8")),
        json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
    )


def test_phase1_manifest_has_exact_complete_evidence_set() -> None:
    manifest, schema = _documents()
    Draft202012Validator(schema).validate(manifest)
    requirements = manifest["requirements"]
    assert isinstance(requirements, list)
    assert {requirement["id"] for requirement in requirements} == REQUIRED_IDS
    for requirement in requirements:
        assert requirement["status"] == "implemented"
        evidence = [
            *requirement["implementation"],
            *requirement["tests"],
            requirement["review"],
        ]
        hosted = requirement.get("hosted_check")
        if hosted:
            evidence.append(hosted)
        assert all((ROOT / relative).is_file() for relative in evidence)


def test_phase1_manifest_rejects_missing_capability_evidence() -> None:
    manifest, schema = _documents()
    incomplete = deepcopy(manifest)
    incomplete["requirements"][0]["tests"] = []
    errors = tuple(Draft202012Validator(schema).iter_errors(incomplete))
    assert errors


def test_phase1_action_items_are_closed() -> None:
    action_plan = (ROOT / "action_plan.md").read_text(encoding="utf-8")
    phase1 = action_plan.split("## Phase 1 — Safe Supervised MVP", 1)[1].split(
        "## Phase 2 — Agent and Plugin Platform", 1
    )[0]
    assert "- [ ]" not in phase1
