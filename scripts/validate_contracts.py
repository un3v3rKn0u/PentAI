from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas" / "v1"
PHASE1_MANIFEST = ROOT / "docs" / "security" / "phase1_completion_manifest.json"
PHASE1_SCHEMA = SCHEMAS / "phase1-completion-manifest-v1.schema.json"
PHASE1_REQUIREMENTS = {
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


def _validate_phase1_manifest(failures: list[str]) -> None:
    try:
        manifest = json.loads(PHASE1_MANIFEST.read_text(encoding="utf-8"))
        schema = json.loads(PHASE1_SCHEMA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"{PHASE1_MANIFEST}: {exc}")
        return
    for error in sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(manifest),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    ):
        location = ".".join(str(part) for part in error.absolute_path) or "root"
        failures.append(f"{PHASE1_MANIFEST}:{location}: {error.message}")
    requirements = manifest.get("requirements")
    if not isinstance(requirements, list):
        return
    identifiers = {
        item.get("id") for item in requirements if isinstance(item, dict)
    }
    if identifiers != PHASE1_REQUIREMENTS:
        missing = sorted(PHASE1_REQUIREMENTS - identifiers)
        unexpected = sorted(identifiers - PHASE1_REQUIREMENTS, key=str)
        failures.append(
            f"{PHASE1_MANIFEST}: requirement set mismatch; "
            f"missing={missing}, unexpected={unexpected}"
        )
    invariant_register = (ROOT / "docs/security/security_invariants.md").read_text(
        encoding="utf-8"
    )
    for requirement in requirements:
        if not isinstance(requirement, dict):
            continue
        requirement_id = requirement.get("id", "unknown")
        evidence_paths = [
            *requirement.get("implementation", []),
            *requirement.get("tests", []),
            requirement.get("review"),
        ]
        if requirement.get("hosted_check"):
            evidence_paths.append(requirement["hosted_check"])
        for relative in evidence_paths:
            if not isinstance(relative, str):
                continue
            resolved = (ROOT / relative).resolve()
            if ROOT not in resolved.parents or not resolved.is_file():
                failures.append(
                    f"{PHASE1_MANIFEST}: {requirement_id} evidence is missing: {relative}"
                )
        for invariant in requirement.get("invariants", []):
            if invariant not in invariant_register:
                failures.append(
                    f"{PHASE1_MANIFEST}: {requirement_id} references unknown {invariant}"
                )
    for requirement_id in ("P1-GATEWAY-001", "P1-WORKER-001"):
        requirement = next(
            (item for item in requirements if item.get("id") == requirement_id), None
        )
        if not requirement or not requirement.get("hosted_check"):
            failures.append(
                f"{PHASE1_MANIFEST}: {requirement_id} requires hosted containment evidence"
            )
    action_plan = (ROOT / "action_plan.md").read_text(encoding="utf-8")
    try:
        phase1 = action_plan.split("## Phase 1 — Safe Supervised MVP", 1)[1].split(
            "## Phase 2 — Agent and Plugin Platform", 1
        )[0]
    except IndexError:
        failures.append(f"{ROOT / 'action_plan.md'}: Phase 1 boundaries are missing")
    else:
        if "- [ ]" in phase1:
            failures.append(
                f"{ROOT / 'action_plan.md'}: Phase 1 contains unchecked action items"
            )


def main() -> int:
    failures: list[str] = []
    identifiers: set[str] = set()
    for path in sorted(SCHEMAS.glob("*.schema.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"{path}: {exc}")
            continue
        for required in ("$schema", "$id", "title"):
            if required not in document:
                failures.append(f"{path}: missing {required}")
        identifier = document.get("$id")
        if identifier in identifiers:
            failures.append(f"{path}: duplicate $id {identifier}")
        if identifier:
            identifiers.add(identifier)
        if document.get("type") != "object":
            failures.append(f"{path}: root type must be object")
    _validate_phase1_manifest(failures)
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Validated {len(identifiers)} JSON contract files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
