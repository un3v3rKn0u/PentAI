import { describe, expect, it } from "vitest";

import {
  evidenceDeletionPath,
  evidenceDeletionRequest,
  evidenceMetadataPath,
  evidenceOriginalPath,
  evidencePreviewPath,
  evidenceRedactionPath,
  parseRedactionSpans
} from "./EvidenceWorkspace";

const workflow = "10000000-0000-4000-8000-000000000001";
const evidence = "20000000-0000-4000-8000-000000000001";
const derivative = "30000000-0000-4000-8000-000000000001";

describe("supervised evidence workspace", () => {
  it("routes only through authenticated evidence custody endpoints", () => {
    expect(evidenceOriginalPath(workflow)).toBe(`/workflows/${workflow}/evidence/originals`);
    expect(evidenceMetadataPath(evidence)).toBe(`/evidence/${evidence}/metadata`);
    expect(evidenceRedactionPath(evidence)).toBe(`/evidence/${evidence}/redactions`);
    expect(evidencePreviewPath(derivative)).toBe(`/evidence/derivatives/${derivative}/preview`);
    expect(evidenceDeletionPath()).toBe("/evidence/deletions");
    expect(`${evidenceOriginalPath(workflow)}${evidencePreviewPath(derivative)}`).not.toMatch(/execute|grant|submit/);
  });

  it("binds retention deletion to the exact artifact, full digest, reason, and confirmation", () => {
    const digest = "a".repeat(64);
    expect(evidenceDeletionRequest("redaction", derivative, digest, "  expired case data  ", true)).toEqual({
      artifact_type: "redaction",
      artifact_id: derivative,
      expected_sha256: digest,
      reason: "expired case data",
      confirm_permanent_deletion: true
    });
  });

  it("does not manufacture permanent-deletion confirmation", () => {
    expect(evidenceDeletionRequest("original", evidence, "b".repeat(64), "retention expired", false))
      .toMatchObject({ confirm_permanent_deletion: false });
  });

  it("parses exact ordered Unicode-codepoint redaction selections", () => {
    expect(parseRedactionSpans("2:5:secret\n8:13:personal_data")).toEqual([
      { start: 2, end: 5, reason: "secret" },
      { start: 8, end: 13, reason: "personal_data" }
    ]);
  });

  it.each(["", "2:2:secret", "-1:2:secret", "x:2:secret", "1:2:unknown", "1:2:secret:extra", "4:8:secret\n7:9:irrelevant", "8:9:secret\n2:4:irrelevant"])(
    "denies malformed redaction selection %s",
    (value) => expect(() => parseRedactionSpans(value)).toThrow("EVIDENCE_REDACTION_SELECTION_INVALID")
  );
});
