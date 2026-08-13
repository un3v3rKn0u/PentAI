import { describe, expect, it } from "vitest";
import { policyApprovalRequest, policyRevocationRequest, reviewedManifest } from "./PolicyWorkspace";

const manifest = { id: "10000000-0000-4000-8000-000000000001", engagement_id: "engagement-a", schema_version: "2.0.0", version_number: 1, content_hash: "a".repeat(64), document: { schema_version: "2.0.0", engagement: { id: "engagement-a" }, sources: [{ source_id: "source-a" }] }, valid: true, validation_status: "valid", issues: [] };

describe("supervised Policy lifecycle workspace", () => {
  it("recovers one exact canonical manifest for the selected engagement", () => {
    expect(reviewedManifest([manifest], manifest.id, "engagement-a")).toBe(manifest);
    expect(() => reviewedManifest([manifest], manifest.id, "engagement-b")).toThrow("MANIFEST_REVIEW_INVALID");
    expect(() => reviewedManifest([manifest, { ...manifest }], manifest.id, "engagement-a")).toThrow("MANIFEST_REVIEW_INVALID");
    expect(() => reviewedManifest([{ ...manifest, valid: false }], manifest.id, "engagement-a")).toThrow("MANIFEST_REVIEW_INVALID");
    expect(() => reviewedManifest([{ ...manifest, document: { ...manifest.document, engagement: { id: "engagement-b" } } }], manifest.id, "engagement-a")).toThrow("MANIFEST_REVIEW_INVALID");
  });
  it("binds a typed approval to exact decision, expiry, and bounded reason", () => {
    expect(policyApprovalRequest("approved", "2030-01-01T10:00", "  reviewed exact hashes  ")).toEqual({ decision: "approved", expires_at: new Date("2030-01-01T10:00").toISOString(), reason: "reviewed exact hashes" });
  });
  it.each(["", "not-a-date", "2020-01-01"])("denies invalid approval expiry %s", (expiry) => expect(() => policyApprovalRequest("approved", expiry, "reviewed")).toThrow("POLICY_APPROVAL_EXPIRY_INVALID"));
  it("denies empty or oversized approval reasons", () => { expect(() => policyApprovalRequest("approved", "2030-01-01", " ")).toThrow("POLICY_APPROVAL_REASON_INVALID"); expect(() => policyApprovalRequest("approved", "2030-01-01", "x".repeat(501))).toThrow("POLICY_APPROVAL_REASON_INVALID"); });
  it("normalizes revocation reason and denies missing intent", () => { expect(policyRevocationRequest("  authorization changed  ")).toEqual({ reason: "authorization changed" }); expect(() => policyRevocationRequest(" ")).toThrow("POLICY_REVOCATION_REASON_INVALID"); });
});
