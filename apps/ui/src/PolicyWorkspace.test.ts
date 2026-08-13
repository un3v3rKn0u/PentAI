import { describe, expect, it } from "vitest";
import { policyApprovalRequest, policyRevocationRequest, reviewedManifest, reviewedManifestDiff, reviewedPolicy } from "./PolicyWorkspace";

const manifest = { id: "10000000-0000-4000-8000-000000000001", engagement_id: "engagement-a", schema_version: "2.0.0", version_number: 1, content_hash: "a".repeat(64), document: { schema_version: "2.0.0", engagement: { id: "engagement-a" }, sources: [{ source_id: "source-a" }] }, valid: true, validation_status: "valid", issues: [] };
const policySummary = { id: manifest.id, manifest_version_id: manifest.id, content_hash: "b".repeat(64), compiler_version: "1.1.0", signer_key_id: "local-key", status: "active" };
const policyResponse = { ...policySummary, engagement_id: "engagement-a", policy: { schema_version: "1.0.0", engagement_id: "engagement-a", content_hash: "b".repeat(64), compiler: { version: "1.1.0" }, signature: { algorithm: "Ed25519", key_id: "local-key", value: "synthetic-signature" } } };

describe("supervised Policy lifecycle workspace", () => {
  it("recovers one exact canonical manifest for the selected engagement", () => {
    expect(reviewedManifest([manifest], manifest.id, "engagement-a")).toBe(manifest);
    expect(() => reviewedManifest([manifest], manifest.id, "engagement-b")).toThrow("MANIFEST_REVIEW_INVALID");
    expect(() => reviewedManifest([manifest, { ...manifest }], manifest.id, "engagement-a")).toThrow("MANIFEST_REVIEW_INVALID");
    expect(() => reviewedManifest([{ ...manifest, valid: false }], manifest.id, "engagement-a")).toThrow("MANIFEST_REVIEW_INVALID");
    expect(() => reviewedManifest([{ ...manifest, document: { ...manifest.document, engagement: { id: "engagement-b" } } }], manifest.id, "engagement-a")).toThrow("MANIFEST_REVIEW_INVALID");
  });
  it("accepts only an exact core-verified policy with matching active identity", () => {
    expect(reviewedPolicy(policyResponse, policySummary, "engagement-a", manifest.id)).toBe(policyResponse);
    expect(() => reviewedPolicy(policyResponse, policySummary, "engagement-b", manifest.id)).toThrow("POLICY_REVIEW_INVALID");
    expect(() => reviewedPolicy(policyResponse, policySummary, "engagement-a", null)).toThrow("POLICY_REVIEW_INVALID");
    expect(() => reviewedPolicy({ ...policyResponse, content_hash: "c".repeat(64) }, policySummary, "engagement-a", manifest.id)).toThrow("POLICY_REVIEW_INVALID");
  });
  it("binds semantic comparison to two exact immutable manifest versions", () => {
    const target = { ...manifest, id: "20000000-0000-4000-8000-000000000001", version_number: 2, content_hash: "c".repeat(64) };
    const response = { from: { id: manifest.id, version_number: 1, content_hash: manifest.content_hash }, to: { id: target.id, version_number: 2, content_hash: target.content_hash }, changed_sections: ["scope"], changes: [{ section: "scope", before: {}, after: { assets: [] } }] };
    expect(reviewedManifestDiff(response, [target, manifest], manifest.id, target.id)).toBe(response);
    expect(() => reviewedManifestDiff(response, [target, manifest], target.id, manifest.id)).toThrow("MANIFEST_DIFF_REVIEW_INVALID");
    expect(() => reviewedManifestDiff({ ...response, changed_sections: ["unknown"] }, [target, manifest], manifest.id, target.id)).toThrow("MANIFEST_DIFF_REVIEW_INVALID");
  });
  it("binds a typed approval to exact decision, expiry, and bounded reason", () => {
    expect(policyApprovalRequest("approved", "2030-01-01T10:00", "  reviewed exact hashes  ")).toEqual({ decision: "approved", expires_at: new Date("2030-01-01T10:00").toISOString(), reason: "reviewed exact hashes" });
  });
  it.each(["", "not-a-date", "2020-01-01"])("denies invalid approval expiry %s", (expiry) => expect(() => policyApprovalRequest("approved", expiry, "reviewed")).toThrow("POLICY_APPROVAL_EXPIRY_INVALID"));
  it("denies empty or oversized approval reasons", () => { expect(() => policyApprovalRequest("approved", "2030-01-01", " ")).toThrow("POLICY_APPROVAL_REASON_INVALID"); expect(() => policyApprovalRequest("approved", "2030-01-01", "x".repeat(501))).toThrow("POLICY_APPROVAL_REASON_INVALID"); });
  it("normalizes revocation reason and denies missing intent", () => { expect(policyRevocationRequest("  authorization changed  ")).toEqual({ reason: "authorization changed" }); expect(() => policyRevocationRequest(" ")).toThrow("POLICY_REVOCATION_REASON_INVALID"); });
});
