import { describe, expect, it } from "vitest";
import { policyApprovalRequest, policyRevocationRequest } from "./PolicyWorkspace";

describe("supervised Policy lifecycle workspace", () => {
  it("binds a typed approval to exact decision, expiry, and bounded reason", () => {
    expect(policyApprovalRequest("approved", "2030-01-01T10:00", "  reviewed exact hashes  ")).toEqual({ decision: "approved", expires_at: new Date("2030-01-01T10:00").toISOString(), reason: "reviewed exact hashes" });
  });
  it.each(["", "not-a-date", "2020-01-01"])("denies invalid approval expiry %s", (expiry) => expect(() => policyApprovalRequest("approved", expiry, "reviewed")).toThrow("POLICY_APPROVAL_EXPIRY_INVALID"));
  it("denies empty or oversized approval reasons", () => { expect(() => policyApprovalRequest("approved", "2030-01-01", " ")).toThrow("POLICY_APPROVAL_REASON_INVALID"); expect(() => policyApprovalRequest("approved", "2030-01-01", "x".repeat(501))).toThrow("POLICY_APPROVAL_REASON_INVALID"); });
  it("normalizes revocation reason and denies missing intent", () => { expect(policyRevocationRequest("  authorization changed  ")).toEqual({ reason: "authorization changed" }); expect(() => policyRevocationRequest(" ")).toThrow("POLICY_REVOCATION_REASON_INVALID"); });
});
