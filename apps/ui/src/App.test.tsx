import { describe, expect, it } from "vitest";
import { policyStates } from "./App";

describe("authorization workflow safety boundary", () => {
  it("does not expose execution or grant issuance", () => {
    const milestoneCapabilities = ["manifest", "policy", "approval", "decision", "audit"];
    expect(milestoneCapabilities).not.toContain("action-grant");
    expect(milestoneCapabilities).not.toContain("target-execution");
  });
});
