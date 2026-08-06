import { describe, expect, it } from "vitest";
import { policyStates } from "./App";

describe("authorization workflow UI", () => {
  it("exposes every required policy lifecycle state", () => {
    expect(policyStates).toEqual([
      "draft", "invalid", "awaiting approval", "active", "rejected", "revoked", "expired"
    ]);
  });
});
