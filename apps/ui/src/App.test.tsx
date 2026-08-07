import { describe, expect, it } from "vitest";

import { buildIntentTarget } from "./App";

describe("authorization workflow safety boundary", () => {
  it("does not expose execution or grant issuance", () => {
    const milestoneCapabilities = ["manifest", "policy", "approval", "decision", "audit"];
    expect(milestoneCapabilities).not.toContain("action-grant");
    expect(milestoneCapabilities).not.toContain("target-execution");
  });

  it("builds a canonical domain target for policy evaluation", () => {
    expect(buildIntentTarget("https://Example.test/api/items?limit=1")).toEqual({
      scheme: "https",
      host: { kind: "domain", value: "example.test" },
      port: 443,
      path: "/api/items",
      query: "limit=1",
      canonical_url: "https://example.test/api/items?limit=1"
    });
  });

  it("classifies IP targets without treating them as domains", () => {
    expect(buildIntentTarget("http://192.0.2.1/status").host).toEqual({
      kind: "ipv4",
      value: "192.0.2.1"
    });
    expect(buildIntentTarget("https://[2001:db8::1]/status").host).toEqual({
      kind: "ipv6",
      value: "2001:db8::1"
    });
  });

  it.each([
    " https://example.test/api",
    "https://user:secret@example.test/api",
    "https://example.test/api#fragment",
    "ftp://example.test/api",
    "https:\\\\example.test\\api"
  ])("rejects authorization-ambiguous target %s", (url) => {
    expect(() => buildIntentTarget(url)).toThrow("TARGET_AMBIGUOUS");
  });
});
