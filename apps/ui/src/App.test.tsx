import { afterEach, describe, expect, it, vi } from "vitest";

import { coreRequest, networkManifestSettings } from "./App";
import { buildIntentTarget } from "./AuthorizationWorkspace";
import { networkSetupRequirement, parseSourceAddresses } from "./NetworkProfilesWorkspace";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("authorization workflow safety boundary", () => {
  it("keeps every discovered network setting behind explicit human review", () => {
    expect(networkSetupRequirement("CONFIRM_ROUTE")).toContain("Confirm");
    expect(networkSetupRequirement("CONFIRM_RESOLVER_MODE")).toContain("confirm");
    expect(networkSetupRequirement("ENTER_REGISTERED_SOURCE_IP")).toContain("Enter");
    expect(networkSetupRequirement("UNKNOWN")).toContain("before activation");
  });

  it("normalizes human-entered source address lists without inventing an address", () => {
    expect(parseSourceAddresses(" 8.8.8.8, 2001:4860:4860::8888 ")).toEqual([
      "8.8.8.8", "2001:4860:4860::8888"
    ]);
    expect(parseSourceAddresses(" , ")).toEqual([]);
  });

  it("copies only the confirmed profile into a manifest network section", () => {
    const profile = {
      route_profile_id: "route-aaaaaaaaaaaaaaaaaaaaaaaa",
      registered_source_ipv4: ["8.8.8.8"],
      registered_source_ipv6: [],
      ipv6_mode: "disabled",
      resolver_mode: "approved_resolver",
      resolver_addresses: ["192.0.2.53"]
    };
    expect(networkManifestSettings(profile)).toEqual({
      route_mode: "local_gateway",
      route_profile_id: profile.route_profile_id,
      registered_source_ipv4: ["8.8.8.8"],
      registered_source_ipv6: [],
      ipv6_mode: "disabled",
      dns_mode: "approved_resolver",
      approved_resolvers: ["192.0.2.53"],
      pause_on_identity_change: true
    });
    expect(networkManifestSettings().route_profile_id).toBe("network-profile-required");
  });

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

  it("authenticates every core request without exposing the credential in the URL", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "ready" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    const credential = `runtime-${crypto.randomUUID()}`;

    await coreRequest(
      { apiBaseUrl: "http://127.0.0.1:49152/api/v1", credential },
      "/readiness"
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:49152/api/v1/readiness",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: `Bearer ${credential}` })
      })
    );
    expect(fetchMock.mock.calls[0][0]).not.toContain(credential);
  });

  it("surfaces authentication failure without echoing response details", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          detail: { code: "AUTHENTICATION_REQUIRED", message: "Authentication required" }
        }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      )
    );

    await expect(
      coreRequest(
        {
          apiBaseUrl: "http://127.0.0.1:49152/api/v1",
          credential: `runtime-${crypto.randomUUID()}`
        },
        "/readiness"
      )
    ).rejects.toThrow("AUTHENTICATION_REQUIRED");
  });
});
