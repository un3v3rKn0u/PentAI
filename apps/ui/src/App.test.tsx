import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import { App, buildManifest, coreRequest, networkManifestSettings, phaseOneWorkspaces } from "./App";
import { buildIntentTarget } from "./AuthorizationWorkspace";
import { networkSetupRequirement, parseSourceAddresses } from "./NetworkProfilesWorkspace";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("authorization workflow safety boundary", () => {
  it("exposes every required Phase 1 workspace exactly once", () => {
    expect(phaseOneWorkspaces.map((workspace) => workspace.label)).toEqual([
      "Dashboard", "Programs", "Intake", "Assessments", "Evidence", "Findings", "Reports", "Logs"
    ]);
    expect(new Set(phaseOneWorkspaces.map((workspace) => workspace.id)).size).toBe(phaseOneWorkspaces.length);
  });

  it("marks one current workspace and hides inactive content from navigation", () => {
    const markup = renderToStaticMarkup(<App />);
    expect(markup).toContain('aria-label="Phase 1 workspaces"');
    expect(markup.match(/aria-current="page"/g)).toHaveLength(1);
    expect(markup).toContain('class="workspace-pane" hidden=""');
  });
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

  it("preserves every reviewed source and blocks unresolved version conflicts", () => {
    const contract = { id: "10000000-0000-4000-8000-000000000001", reference: "contract://rules", authority: "contract", retrieved_at: "2030-01-01T10:00:00Z", content_hash: "a".repeat(64) };
    const page = { ...contract, id: "10000000-0000-4000-8000-000000000002", authority: "program_page", content_hash: "b".repeat(64) };
    const document = buildManifest(
      { name: "Synthetic program" },
      { id: "20000000-0000-4000-8000-000000000001", effective_from: "2030-01-01T00:00:00Z", expires_at: "2030-01-02T00:00:00Z" },
      { sources: [contract, page], primary: contract, conflicts: [contract.reference], normalizationWarnings: ["Conflicting immutable versions require restrictive review: deny until clarified"] },
      { assetType: "domain", target: "example.test", allowedPaths: ["/api"], deniedPaths: ["/api/admin"], allowedPorts: [443], allowedCapabilities: ["network.http.get"], requestsPerSecond: 1, maximumTotalRequests: 50, maximumResponseBytes: 100000, rationale: "exact restrictive transcription" }
    );
    expect(document.sources.map((item: Record<string, string>) => item.source_id)).toEqual([contract.id, page.id]);
    expect(document.field_provenance["/scope"]).toEqual([
      { source_id: contract.id, content_hash: contract.content_hash },
      { source_id: page.id, content_hash: page.content_hash }
    ]);
    expect(document.unresolved_questions).toContain(`Resolve conflicting immutable source versions for ${contract.reference}.`);
    expect(document.approvals.status).toBe("pending");
    expect(document.scope.assets[0].canonical_value).toBe("example.test");
    expect(document.normalization_warnings).toContain("Human normalization review: exact restrictive transcription");
  });

  it("preserves explicit wildcard apex semantics in the manifest draft", () => {
    const source = { id: "10000000-0000-4000-8000-000000000001", reference: "contract://rules", authority: "contract", retrieved_at: "2030-01-01T10:00:00Z", content_hash: "a".repeat(64) };
    const document = buildManifest(
      { name: "Synthetic program" },
      { id: "20000000-0000-4000-8000-000000000001", effective_from: "2030-01-01T00:00:00Z", expires_at: "2030-01-02T00:00:00Z" },
      { sources: [source], primary: source, conflicts: [], normalizationWarnings: [] },
      { assetType: "wildcard_domain", target: "*.example.test", includeApex: false, allowedPaths: ["/"], deniedPaths: [], allowedPorts: [443], allowedCapabilities: ["network.http.get"], requestsPerSecond: 1, maximumTotalRequests: 5, maximumResponseBytes: 1000, rationale: "exact wildcard transcription" }
    );
    expect(document.scope.assets[0]).toMatchObject({ type: "wildcard_domain", canonical_value: "*.example.test", include_apex: false });
  });

  it("keeps an explicit deny boundary independent from the allow rule", () => {
    const source = { id: "10000000-0000-4000-8000-000000000001", reference: "contract://rules", authority: "contract", retrieved_at: "2030-01-01T10:00:00Z", content_hash: "a".repeat(64) };
    const document = buildManifest(
      { name: "Synthetic program" },
      { id: "20000000-0000-4000-8000-000000000001", effective_from: "2030-01-01T00:00:00Z", expires_at: "2030-01-02T00:00:00Z" },
      { sources: [source], primary: source, conflicts: [], normalizationWarnings: [] },
      { assetType: "domain", target: "example.test", denyBoundary: { assetType: "wildcard_domain", target: "*.third-party.test", includeApex: true }, allowedPaths: ["/api"], deniedPaths: [], allowedPorts: [443], allowedCapabilities: ["network.http.get"], requestsPerSecond: 1, maximumTotalRequests: 5, maximumResponseBytes: 1000, rationale: "exact boundary transcription" }
    );
    expect(document.scope.assets).toHaveLength(2);
    expect(document.scope.assets[1]).toMatchObject({ effect: "deny", type: "wildcard_domain", canonical_value: "*.third-party.test", include_apex: true, source_reference: source.id });
    expect(document.scope.assets[1]).not.toHaveProperty("allowed_ports");
    expect(document.scope.assets[1]).not.toHaveProperty("ownership_verified");
  });

  it("emits reviewed scope rows with their exact source provenance", () => {
    const first = { id: "10000000-0000-4000-8000-000000000001", reference: "contract://rules", authority: "contract", retrieved_at: "2030-01-01T10:00:00Z", content_hash: "a".repeat(64) };
    const second = { ...first, id: "10000000-0000-4000-8000-000000000002", reference: "contract://exclusions", content_hash: "b".repeat(64) };
    const document = buildManifest(
      { name: "Synthetic program" },
      { id: "20000000-0000-4000-8000-000000000001", effective_from: "2030-01-01T00:00:00Z", expires_at: "2030-01-02T00:00:00Z" },
      { sources: [first, second], primary: first, conflicts: [], normalizationWarnings: [] },
      { assetType: "domain", target: "unused.test", assetRules: [{ effect: "allow", assetType: "domain", target: "example.test", sourceReference: first.id, allowedPaths: ["/api"], deniedPaths: [], allowedPorts: [443] }, { effect: "deny", assetType: "domain", target: "excluded.test", sourceReference: second.id }], allowedPaths: ["/"], deniedPaths: [], allowedPorts: [443], allowedCapabilities: ["network.http.get"], requestsPerSecond: 1, maximumTotalRequests: 5, maximumResponseBytes: 1000, rationale: "reviewed rows" }
    );
    expect(document.scope.assets.map((asset) => asset.source_reference)).toEqual([first.id, second.id]);
    expect(document.scope.assets[1]).not.toHaveProperty("allowed_paths");
    expect(document.scope.assets[1]).not.toHaveProperty("ownership_verified");
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
