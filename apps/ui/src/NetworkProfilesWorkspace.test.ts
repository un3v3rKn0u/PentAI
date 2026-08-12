import { describe, expect, it } from "vitest";

import { networkProfileActivationRequest, networkProfileRevocationRequest, networkSetupRequirement, parseSourceAddresses } from "./NetworkProfilesWorkspace";

describe("supervised Network Profiles workspace", () => {
  it("binds activation to the exact proposal and explicit confirmation", () => {
    expect(networkProfileActivationRequest("proposal-1", true, "tunnel_resolver", "192.0.2.10, 192.0.2.10")).toEqual({ proposal_id: "proposal-1", confirm_route: true, resolver_mode: "tunnel_resolver", registered_source_ipv4: ["192.0.2.10"], registered_source_ipv6: [], ipv6_mode: "disabled" });
  });
  it("denies incomplete confirmation and unknown resolver modes", () => {
    expect(() => networkProfileActivationRequest("proposal-1", false, "tunnel_resolver", "192.0.2.10")).toThrow("NETWORK_PROFILE_CONFIRMATION_INCOMPLETE");
    expect(() => networkProfileActivationRequest("proposal-1", true, "custom", "192.0.2.10")).toThrow("NETWORK_PROFILE_RESOLVER_MODE_INVALID");
  });
  it("normalizes address and reason input without inventing authority", () => {
    expect(parseSourceAddresses(" 192.0.2.10, ,198.51.100.8 ")).toEqual(["192.0.2.10", "198.51.100.8"]);
    expect(networkProfileRevocationRequest("  route changed  ")).toEqual({ reason: "route changed" });
    expect(() => networkProfileRevocationRequest(" ")).toThrow("NETWORK_PROFILE_REVOCATION_REASON_INVALID");
  });
  it("renders unknown proposal requirements as unresolved", () => {
    expect(networkSetupRequirement("UNKNOWN")).toContain("unknown setup requirement");
  });
});
