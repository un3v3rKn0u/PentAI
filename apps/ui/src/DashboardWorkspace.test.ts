import { describe, expect, it } from "vitest";

import { operationalDashboardCards } from "./DashboardWorkspace";

const baseline = {
  connected: true,
  safetyState: "active",
  policyState: "active",
  networkProfiles: [{ status: "active", route_interface: "fixture0", resolver_mode: "tunnel_resolver" }],
  audit: { verification: { valid: true, event_count: 7 } }
};

describe("operational dashboard", () => {
  it("reports only authoritative state passed from authenticated workspace reads", () => {
    expect(operationalDashboardCards(baseline).map(({ label, value, tone }) => ({ label, value, tone }))).toEqual([
      { label: "Authenticated core", value: "Connected", tone: "ready" },
      { label: "Global safety", value: "active", tone: "ready" },
      { label: "Policy lifecycle", value: "active", tone: "ready" },
      { label: "Network profile", value: "Active", tone: "ready" },
      { label: "Audit integrity", value: "Verified", tone: "ready" }
    ]);
  });

  it("defaults missing authority and incomplete verification away from ready", () => {
    const cards = operationalDashboardCards({
      connected: false,
      safetyState: "loading",
      policyState: "draft",
      networkProfiles: [],
      audit: { verification: { valid: true } }
    });
    expect(cards.map((card) => card.tone)).not.toContain(undefined);
    expect(cards.filter((card) => card.tone === "ready")).toEqual([]);
    expect(cards.find((card) => card.label === "Audit integrity")?.value).toBe("Not verified");
  });

  it("treats multiple active profiles and an invalid audit chain as blocked", () => {
    const cards = operationalDashboardCards({
      ...baseline,
      networkProfiles: [baseline.networkProfiles[0], { ...baseline.networkProfiles[0], route_interface: "fixture1" }],
      audit: { verification: { valid: false, event_count: 7 } }
    });
    expect(cards.find((card) => card.label === "Network profile")).toMatchObject({ value: "Ambiguous", tone: "blocked" });
    expect(cards.find((card) => card.label === "Audit integrity")).toMatchObject({ value: "Invalid", tone: "blocked" });
  });
});
