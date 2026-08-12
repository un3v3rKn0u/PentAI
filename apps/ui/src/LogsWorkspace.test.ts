import { describe, expect, it } from "vitest";

import { auditPath, filterAuditEvents } from "./LogsWorkspace";

const events = [
  {
    event_id: "10000000-0000-4000-8000-000000000001",
    action: "policy.activated",
    actor_type: "human",
    actor_id: "local-reviewer",
    subject_type: "policy_bundle",
    subject_id: "policy-a"
  },
  {
    event_id: "20000000-0000-4000-8000-000000000002",
    action: "evidence.deletion_completed",
    actor_type: "service",
    actor_id: "evidence-recovery",
    subject_type: "evidence_deletion",
    subject_id: "deletion-b"
  }
];

describe("supervised logs workspace", () => {
  it("uses only the authenticated read-only audit endpoint", () => {
    expect(auditPath()).toBe("/audit");
    expect(auditPath()).not.toMatch(/delete|export|execute|grant|submit/);
  });

  it.each(["POLICY", "local-reviewer", "policy_bundle", "policy-a", "10000000"])(
    "filters across exact audit identity fields using %s",
    (query) => expect(filterAuditEvents(events, query)).toEqual([events[0]])
  );

  it("returns the original ordered history for an empty filter", () => {
    expect(filterAuditEvents(events, "   ")).toBe(events);
  });

  it("does not search arbitrary event data that may contain sensitive values", () => {
    expect(filterAuditEvents([{ ...events[0], data: { secret: "synthetic-sensitive" } }], "synthetic-sensitive"))
      .toEqual([]);
  });
});
