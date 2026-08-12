import { describe, expect, it } from "vitest";

import {
  findingCollectionPath,
  findingNextStates,
  findingTransitionPath,
  findingTransitionRequest,
  parseFindingIds
} from "./FindingsWorkspace";

const first = "10000000-0000-4000-8000-000000000001";
const second = "20000000-0000-4000-8000-000000000001";

describe("supervised findings workspace", () => {
  it("preserves exact unique policy and evidence UUID selections", () => {
    expect(parseFindingIds(` ${first}, ${second} `, 64)).toEqual([first, second]);
  });

  it.each(["", "not-a-uuid", `${first},${first}`])("denies ambiguous UUID selection %s", (value) => {
    expect(() => parseFindingIds(value, 64)).toThrow("FINDING_SELECTION_INVALID");
  });

  it("offers only contract-defined next states", () => {
    expect(findingNextStates("candidate")).toEqual(["scope_reviewed", "rejected"]);
    expect(findingNextStates("report_ready")).toEqual(["closed", "validated"]);
    expect(findingNextStates("closed")).toEqual([]);
  });

  it("routes only to authenticated local finding lifecycle endpoints", () => {
    expect(findingCollectionPath(first)).toBe(`/workflows/${first}/findings`);
    expect(findingTransitionPath(second)).toBe(`/findings/${second}/transition`);
    expect(`${findingCollectionPath(first)}${findingTransitionPath(second)}`).not.toMatch(
      /execute|grant|submit/
    );
  });

  it("binds a human transition to the displayed immutable version", () => {
    expect(findingTransitionRequest(
      { version: 4 }, "report_ready", " reviewed ", "confirmed", "clear", ""
    )).toEqual({
      target_state: "report_ready",
      expected_version: 4,
      reason: "reviewed",
      validation_status: "confirmed",
      duplicate_status: "clear",
      duplicate_of: null
    });
  });

  it("includes duplicate identity only for an explicit duplicate outcome", () => {
    expect(findingTransitionRequest(
      { version: 2 }, "duplicate_reviewed", "match", "unverified", "duplicate", first
    ).duplicate_of).toBe(first);
  });
});
