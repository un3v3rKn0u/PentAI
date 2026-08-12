import { describe, expect, it } from "vitest";

import { programCreateRequest, programsPath } from "./ProgramsWorkspace";

describe("supervised Programs workspace", () => {
  it("uses the authenticated programs collection without mutation-specific paths", () => {
    expect(programsPath()).toBe("/programs");
    expect(programsPath()).not.toMatch(/activate|delete|execute|grant|submit/);
  });

  it("normalizes the human-entered name without inventing program authority", () => {
    expect(programCreateRequest("  Synthetic program  ")).toEqual({
      name: "Synthetic program",
      platform: "local"
    });
  });

  it("preserves an empty name for default-deny handling", () => {
    expect(programCreateRequest("   ").name).toBe("");
  });
});
