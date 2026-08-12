import { describe, expect, it } from "vitest";

import {
  parseReportIds,
  reportDraftPath,
  reportFileExportPath,
  reportFileExportRequest
} from "./ReportsWorkspace";

const first = "10000000-0000-4000-8000-000000000001";
const second = "20000000-0000-4000-8000-000000000001";

describe("supervised reports workspace", () => {
  it("preserves an explicit unique report selection", () => {
    expect(parseReportIds(` ${first}, ${second} `, 100)).toEqual([first, second]);
  });

  it.each([
    "",
    "not-a-uuid",
    `${first},${first}`
  ])("denies ambiguous report selection %s", (value) => {
    expect(() => parseReportIds(value, 100)).toThrow("REPORT_SELECTION_INVALID");
  });

  it("routes report types only to their supervised draft endpoints", () => {
    expect(reportDraftPath("findings", first)).toBe(`/workflows/${first}/report-drafts`);
    expect(reportDraftPath("no_findings", first)).toBe(
      `/workflows/${first}/no-findings-report-drafts`
    );
    expect(reportDraftPath("findings", first)).not.toContain("submit");
  });

  it("binds local export to the exact report, format, directory, and confirmation", () => {
    expect(reportFileExportPath(first)).toBe(`/report-drafts/${first}/file-exports`);
    expect(reportFileExportRequest("findings", "pdf", "/synthetic/exports", true)).toEqual({
      report_kind: "findings",
      format: "pdf",
      destination_directory: "/synthetic/exports",
      confirm_restricted_export: true
    });
  });

  it("exposes no submission path in the export request", () => {
    const path = reportFileExportPath(first);
    const request = reportFileExportRequest("no_findings", "json", "/synthetic", false);
    expect(path).not.toMatch(/submit|upload/);
    expect(request.confirm_restricted_export).toBe(false);
    expect(request).not.toHaveProperty("submission_enabled");
  });
});
