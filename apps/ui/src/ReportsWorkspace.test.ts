import { describe, expect, it } from "vitest";

import {
  parseReportIds,
  reportDraftPath,
  reportFileExportPath,
  reportFileExportRequest
} from "./ReportsWorkspace";
import { coveragePath, coverageRecordRequest, selectCoverageId, verifiedCoverage } from "./ReportsWorkspace";
import { coveragePolicySelection } from "./ReportsWorkspace";

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
  it("binds human coverage to exact rules, interval, evidence, and limitations", () => {
    expect(coveragePath(first)).toBe(`/workflows/${first}/coverage`);
    const request = coverageRecordRequest({ assetRuleId: first, capabilityRuleId: second, capability: "network.http.get", outcome: "tested_no_findings", startedAt: "2030-01-01T10:00", endedAt: "2030-01-01T11:00", evidenceIds: first, limitations: "Synthetic route only", notes: "Reviewed", idempotencyKey: "coverage-ui-stable-001" });
    expect(request).toMatchObject({ asset_rule_id: first, capability_rule_id: second, evidence_ids: [first], limitations: ["Synthetic route only"] });
    expect(selectCoverageId("", first)).toBe(first);
    expect(selectCoverageId(first, second)).toBe(`${first},${second}`);
  });
  it("denies unsupported coverage claims and authority-bearing responses", () => {
    expect(() => coverageRecordRequest({ assetRuleId: first, capabilityRuleId: second, capability: "network.http.get", outcome: "tested_no_findings", startedAt: "2030-01-01T10:00", endedAt: "2030-01-01T11:00", evidenceIds: "", limitations: "limited", notes: "reviewed", idempotencyKey: "coverage-ui-stable-001" })).toThrow("COVERAGE_RECORD_INVALID");
    expect(() => verifiedCoverage({ coverage_id: first, workflow_id: first, coverage_complete: true, outcome: "tested_no_findings", evidence_ids: [first], limitations: ["limited"] }, first)).toThrow("COVERAGE_RESPONSE_INVALID");
  });
  it("derives only permitted rules from the exact active workflow policy", () => {
    const policy = { id: first, policy: { asset_rules: [{ rule_id: first, effect: "allow", asset_type: "domain", matcher: { value: "example.test" } }, { rule_id: second, effect: "deny", asset_type: "domain", matcher: { value: "denied.test" } }], capability_rules: [{ rule_id: second, capability: "network.http.get", effect: "allow", applicable_asset_rule_ids: [first] }] } };
    const selection = coveragePolicySelection({ workflow: { workflow_id: first, policy_bundle_id: first, execution_enabled: false } }, first, policy, "active");
    expect(selection.assetRules.map((rule) => rule.ruleId)).toEqual([first]);
    expect(selection.capabilityRules).toMatchObject([{ ruleId: second, capability: "network.http.get", applicableAssetRuleIds: [first] }]);
  });
  it("denies stale, inactive, or authority-bearing workflow policy bindings", () => {
    const policy = { id: first, policy: { asset_rules: [], capability_rules: [] } };
    expect(() => coveragePolicySelection({ workflow: { workflow_id: first, policy_bundle_id: second, execution_enabled: false } }, first, policy, "active")).toThrow("COVERAGE_POLICY_BINDING_INVALID");
    expect(() => coveragePolicySelection({ workflow: { workflow_id: first, policy_bundle_id: first, execution_enabled: true } }, first, policy, "active")).toThrow("COVERAGE_POLICY_BINDING_INVALID");
    expect(() => coveragePolicySelection({ workflow: { workflow_id: first, policy_bundle_id: first, execution_enabled: false } }, first, policy, "revoked")).toThrow("COVERAGE_POLICY_BINDING_INVALID");
  });
});
