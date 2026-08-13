import { describe, expect, it } from "vitest";
import { encodeBytesBase64, prepareSourceImport, reviewedAccountUse, reviewedAssetRules, reviewedDataHandling, reviewedEngagement, reviewedNormalization, reviewedOperationalLimits, reviewedReporting, reviewedScopeBoundaries, reviewedSource, reviewedSourceBundle, reviewedSourceStatements, reviewedTechniques, reviewedTestingSchedule, sourceFileMediaType } from "./IntakeWorkspace";

const source = { id: "10000000-0000-4000-8000-000000000001", authority: "contract", reference: "contract://authorization", retrieved_at: "2030-01-01T10:00:00Z", content_hash: "a".repeat(64) };
const engagement = { id: "20000000-0000-4000-8000-000000000001", program_id: "program-a", status: "draft", effective_from: "2030-01-01T10:00:00Z", expires_at: "2030-01-02T10:00:00Z" };

describe("supervised Intake workspace", () => {
  it("encodes selected bytes without exposing a filesystem path", () => expect(encodeBytesBase64(new Uint8Array([0, 1, 2, 253, 254, 255]))).toBe("AAEC/f7/"));
  it("derives only approved media types", () => { expect(sourceFileMediaType("Rules.JSON")).toBe("application/json"); expect(() => sourceFileMediaType("rules.exe")).toThrow("SOURCE_MEDIA_TYPE_INVALID"); });
  it("preserves explicit source timing and version provenance", async () => expect(await prepareSourceImport("pasted_text", "contract", "2030-01-01T10:00", " rules-v2 ", "terms", "", null)).toEqual({ mode: "pasted_text", authority: "contract", effectiveAt: new Date("2030-01-01T10:00").toISOString(), sourceVersion: "rules-v2", content: "terms" }));
  it("prepares URL acquisition without resolving it in the browser", async () => expect(await prepareSourceImport("url", "program_page", "", "", "", "https://example.invalid/rules", null)).toEqual({ mode: "url", authority: "program_page", effectiveAt: null, sourceVersion: null, url: "https://example.invalid/rules" }));
  it("denies a missing selected file", async () => await expect(prepareSourceImport("file", "contract", "", "", "", "", null)).rejects.toThrow("SOURCE_FILE_REQUIRED"));
  it("denies malformed or oversized optional provenance", async () => {
    await expect(prepareSourceImport("pasted_text", "contract", "not-a-time", "", "terms", "", null)).rejects.toThrow("SOURCE_EFFECTIVE_AT_INVALID");
    await expect(prepareSourceImport("pasted_text", "contract", "", "v".repeat(129), "terms", "", null)).rejects.toThrow("SOURCE_VERSION_INVALID");
  });
  it("selects one exact immutable source and denies ambiguous history", () => {
    expect(reviewedSource([source], source.id)).toBe(source);
    expect(() => reviewedSource([source, { ...source }], source.id)).toThrow("SOURCE_REVIEW_INVALID");
    expect(() => reviewedSource([{ ...source, content_hash: "bad" }], source.id)).toThrow("SOURCE_REVIEW_INVALID");
  });
  it("orders a multi-source review by explicit authority precedence", () => {
    const page = { ...source, id: "10000000-0000-4000-8000-000000000002", authority: "program_page", reference: "https://example.invalid/rules" };
    const review = reviewedSourceBundle([page, source], [page.id, source.id], "");
    expect(review.sources.map((item) => item.id)).toEqual([source.id, page.id]);
    expect(review.primary.id).toBe(source.id);
    expect(review.conflicts).toEqual([]);
  });
  it("denies divergent versions until restrictive conflict review is recorded", () => {
    const changed = { ...source, id: "10000000-0000-4000-8000-000000000003", content_hash: "b".repeat(64) };
    expect(() => reviewedSourceBundle([source, changed], [source.id, changed.id], "")).toThrow("SOURCE_CONFLICT_REVIEW_REQUIRED");
    const review = reviewedSourceBundle([source, changed], [source.id, changed.id], "Use the deny rule and request clarification");
    expect(review.conflicts).toEqual([source.reference]);
    expect(review.normalizationWarnings[0]).toContain("Use the deny rule");
  });
  it("denies unknown authority and malformed effective-time precedence", () => {
    expect(() => reviewedSourceBundle([{ ...source, authority: "unknown" }], [source.id], "")).toThrow("SOURCE_BUNDLE_INVALID");
    expect(() => reviewedSourceBundle([{ ...source, effective_at: "not-a-time" }], [source.id], "")).toThrow("SOURCE_BUNDLE_INVALID");
  });
  it("reviews bounded candidate statements with exact immutable provenance", () => {
    expect(reviewedSourceStatements([{ sourceId: source.id, fieldPath: "/scope", statement: " Only example.test is in scope. ", interpretation: "Allow only example.test." }], [source])).toEqual([{ sourceId: source.id, contentHash: source.content_hash, fieldPath: "/scope", statement: "Only example.test is in scope.", interpretation: "Allow only example.test.", status: "candidate" }]);
  });
  it("denies missing, unknown, duplicate, or unbounded source statements", () => {
    const valid = { sourceId: source.id, fieldPath: "/scope", statement: "Only example.test is in scope.", interpretation: "Allow only example.test." };
    expect(() => reviewedSourceStatements([], [source])).toThrow("SOURCE_STATEMENTS_INVALID");
    expect(() => reviewedSourceStatements([{ ...valid, sourceId: "missing" }], [source])).toThrow("SOURCE_STATEMENT_INVALID");
    expect(() => reviewedSourceStatements([{ ...valid, fieldPath: "/approvals" }], [source])).toThrow("SOURCE_STATEMENT_INVALID");
    expect(() => reviewedSourceStatements([valid, valid], [source])).toThrow("SOURCE_STATEMENT_DUPLICATE");
    expect(() => reviewedSourceStatements([{ ...valid, statement: "x".repeat(501) }], [source])).toThrow("SOURCE_STATEMENT_INVALID");
  });
  it("normalizes explicit scope and budget review without widening it", () => {
    expect(reviewedNormalization({ assetType: "domain", target: "Example.TEST.", allowedPaths: " /api, /status, /api ", deniedPaths: "/api/admin", allowedPorts: "443", allowedCapabilities: "network.http.get", requestsPerSecond: "0.5", maximumTotalRequests: "25", maximumResponseBytes: "4096", rationale: "  exact restrictive transcription  " })).toEqual({
      assetType: "domain", target: "example.test", allowedPaths: ["/api", "/status"], deniedPaths: ["/api/admin"], allowedPorts: [443], allowedCapabilities: ["network.http.get"], requestsPerSecond: 0.5, maximumTotalRequests: 25, maximumResponseBytes: 4096, rationale: "exact restrictive transcription"
    });
  });
  it("normalizes each typed asset without inferring wildcard apex authority", () => {
    const base = { assetType: "domain", target: "example.test", includeApex: "false", allowedPaths: "/", deniedPaths: "", allowedPorts: "443", allowedCapabilities: "network.http.get", requestsPerSecond: "1", maximumTotalRequests: "5", maximumResponseBytes: "1000", rationale: "reviewed" };
    expect(reviewedNormalization({ ...base, assetType: "wildcard_domain", target: "*.Example.TEST" })).toMatchObject({ assetType: "wildcard_domain", target: "*.example.test", includeApex: false });
    expect(reviewedNormalization({ ...base, assetType: "url", target: "https://Example.TEST/api" }).target).toBe("https://example.test/api");
    expect(reviewedNormalization({ ...base, assetType: "ipv4", target: "192.0.2.10" }).target).toBe("192.0.2.10");
    expect(reviewedNormalization({ ...base, assetType: "ipv6", target: "2001:DB8::1" }).target).toBe("2001:db8::1");
    expect(reviewedNormalization({ ...base, assetType: "cidr", target: "192.0.2.0/24" }).target).toBe("192.0.2.0/24");
  });
  it("records a complete typed deny boundary without granting it allow fields", () => {
    const review = reviewedNormalization({ assetType: "domain", target: "example.test", includeApex: "false", denyAssetType: "wildcard_domain", denyTarget: "*.third-party.test", denyIncludeApex: "true", allowedPaths: "/", deniedPaths: "", allowedPorts: "443", allowedCapabilities: "network.http.get", requestsPerSecond: "1", maximumTotalRequests: "5", maximumResponseBytes: "1000", rationale: "reviewed explicit boundary" });
    expect(review.denyBoundary).toEqual({ assetType: "wildcard_domain", target: "*.third-party.test", includeApex: true });
  });
  it("denies partial or exactly contradictory out-of-scope boundaries", () => {
    const valid = { assetType: "domain", target: "example.test", allowedPaths: "/", deniedPaths: "", allowedPorts: "443", allowedCapabilities: "network.http.get", requestsPerSecond: "1", maximumTotalRequests: "5", maximumResponseBytes: "1000", rationale: "reviewed" };
    expect(() => reviewedNormalization({ ...valid, denyAssetType: "domain", denyTarget: "" })).toThrow("DENY_BOUNDARY_INVALID");
    expect(() => reviewedNormalization({ ...valid, denyAssetType: "", denyTarget: "other.test" })).toThrow("DENY_BOUNDARY_INVALID");
    expect(() => reviewedNormalization({ ...valid, denyAssetType: "domain", denyTarget: "EXAMPLE.TEST" })).toThrow("DENY_BOUNDARY_CONFLICT");
  });
  it("reviews bounded multi-row scope with exact per-row provenance", () => {
    const rules = reviewedAssetRules([
      { effect: "allow", assetType: "domain", target: "EXAMPLE.TEST", sourceReference: "source-a", allowedPaths: "/api,/api", deniedPaths: "/api/admin", allowedPorts: "443" },
      { effect: "deny", assetType: "wildcard_domain", target: "*.third-party.test", sourceReference: "source-b", includeApex: "true" }
    ], ["source-a", "source-b"]);
    expect(rules).toEqual([
      { effect: "allow", assetType: "domain", target: "example.test", sourceReference: "source-a", allowedPaths: ["/api"], deniedPaths: ["/api/admin"], allowedPorts: [443] },
      { effect: "deny", assetType: "wildcard_domain", target: "*.third-party.test", sourceReference: "source-b", includeApex: true }
    ]);
  });
  it("denies invalid multi-row authority and canonical duplicates", () => {
    const allow = { effect: "allow", assetType: "domain", target: "example.test", sourceReference: "source-a", allowedPaths: "/", deniedPaths: "", allowedPorts: "443" };
    expect(() => reviewedAssetRules([], ["source-a"])).toThrow("ASSET_RULES_INVALID");
    expect(() => reviewedAssetRules([allow], ["source-a", "source-a"])).toThrow("ASSET_RULES_INVALID");
    expect(() => reviewedAssetRules([{ ...allow, sourceReference: "unknown" }], ["source-a"])).toThrow("ASSET_RULE_INVALID");
    expect(() => reviewedAssetRules([{ ...allow, effect: "deny" }], ["source-a"])).toThrow("DENY_RULE_AUTHORITY_INVALID");
    expect(() => reviewedAssetRules([{ ...allow, effect: "deny", allowedPaths: "", allowedPorts: "" }], ["source-a"])).toThrow("ALLOW_RULE_REQUIRED");
    expect(() => reviewedAssetRules([allow, { effect: "deny", assetType: "domain", target: "EXAMPLE.TEST", sourceReference: "source-a" }], ["source-a"])).toThrow("ASSET_RULE_CONFLICT");
  });
  it("reviews explicit external-infrastructure boundaries", () => {
    expect(reviewedScopeBoundaries({ thirdPartyServices: "deny", sharedHostingAndCdn: "allow_if_explicit", scopeExpansionProcess: "Stop and obtain written authorization for the exact asset." })).toEqual({
      thirdPartyServices: "deny",
      sharedHostingAndCdn: "allow_if_explicit",
      scopeExpansionProcess: "Stop and obtain written authorization for the exact asset."
    });
  });
  it("denies incomplete or invalid scope-boundary review", () => {
    const valid = { thirdPartyServices: "deny", sharedHostingAndCdn: "deny", scopeExpansionProcess: "Stop and obtain written authorization." };
    expect(() => reviewedScopeBoundaries({ ...valid, thirdPartyServices: "unknown" })).toThrow("SCOPE_BOUNDARY_REVIEW_INVALID");
    expect(() => reviewedScopeBoundaries({ ...valid, scopeExpansionProcess: " " })).toThrow("SCOPE_BOUNDARY_REVIEW_INVALID");
    expect(() => reviewedScopeBoundaries({ ...valid, scopeExpansionProcess: "x".repeat(501) })).toThrow("SCOPE_BOUNDARY_REVIEW_INVALID");
  });
  it("reviews explicit allowed, denied, and conditional techniques", () => {
    expect(reviewedTechniques({ allowedCapabilities: "network.http.get", deniedCapabilities: "network.http.options", conditionalCapability: "network.http.head", conditionalApprovalType: "sensitive_validation", conditionalConditions: "written approval,active engagement", methodGET: "true", methodHEAD: "false", methodOPTIONS: "false" })).toEqual({
      allowedCapabilities: ["network.http.get"],
      deniedCapabilities: ["network.http.options"],
      conditionalCapabilities: [{ capability: "network.http.head", approvalType: "sensitive_validation", conditions: ["written approval", "active engagement"] }],
      allowedHttpMethods: ["GET"]
    });
  });
  it("denies incomplete, overlapping, or method-inconsistent techniques", () => {
    const valid = { allowedCapabilities: "network.http.get", deniedCapabilities: "", conditionalCapability: "", conditionalApprovalType: "", conditionalConditions: "", methodGET: "true", methodHEAD: "false", methodOPTIONS: "false" };
    expect(() => reviewedTechniques({ ...valid, allowedCapabilities: "" })).toThrow("TECHNIQUE_REVIEW_INVALID");
    expect(() => reviewedTechniques({ ...valid, deniedCapabilities: "network.http.get" })).toThrow("TECHNIQUE_CLASSIFICATION_CONFLICT");
    expect(() => reviewedTechniques({ ...valid, conditionalCapability: "network.http.head" })).toThrow("CONDITIONAL_CAPABILITY_INVALID");
    expect(() => reviewedTechniques({ ...valid, methodGET: "false" })).toThrow("TECHNIQUE_METHOD_CONFLICT");
  });
  it("reviews complete operational ceilings and stop conditions", () => {
    expect(reviewedOperationalLimits({ requestsPerSecond: "2", perHostRequestsPerSecond: "1", burstLimit: "2", concurrentConnections: "1", maximumRuntimeMinutes: "30", maximumTotalRequests: "50", maximumRequestBodyBytes: "0", maximumResponseBytes: "1000", stopConditions: "authorization changes,safety control pauses,authorization changes" })).toEqual({
      requestsPerSecond: 2, perHostRequestsPerSecond: 1, burstLimit: 2, concurrentConnections: 1, maximumRuntimeMinutes: 30, maximumTotalRequests: 50, maximumRequestBodyBytes: 0, maximumResponseBytes: 1000, stopConditions: ["authorization changes", "safety control pauses"]
    });
  });
  it("denies malformed or internally inconsistent operational limits", () => {
    const valid = { requestsPerSecond: "2", perHostRequestsPerSecond: "1", burstLimit: "1", concurrentConnections: "1", maximumRuntimeMinutes: "30", maximumTotalRequests: "50", maximumRequestBodyBytes: "0", maximumResponseBytes: "1000", stopConditions: "authorization changes" };
    expect(() => reviewedOperationalLimits({ ...valid, perHostRequestsPerSecond: "3" })).toThrow("OPERATIONAL_LIMIT_REVIEW_INVALID");
    expect(() => reviewedOperationalLimits({ ...valid, burstLimit: "1.5" })).toThrow("OPERATIONAL_LIMIT_REVIEW_INVALID");
    expect(() => reviewedOperationalLimits({ ...valid, maximumRequestBodyBytes: "" })).toThrow("OPERATIONAL_LIMIT_REVIEW_INVALID");
    expect(() => reviewedOperationalLimits({ ...valid, maximumRequestBodyBytes: "-1" })).toThrow("OPERATIONAL_LIMIT_REVIEW_INVALID");
    expect(() => reviewedOperationalLimits({ ...valid, stopConditions: " " })).toThrow("OPERATIONAL_LIMIT_REVIEW_INVALID");
  });
  it("reviews an explicit testing window and optional blackout", () => {
    expect(reviewedTestingSchedule({ testingDays: "Monday,tuesday,monday", testingStartTime: "09:00", testingEndTime: "17:00", testingTimezone: "UTC", blackoutStartsAt: "2030-01-01T12:00:00Z", blackoutEndsAt: "2030-01-01T13:00:00Z", blackoutReason: "Maintenance" })).toEqual({
      allowedTestingWindows: [{ days: ["monday", "tuesday"], startTime: "09:00", endTime: "17:00", timezone: "UTC" }],
      blackoutPeriods: [{ startsAt: new Date("2030-01-01T12:00").toISOString(), endsAt: new Date("2030-01-01T13:00").toISOString(), reason: "Maintenance" }]
    });
  });
  it("denies invalid testing windows and incomplete blackouts", () => {
    const valid = { testingDays: "monday", testingStartTime: "09:00", testingEndTime: "17:00", testingTimezone: "UTC", blackoutStartsAt: "", blackoutEndsAt: "", blackoutReason: "" };
    expect(() => reviewedTestingSchedule({ ...valid, testingDays: "holiday" })).toThrow("TESTING_WINDOW_REVIEW_INVALID");
    expect(() => reviewedTestingSchedule({ ...valid, testingTimezone: "Unknown/Zone" })).toThrow("TESTING_WINDOW_REVIEW_INVALID");
    expect(() => reviewedTestingSchedule({ ...valid, testingEndTime: "09:00" })).toThrow("TESTING_WINDOW_REVIEW_INVALID");
    expect(() => reviewedTestingSchedule({ ...valid, blackoutReason: "Maintenance" })).toThrow("BLACKOUT_PERIOD_REVIEW_INVALID");
    expect(() => reviewedTestingSchedule({ ...valid, blackoutStartsAt: "2030-01-02T10:00:00Z", blackoutEndsAt: "2030-01-01T10:00:00Z", blackoutReason: "Maintenance" })).toThrow("BLACKOUT_PERIOD_REVIEW_INVALID");
  });
  it("reviews identifier-only test account use without accepting credentials", () => {
    expect(reviewedAccountUse({ accountMode: "approved_test_accounts", approvedAccountReferences: "synthetic-user-1,synthetic-user-2,synthetic-user-1" })).toEqual({
      mode: "approved_test_accounts", approvedAccountReferences: ["synthetic-user-1", "synthetic-user-2"], sharedAccounts: "deny", credentialHandling: "external_secret_store_only"
    });
    expect(reviewedAccountUse({ accountMode: "unauthenticated_only", approvedAccountReferences: "" }).approvedAccountReferences).toEqual([]);
  });
  it("denies missing, conflicting, or secret-shaped account references", () => {
    expect(() => reviewedAccountUse({ accountMode: "approved_test_accounts", approvedAccountReferences: "" })).toThrow("ACCOUNT_REFERENCE_REQUIRED");
    expect(() => reviewedAccountUse({ accountMode: "unauthenticated_only", approvedAccountReferences: "synthetic-user" })).toThrow("ACCOUNT_REFERENCE_CONFLICT");
    expect(() => reviewedAccountUse({ accountMode: "approved_test_accounts", approvedAccountReferences: "user@example.test" })).toThrow("ACCOUNT_USE_REVIEW_INVALID");
  });
  it("reviews bounded real-user data handling and redaction", () => {
    expect(reviewedDataHandling({ realUserData: "minimal_if_explicit", maximumRecordsToView: "3", retentionDays: "7", remoteAiMaxClassification: "none", redactionRules: "remove credentials,remove identifiers,remove credentials" })).toEqual({
      realUserData: "minimal_if_explicit", maximumRecordsToView: 3, retentionDays: 7, approvedStorage: "local_encrypted", remoteAiMaxClassification: "none", redactionRules: ["remove credentials", "remove identifiers"]
    });
  });
  it("denies incomplete or contradictory data handling", () => {
    const valid = { realUserData: "avoid_and_stop", maximumRecordsToView: "", retentionDays: "7", remoteAiMaxClassification: "none", redactionRules: "remove credentials" };
    expect(() => reviewedDataHandling({ ...valid, retentionDays: "" })).toThrow("DATA_HANDLING_REVIEW_INVALID");
    expect(() => reviewedDataHandling({ ...valid, realUserData: "minimal_if_explicit" })).toThrow("REAL_USER_DATA_LIMIT_REQUIRED");
    expect(() => reviewedDataHandling({ ...valid, maximumRecordsToView: "1" })).toThrow("REAL_USER_DATA_LIMIT_CONFLICT");
    expect(() => reviewedDataHandling({ ...valid, remoteAiMaxClassification: "secret" })).toThrow("DATA_HANDLING_REVIEW_INVALID");
  });
  it("reviews reporting terms without enabling submission", () => {
    expect(reviewedReporting({ submissionChannel: "Program portal", requiredFields: "title,impact,title", evidenceRules: "redact secrets", disclosureTimeline: "Wait for written approval." })).toEqual({ submissionChannel: "Program portal", requiredFields: ["title", "impact"], evidenceRules: ["redact secrets"], disclosureTimeline: "Wait for written approval." });
  });
  it("denies incomplete reporting terms", () => {
    const valid = { submissionChannel: "Portal", requiredFields: "title", evidenceRules: "redact secrets", disclosureTimeline: "Wait for approval." };
    expect(() => reviewedReporting({ ...valid, submissionChannel: "" })).toThrow("REPORTING_REVIEW_INVALID");
    expect(() => reviewedReporting({ ...valid, requiredFields: "" })).toThrow("REPORTING_REVIEW_INVALID");
    expect(() => reviewedReporting({ ...valid, evidenceRules: "" })).toThrow("REPORTING_REVIEW_INVALID");
  });
  it("denies malformed or incomplete structured normalization", () => {
    const valid = { assetType: "domain", target: "example.test", allowedPaths: "/api", deniedPaths: "/admin", allowedPorts: "443", allowedCapabilities: "network.http.get", requestsPerSecond: "1", maximumTotalRequests: "50", maximumResponseBytes: "1000", rationale: "reviewed" };
    expect(() => reviewedNormalization({ ...valid, target: "*.example.test" })).toThrow("NORMALIZATION_REVIEW_INVALID");
    expect(() => reviewedNormalization({ ...valid, assetType: "ipv4", target: "192.0.2.01" })).toThrow("NORMALIZATION_REVIEW_INVALID");
    expect(() => reviewedNormalization({ ...valid, assetType: "url", target: "https://user@example.test/" })).toThrow("NORMALIZATION_REVIEW_INVALID");
    expect(() => reviewedNormalization({ ...valid, assetType: "cidr", target: "192.0.2.0/33" })).toThrow("NORMALIZATION_REVIEW_INVALID");
    expect(() => reviewedNormalization({ ...valid, allowedPaths: "api" })).toThrow("NORMALIZATION_REVIEW_INVALID");
    expect(() => reviewedNormalization({ ...valid, allowedPorts: "0" })).toThrow("NORMALIZATION_REVIEW_INVALID");
    expect(() => reviewedNormalization({ ...valid, rationale: " " })).toThrow("NORMALIZATION_REVIEW_INVALID");
  });
  it("binds engagement recovery to one exact program and validity window", () => {
    expect(reviewedEngagement([engagement], engagement.id, "program-a")).toBe(engagement);
    expect(() => reviewedEngagement([engagement], engagement.id, "program-b")).toThrow("ENGAGEMENT_REVIEW_INVALID");
    expect(() => reviewedEngagement([{ ...engagement, expires_at: engagement.effective_from }], engagement.id, "program-a")).toThrow("ENGAGEMENT_REVIEW_INVALID");
  });
});
