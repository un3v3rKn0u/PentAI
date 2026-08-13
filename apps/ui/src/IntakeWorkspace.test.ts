import { describe, expect, it } from "vitest";
import { encodeBytesBase64, prepareSourceImport, reviewedEngagement, reviewedNormalization, reviewedSource, reviewedSourceBundle, sourceFileMediaType } from "./IntakeWorkspace";

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
