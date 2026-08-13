import { describe, expect, it } from "vitest";
import { encodeBytesBase64, prepareSourceImport, reviewedSource, sourceFileMediaType } from "./IntakeWorkspace";

const source = { id: "10000000-0000-4000-8000-000000000001", authority: "contract", retrieved_at: "2030-01-01T10:00:00Z", content_hash: "a".repeat(64) };

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
});
