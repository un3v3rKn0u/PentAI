import { describe, expect, it } from "vitest";
import { encodeBytesBase64, prepareSourceImport, sourceFileMediaType } from "./IntakeWorkspace";

describe("supervised Intake workspace", () => {
  it("encodes selected bytes without exposing a filesystem path", () => expect(encodeBytesBase64(new Uint8Array([0, 1, 2, 253, 254, 255]))).toBe("AAEC/f7/"));
  it("derives only approved media types", () => { expect(sourceFileMediaType("Rules.JSON")).toBe("application/json"); expect(() => sourceFileMediaType("rules.exe")).toThrow("SOURCE_MEDIA_TYPE_INVALID"); });
  it("prepares pasted content without inventing provenance", async () => expect(await prepareSourceImport("pasted_text", "contract", "terms", "", null)).toEqual({ mode: "pasted_text", authority: "contract", content: "terms" }));
  it("prepares URL acquisition without resolving it in the browser", async () => expect(await prepareSourceImport("url", "program_page", "", "https://example.invalid/rules", null)).toEqual({ mode: "url", authority: "program_page", url: "https://example.invalid/rules" }));
  it("denies a missing selected file", async () => await expect(prepareSourceImport("file", "contract", "", "", null)).rejects.toThrow("SOURCE_FILE_REQUIRED"));
});
