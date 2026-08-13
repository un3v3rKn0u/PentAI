import { FormEvent, useEffect, useState } from "react";

type Json = Record<string, any>;
export type SourceMode = "pasted_text" | "file" | "url";
export type IntakeState = "empty" | "ready" | "loading" | "denied" | "degraded" | "error";
export type SourceImport =
  | { mode: "pasted_text"; authority: string; effectiveAt: string | null; sourceVersion: string | null; content: string }
  | { mode: "file"; authority: string; effectiveAt: string | null; sourceVersion: string | null; filename: string; mediaType: string; contentBase64: string }
  | { mode: "url"; authority: string; effectiveAt: string | null; sourceVersion: string | null; url: string };

const maxSourceBytes = 2 * 1024 * 1024;
const authorityPrecedence: Record<string, number> = {
  contract: 0,
  program_staff: 1,
  program_page: 2,
  platform_rule: 3,
  internal_note: 4
};

export function reviewedSource(sources: Json[], sourceId: string) {
  const matches = sources.filter((source) => source.id === sourceId);
  const source = matches[0];
  if (matches.length !== 1 || !source || typeof source.content_hash !== "string" || !source.content_hash.match(/^[a-f0-9]{64}$/) || typeof source.authority !== "string" || typeof source.retrieved_at !== "string" || !Number.isFinite(Date.parse(source.retrieved_at))) throw new Error("SOURCE_REVIEW_INVALID");
  return source;
}

export type SourceBundleReview = {
  sources: Json[];
  primary: Json;
  conflicts: string[];
  normalizationWarnings: string[];
};

export type AssetType = "domain" | "wildcard_domain" | "url" | "ipv4" | "ipv6" | "cidr";
export type DenyBoundary = { assetType: AssetType; target: string; includeApex?: boolean };

export type NormalizationReview = {
  assetType: AssetType;
  target: string;
  includeApex?: boolean;
  denyBoundary?: DenyBoundary;
  allowedPaths: string[];
  deniedPaths: string[];
  allowedPorts: number[];
  allowedCapabilities: string[];
  requestsPerSecond: number;
  maximumTotalRequests: number;
  maximumResponseBytes: number;
  rationale: string;
};

function normalizedAssetValue(assetType: NormalizationReview["assetType"], value: string): string {
  const target = value.trim();
  const domain = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const normalizeDomain = (candidate: string) => {
    const normalized = candidate.toLowerCase().replace(/\.$/, "");
    if (!domain.test(normalized)) throw new Error("NORMALIZATION_REVIEW_INVALID");
    return normalized;
  };
  const normalizeIpv4 = (candidate: string) => {
    const octets = candidate.split(".");
    if (octets.length !== 4 || octets.some((octet) => !octet.match(/^(?:0|[1-9][0-9]{0,2})$/) || Number(octet) > 255)) throw new Error("NORMALIZATION_REVIEW_INVALID");
    return octets.join(".");
  };
  if (assetType === "domain") return normalizeDomain(target);
  if (assetType === "wildcard_domain") return `*.${normalizeDomain(target.startsWith("*.") ? target.slice(2) : target)}`;
  if (assetType === "ipv4") return normalizeIpv4(target);
  if (assetType === "ipv6") {
    try {
      const parsed = new URL(`http://[${target}]/`);
      if (!parsed.hostname.startsWith("[") || !target.includes(":")) throw new Error();
      return parsed.hostname.slice(1, -1).toLowerCase();
    } catch { throw new Error("NORMALIZATION_REVIEW_INVALID"); }
  }
  if (assetType === "cidr") {
    const [address, prefix, ...rest] = target.split("/");
    const maximum = address.includes(":") ? 128 : 32;
    if (rest.length > 0 || !prefix?.match(/^(?:0|[1-9][0-9]{0,2})$/) || Number(prefix) > maximum) throw new Error("NORMALIZATION_REVIEW_INVALID");
    const normalizedAddress: string = address.includes(":")
      ? normalizedAssetValue("ipv6", address)
      : normalizeIpv4(address);
    return `${normalizedAddress}/${Number(prefix)}`;
  }
  try {
    const parsed = new URL(target);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash) throw new Error();
    return parsed.toString();
  } catch { throw new Error("NORMALIZATION_REVIEW_INVALID"); }
}

export function reviewedNormalization(input: Record<string, string>): NormalizationReview {
  const assetTypes = ["domain", "wildcard_domain", "url", "ipv4", "ipv6", "cidr"] as const;
  const assetType = assetTypes.find((item) => item === input.assetType);
  if (!assetType) throw new Error("NORMALIZATION_REVIEW_INVALID");
  const target = normalizedAssetValue(assetType, input.target);
  const denyAssetType = assetTypes.find((item) => item === input.denyAssetType);
  const denyTarget = input.denyTarget?.trim() ?? "";
  if ((denyAssetType && !denyTarget) || (!denyAssetType && denyTarget)) throw new Error("DENY_BOUNDARY_INVALID");
  const denyBoundary = denyAssetType && denyTarget
    ? {
        assetType: denyAssetType,
        target: normalizedAssetValue(denyAssetType, denyTarget),
        ...(denyAssetType === "wildcard_domain" ? { includeApex: input.denyIncludeApex === "true" } : {})
      }
    : undefined;
  if (denyBoundary?.assetType === assetType && denyBoundary.target === target) throw new Error("DENY_BOUNDARY_CONFLICT");
  const paths = (value: string) => [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))];
  const allowedPaths = paths(input.allowedPaths);
  const deniedPaths = paths(input.deniedPaths);
  const allowedPorts = paths(input.allowedPorts).map(Number);
  const allowedCapabilities = paths(input.allowedCapabilities);
  const requestsPerSecond = Number(input.requestsPerSecond);
  const maximumTotalRequests = Number(input.maximumTotalRequests);
  const maximumResponseBytes = Number(input.maximumResponseBytes);
  const rationale = input.rationale.trim();
  if (
    allowedPaths.length === 0
    || [...allowedPaths, ...deniedPaths].some((path) => !path.startsWith("/"))
    || allowedPorts.length === 0
    || allowedPorts.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)
    || allowedCapabilities.length === 0
    || allowedCapabilities.some((capability) => !capability.match(/^[a-z][a-z0-9_.-]+$/))
    || !Number.isFinite(requestsPerSecond) || requestsPerSecond <= 0
    || !Number.isInteger(maximumTotalRequests) || maximumTotalRequests < 1
    || !Number.isInteger(maximumResponseBytes) || maximumResponseBytes < 1
    || !rationale || rationale.length > 500
  ) throw new Error("NORMALIZATION_REVIEW_INVALID");
  return { assetType, target, ...(assetType === "wildcard_domain" ? { includeApex: input.includeApex === "true" } : {}), ...(denyBoundary ? { denyBoundary } : {}), allowedPaths, deniedPaths, allowedPorts, allowedCapabilities, requestsPerSecond, maximumTotalRequests, maximumResponseBytes, rationale };
}

export function reviewedSourceBundle(
  sources: Json[],
  sourceIds: string[],
  conflictNote: string
): SourceBundleReview {
  if (sourceIds.length === 0 || new Set(sourceIds).size !== sourceIds.length) {
    throw new Error("SOURCE_BUNDLE_INVALID");
  }
  const reviewed = sourceIds.map((sourceId) => reviewedSource(sources, sourceId));
  if (reviewed.some((source) =>
    !(source.authority in authorityPrecedence)
    || typeof source.reference !== "string"
    || !source.reference.trim()
    || (source.effective_at != null && !Number.isFinite(Date.parse(source.effective_at)))
  )) throw new Error("SOURCE_BUNDLE_INVALID");
  const ordered = [...reviewed].sort((left, right) => {
    const authority = (authorityPrecedence[left.authority] ?? 99) - (authorityPrecedence[right.authority] ?? 99);
    return authority || Date.parse(right.effective_at ?? right.retrieved_at) - Date.parse(left.effective_at ?? left.retrieved_at) || left.id.localeCompare(right.id);
  });
  const references = new Map<string, Set<string>>();
  for (const source of ordered) {
    const hashes = references.get(source.reference) ?? new Set<string>();
    hashes.add(source.content_hash);
    references.set(source.reference, hashes);
  }
  const conflicts = [...references.entries()]
    .filter(([, hashes]) => hashes.size > 1)
    .map(([reference]) => reference)
    .sort();
  const note = conflictNote.trim();
  if (conflicts.length > 0 && (!note || note.length > 500)) {
    throw new Error("SOURCE_CONFLICT_REVIEW_REQUIRED");
  }
  return {
    sources: ordered,
    primary: ordered[0],
    conflicts,
    normalizationWarnings: conflicts.length > 0
      ? [`Conflicting immutable versions require restrictive review: ${note}`]
      : []
  };
}

export function reviewedEngagement(engagements: Json[], engagementId: string, programId: string) {
  const matches = engagements.filter((engagement) => engagement.id === engagementId);
  const engagement = matches[0];
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (matches.length !== 1 || !engagement || !uuid.test(engagement.id) || engagement.program_id !== programId || !["draft", "approved", "active", "paused", "expired", "revoked"].includes(engagement.status) || !Number.isFinite(Date.parse(engagement.effective_from)) || !Number.isFinite(Date.parse(engagement.expires_at)) || Date.parse(engagement.effective_from) >= Date.parse(engagement.expires_at)) throw new Error("ENGAGEMENT_REVIEW_INVALID");
  return engagement;
}

export function encodeBytesBase64(bytes: Uint8Array) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 16_384) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 16_384));
  }
  return btoa(binary);
}

export function sourceFileMediaType(filename: string) {
  const extension = filename.toLowerCase().split(".").pop();
  const mediaTypes: Record<string, string> = {
    txt: "text/plain", md: "text/markdown", markdown: "text/markdown",
    htm: "text/html", html: "text/html", json: "application/json", pdf: "application/pdf"
  };
  if (!extension || !mediaTypes[extension]) throw new Error("SOURCE_MEDIA_TYPE_INVALID");
  return mediaTypes[extension];
}

export async function prepareSourceImport(
  mode: SourceMode,
  authority: string,
  effectiveAt: string,
  sourceVersion: string,
  text: string,
  url: string,
  file: File | null
): Promise<SourceImport> {
  const normalizedEffectiveAt = effectiveAt ? new Date(effectiveAt) : null;
  if (normalizedEffectiveAt && !Number.isFinite(normalizedEffectiveAt.getTime())) throw new Error("SOURCE_EFFECTIVE_AT_INVALID");
  const provenance = {
    effectiveAt: normalizedEffectiveAt?.toISOString() ?? null,
    sourceVersion: sourceVersion.trim() || null
  };
  if (provenance.sourceVersion && provenance.sourceVersion.length > 128) throw new Error("SOURCE_VERSION_INVALID");
  if (mode === "file") {
    if (!file) throw new Error("SOURCE_FILE_REQUIRED");
    if (file.size > maxSourceBytes) throw new Error("SOURCE_TOO_LARGE");
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes.byteLength > maxSourceBytes) throw new Error("SOURCE_TOO_LARGE");
    return { mode, authority, ...provenance, filename: file.name, mediaType: sourceFileMediaType(file.name), contentBase64: encodeBytesBase64(bytes) };
  }
  if (mode === "url") return { mode, authority, ...provenance, url };
  return { mode, authority, ...provenance, content: text };
}

export function IntakeWorkspace({
  connected, program, engagements, selectedEngagement, sources, selectedSources, state, error, submit, selectEngagement, selectBundle, refresh
}: {
  connected: boolean; program: Json | null; engagements: Json[]; selectedEngagement: Json | null; sources: Json[]; selectedSources: Json[];
  state: IntakeState; error: string; submit: (source: SourceImport) => Promise<void>;
  selectEngagement: (engagement: Json) => void;
  selectBundle: (review: SourceBundleReview, normalization: NormalizationReview) => void;
  refresh: () => Promise<void>;
}) {
  const [mode, setMode] = useState<SourceMode>("pasted_text");
  const [authority, setAuthority] = useState("contract");
  const [effectiveAt, setEffectiveAt] = useState("");
  const [sourceVersion, setSourceVersion] = useState("");
  const [text, setText] = useState("Synthetic authorization for HTTPS GET requests to example.test/api.");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [preparationError, setPreparationError] = useState("");
  const [reviewIds, setReviewIds] = useState<string[]>(selectedSources.map((item) => item.id));
  const [conflictNote, setConflictNote] = useState("");
  const [reviewError, setReviewError] = useState("");
  const [target, setTarget] = useState("example.test");
  const [assetType, setAssetType] = useState<NormalizationReview["assetType"]>("domain");
  const [includeApex, setIncludeApex] = useState(false);
  const [includeDenyBoundary, setIncludeDenyBoundary] = useState(false);
  const [denyAssetType, setDenyAssetType] = useState<AssetType>("domain");
  const [denyTarget, setDenyTarget] = useState("");
  const [denyIncludeApex, setDenyIncludeApex] = useState(false);
  const [allowedPaths, setAllowedPaths] = useState("/api");
  const [deniedPaths, setDeniedPaths] = useState("/api/admin");
  const [allowedPorts, setAllowedPorts] = useState("443");
  const [allowedCapabilities, setAllowedCapabilities] = useState("network.http.get");
  const [requestsPerSecond, setRequestsPerSecond] = useState("1");
  const [maximumTotalRequests, setMaximumTotalRequests] = useState("50");
  const [maximumResponseBytes, setMaximumResponseBytes] = useState("100000");
  const [normalizationRationale, setNormalizationRationale] = useState("Restrictive values transcribed from the reviewed sources.");
  const selectedSourceIds = selectedSources.map((item) => item.id).join("|");

  useEffect(() => {
    setReviewIds(selectedSourceIds ? selectedSourceIds.split("|") : []);
  }, [selectedSourceIds]);

  async function importSource(event: FormEvent) {
    event.preventDefault();
    setPreparationError("");
    try {
      await submit(await prepareSourceImport(mode, authority, effectiveAt, sourceVersion, text, url, file));
    } catch (cause) {
      setPreparationError(cause instanceof Error ? cause.message : "SOURCE_PREPARATION_FAILED");
    }
  }

  function reviewBundle() {
    setReviewError("");
    try {
      selectBundle(
        reviewedSourceBundle(sources, reviewIds, conflictNote),
        reviewedNormalization({ assetType, target, includeApex: String(includeApex), denyAssetType: includeDenyBoundary ? denyAssetType : "", denyTarget: includeDenyBoundary ? denyTarget : "", denyIncludeApex: String(denyIncludeApex), allowedPaths, deniedPaths, allowedPorts, allowedCapabilities, requestsPerSecond, maximumTotalRequests, maximumResponseBytes, rationale: normalizationRationale })
      );
    } catch (cause) {
      setReviewError(cause instanceof Error ? cause.message : "SOURCE_BUNDLE_INVALID");
    }
  }

  return (
    <section className="panel intake-workspace">
      <h2><span>2</span> Intake</h2>
      <p className="hint">Selected program: {program ? `${program.name} · ${program.id}` : "None — select a program first"}</p>
      <form onSubmit={(event) => void importSource(event)} aria-busy={state === "loading"}>
        <fieldset disabled={!connected || !program || state === "loading"}>
          <legend>Supervised source import</legend>
          <div className="mode-row" role="group" aria-label="Source type">
            {(["pasted_text", "file", "url"] as SourceMode[]).map((item) => (
              <button type="button" key={item} className={mode === item ? "selected" : ""} onClick={() => { setMode(item); setPreparationError(""); }}>
                {item === "pasted_text" ? "Paste text" : item === "file" ? "Choose file" : "Acquire URL"}
              </button>
            ))}
          </div>
          <label>Source authority<select value={authority} onChange={(event) => setAuthority(event.target.value)}>
            <option value="contract">Contract</option><option value="program_staff">Program staff</option>
            <option value="program_page">Program page</option><option value="platform_rule">Platform rule</option>
            <option value="internal_note">Internal note</option>
          </select></label>
          <label>Effective from (optional)<input type="datetime-local" value={effectiveAt} onChange={(event) => setEffectiveAt(event.target.value)} /></label>
          <label>Source version (optional)<input maxLength={128} value={sourceVersion} onChange={(event) => setSourceVersion(event.target.value)} /></label>
          {mode === "pasted_text" && <label>Authoritative text<textarea rows={4} value={text} onChange={(event) => setText(event.target.value)} /></label>}
          {mode === "file" && <label>Local source file (maximum 2 MiB)<input type="file" accept=".txt,.md,.markdown,.htm,.html,.json,.pdf,text/plain,text/markdown,text/html,application/json,application/pdf" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label>}
          {mode === "url" && <label>Public HTTP(S) source URL<input type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://program.example/rules" /></label>}
          <button type="submit">{state === "loading" ? "Importing…" : "Review and import source"}</button>
        </fieldset>
      </form>
      {preparationError && <p className="result bad" role="alert">Import denied: {preparationError}</p>}
      <p className={`intake-state ${state}`} role="status">
        {state === "empty" && "No sources imported."}{state === "ready" && `${sources.length} immutable source${sources.length === 1 ? "" : "s"} available.`}
        {state === "loading" && "Import in progress. No background retries will occur."}{state === "denied" && `Import denied: ${error}`}
        {state === "degraded" && "Source intake unavailable until the authenticated core recovers."}{state === "error" && `Import failed safely: ${error}`}
      </p>
      <div className="panel-heading"><strong>Engagement history</strong><span className="hint">Select the exact validity window for source review.</span></div>
      {engagements.length === 0 ? <p className="hint">No durable engagement is available yet.</p> : <ol className="source-list">{engagements.map((item) => <li key={item.id} className={selectedEngagement?.id === item.id ? "selected" : ""}><div><strong>{item.status}</strong><span>{item.effective_from} → {item.expires_at}</span><code>{item.id}</code></div><button type="button" onClick={() => selectEngagement(reviewedEngagement(engagements, item.id, program?.id ?? ""))} aria-pressed={selectedEngagement?.id === item.id}>{selectedEngagement?.id === item.id ? "Selected" : "Review engagement"}</button></li>)}</ol>}
      <div className="panel-heading"><strong>Source history</strong><button type="button" onClick={() => void refresh()} disabled={!connected || !program || state === "loading"}>Refresh</button></div>
      <p className="hint">Choose every immutable source used by the draft. Contract and authorized clarification take precedence; conflicting versions remain blocked for restrictive review.</p>
      {sources.length === 0 ? <p className="hint">The history is empty.</p> : <ol className="source-list">{sources.map((item) => <li key={item.id} className={reviewIds.includes(item.id) ? "selected" : ""}><div><strong>{item.source_kind} · {item.authority}</strong><span>{item.reference}</span><span>Retrieved {item.retrieved_at}{item.effective_at ? ` · effective ${item.effective_at}` : " · no separate effective date"}</span><code>{item.content_hash.slice(0, 16)}…</code></div><label className="source-choice"><input type="checkbox" checked={reviewIds.includes(item.id)} onChange={(event) => setReviewIds((current) => event.target.checked ? [...current, item.id] : current.filter((id) => id !== item.id))} /> Include</label></li>)}</ol>}
      {reviewIds.length > 1 && <label>Conflict review note (required only when one reference has different hashes)<textarea maxLength={500} value={conflictNote} onChange={(event) => setConflictNote(event.target.value)} placeholder="Record the restrictive interpretation and clarification still required." /></label>}
      <fieldset disabled={reviewIds.length === 0}>
        <legend>Structured normalization review</legend>
        <p className="hint">Transcribe exact restrictive values from the reviewed sources. The core canonicalizes and validates this draft again.</p>
        <label>Asset type<select value={assetType} onChange={(event) => { setAssetType(event.target.value as NormalizationReview["assetType"]); setTarget(""); }}><option value="domain">Domain</option><option value="wildcard_domain">Wildcard domain</option><option value="url">URL</option><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option><option value="cidr">CIDR</option></select></label>
        <label>Exact asset value<input value={target} onChange={(event) => setTarget(event.target.value)} placeholder={assetType === "wildcard_domain" ? "*.example.test" : assetType === "url" ? "https://example.test/api" : assetType === "cidr" ? "192.0.2.0/24" : "example.test"} /></label>
        {assetType === "wildcard_domain" && <label className="source-choice"><input type="checkbox" checked={includeApex} onChange={(event) => setIncludeApex(event.target.checked)} /> Explicitly include the apex domain</label>}
        <label className="source-choice"><input type="checkbox" checked={includeDenyBoundary} onChange={(event) => setIncludeDenyBoundary(event.target.checked)} /> Add an explicit out-of-scope boundary</label>
        {includeDenyBoundary && <div className="boundary-review"><label>Deny asset type<select value={denyAssetType} onChange={(event) => { setDenyAssetType(event.target.value as AssetType); setDenyTarget(""); }}><option value="domain">Domain</option><option value="wildcard_domain">Wildcard domain</option><option value="url">URL</option><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option><option value="cidr">CIDR</option></select></label><label>Exact denied asset value<input value={denyTarget} onChange={(event) => setDenyTarget(event.target.value)} /></label>{denyAssetType === "wildcard_domain" && <label className="source-choice"><input type="checkbox" checked={denyIncludeApex} onChange={(event) => setDenyIncludeApex(event.target.checked)} /> Deny the wildcard apex too</label>}</div>}
        <label>Allowed paths (comma-separated)<input value={allowedPaths} onChange={(event) => setAllowedPaths(event.target.value)} /></label>
        <label>Denied paths (comma-separated)<input value={deniedPaths} onChange={(event) => setDeniedPaths(event.target.value)} /></label>
        <label>Allowed ports (comma-separated)<input value={allowedPorts} onChange={(event) => setAllowedPorts(event.target.value)} /></label>
        <label>Allowed capabilities (comma-separated)<input value={allowedCapabilities} onChange={(event) => setAllowedCapabilities(event.target.value)} /></label>
        <label>Requests per second<input type="number" min="0.001" step="0.001" value={requestsPerSecond} onChange={(event) => setRequestsPerSecond(event.target.value)} /></label>
        <label>Maximum total requests<input type="number" min="1" value={maximumTotalRequests} onChange={(event) => setMaximumTotalRequests(event.target.value)} /></label>
        <label>Maximum response bytes<input type="number" min="1" value={maximumResponseBytes} onChange={(event) => setMaximumResponseBytes(event.target.value)} /></label>
        <label>Review rationale<textarea maxLength={500} value={normalizationRationale} onChange={(event) => setNormalizationRationale(event.target.value)} /></label>
      </fieldset>
      <button type="button" onClick={reviewBundle} disabled={reviewIds.length === 0}>Use reviewed source bundle</button>
      {reviewError && <p className="result bad" role="alert">Review denied: {reviewError}</p>}
      {selectedSources.length > 0 && <dl className="hash"><dt>Reviewed immutable sources</dt><dd>{selectedSources.map((item) => item.id).join(", ")}</dd><dt>Primary authority</dt><dd>{selectedSources[0].authority}</dd><dt>SHA-256 provenance</dt><dd>{selectedSources.map((item) => item.content_hash).join(", ")}</dd></dl>}
    </section>
  );
}
