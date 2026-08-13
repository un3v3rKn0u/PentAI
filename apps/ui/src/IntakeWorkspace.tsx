import { FormEvent, useState } from "react";

type Json = Record<string, any>;
export type SourceMode = "pasted_text" | "file" | "url";
export type IntakeState = "empty" | "ready" | "loading" | "denied" | "degraded" | "error";
export type SourceImport =
  | { mode: "pasted_text"; authority: string; effectiveAt: string | null; sourceVersion: string | null; content: string }
  | { mode: "file"; authority: string; effectiveAt: string | null; sourceVersion: string | null; filename: string; mediaType: string; contentBase64: string }
  | { mode: "url"; authority: string; effectiveAt: string | null; sourceVersion: string | null; url: string };

const maxSourceBytes = 2 * 1024 * 1024;

export function reviewedSource(sources: Json[], sourceId: string) {
  const matches = sources.filter((source) => source.id === sourceId);
  const source = matches[0];
  if (matches.length !== 1 || !source || typeof source.content_hash !== "string" || !source.content_hash.match(/^[a-f0-9]{64}$/) || typeof source.authority !== "string" || typeof source.retrieved_at !== "string" || !Number.isFinite(Date.parse(source.retrieved_at))) throw new Error("SOURCE_REVIEW_INVALID");
  return source;
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
  connected, program, sources, selectedSource, state, error, submit, select, refresh
}: {
  connected: boolean; program: Json | null; sources: Json[]; selectedSource: Json | null;
  state: IntakeState; error: string; submit: (source: SourceImport) => Promise<void>;
  select: (source: Json) => void;
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

  async function importSource(event: FormEvent) {
    event.preventDefault();
    setPreparationError("");
    try {
      await submit(await prepareSourceImport(mode, authority, effectiveAt, sourceVersion, text, url, file));
    } catch (cause) {
      setPreparationError(cause instanceof Error ? cause.message : "SOURCE_PREPARATION_FAILED");
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
      <div className="panel-heading"><strong>Source history</strong><button type="button" onClick={() => void refresh()} disabled={!connected || !program || state === "loading"}>Refresh</button></div>
      {sources.length === 0 ? <p className="hint">The history is empty.</p> : <ol className="source-list">{sources.map((item) => <li key={item.id} className={selectedSource?.id === item.id ? "selected" : ""}><div><strong>{item.source_kind} · {item.authority}</strong><span>{item.reference}</span><span>Retrieved {item.retrieved_at}{item.effective_at ? ` · effective ${item.effective_at}` : " · no separate effective date"}</span><code>{item.content_hash.slice(0, 16)}…</code></div><button type="button" onClick={() => select(reviewedSource(sources, item.id))} aria-pressed={selectedSource?.id === item.id}>{selectedSource?.id === item.id ? "Selected" : "Review source"}</button></li>)}</ol>}
      {selectedSource && <dl className="hash"><dt>Selected source ID</dt><dd>{selectedSource.id}</dd><dt>Authority</dt><dd>{selectedSource.authority}</dd><dt>Source version</dt><dd>{selectedSource.source_version ?? "Not specified"}</dd><dt>SHA-256 provenance</dt><dd>{selectedSource.content_hash}</dd></dl>}
    </section>
  );
}
