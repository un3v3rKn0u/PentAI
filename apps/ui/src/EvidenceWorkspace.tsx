import { useState } from "react";

import type { CoreConnection } from "./App";
import { coreRequest, encodeBytesBase64 } from "./App";

type Json = Record<string, any>;
type RedactionReason = "secret" | "personal_data" | "irrelevant" | "operator_selected";

const maxEvidenceBytes = 2 * 1024 * 1024;
const redactionReasons = new Set<RedactionReason>([
  "secret", "personal_data", "irrelevant", "operator_selected"
]);

export function evidenceOriginalPath(workflowId: string) {
  return `/workflows/${workflowId}/evidence/originals`;
}

export function evidenceMetadataPath(evidenceId: string) {
  return `/evidence/${evidenceId}/metadata`;
}

export function evidenceRedactionPath(evidenceId: string) {
  return `/evidence/${evidenceId}/redactions`;
}

export function evidencePreviewPath(derivativeId: string) {
  return `/evidence/derivatives/${derivativeId}/preview`;
}

export function parseRedactionSpans(value: string) {
  const spans = value.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
    const [startText, endText, reasonText, ...extra] = line.split(":");
    const start = Number(startText);
    const end = Number(endText);
    if (
      extra.length || !Number.isSafeInteger(start) || !Number.isSafeInteger(end)
      || start < 0 || end <= start || !redactionReasons.has(reasonText as RedactionReason)
    ) {
      throw new Error("EVIDENCE_REDACTION_SELECTION_INVALID");
    }
    return { start, end, reason: reasonText as RedactionReason };
  });
  if (!spans.length || spans.length > 256) {
    throw new Error("EVIDENCE_REDACTION_SELECTION_INVALID");
  }
  if (spans.some((span, index) => index > 0 && span.start < spans[index - 1].end)) {
    throw new Error("EVIDENCE_REDACTION_SELECTION_INVALID");
  }
  return spans;
}

export function EvidenceWorkspace({ connection }: { connection: CoreConnection | null }) {
  const [workflowId, setWorkflowId] = useState("");
  const [kind, setKind] = useState("note");
  const [classification, setClassification] = useState("restricted");
  const [note, setNote] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [executionTraceId, setExecutionTraceId] = useState("");
  const [evidenceId, setEvidenceId] = useState("");
  const [metadata, setMetadata] = useState<Json | null>(null);
  const [redactionText, setRedactionText] = useState("");
  const [derivativeClassification, setDerivativeClassification] = useState("internal");
  const [classificationConfirmed, setClassificationConfirmed] = useState(false);
  const [derivative, setDerivative] = useState<Json | null>(null);
  const [preview, setPreview] = useState<Json | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function captureOriginal() {
    if (!connection) return;
    setBusy(true);
    setError("");
    try {
      let bytes: Uint8Array;
      let mediaType: string;
      if (kind === "note") {
        bytes = new TextEncoder().encode(note);
        mediaType = "text/plain";
      } else {
        if (!file || file.size < 1 || file.size > maxEvidenceBytes) {
          throw new Error("EVIDENCE_FILE_SIZE_INVALID");
        }
        bytes = new Uint8Array(await file.arrayBuffer());
        mediaType = file.type || "application/octet-stream";
      }
      if (bytes.length < 1 || bytes.length > maxEvidenceBytes) {
        throw new Error("EVIDENCE_SIZE_INVALID");
      }
      const captured = await coreRequest(
        connection,
        evidenceOriginalPath(workflowId.trim()),
        {
          evidence_kind: kind,
          media_type: mediaType,
          classification,
          idempotency_key: `evidence-ui-${crypto.randomUUID()}`,
          content_base64: encodeBytesBase64(bytes),
          execution_trace_id: executionTraceId.trim() || null
        }
      );
      setEvidenceId(captured.evidence_id);
      setMetadata({ evidence: captured });
      setDerivative(null);
      setPreview(null);
      setNote("");
      setFile(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "EVIDENCE_CAPTURE_FAILED");
    } finally {
      setBusy(false);
    }
  }

  async function loadMetadata() {
    if (!connection || !evidenceId.trim()) return;
    setBusy(true);
    setError("");
    try {
      setMetadata(await coreRequest(connection, evidenceMetadataPath(evidenceId.trim())));
      setDerivative(null);
      setPreview(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "EVIDENCE_METADATA_FAILED");
    } finally {
      setBusy(false);
    }
  }

  async function createRedaction() {
    if (!connection || !metadata?.evidence) return;
    setBusy(true);
    setError("");
    try {
      const created = await coreRequest(
        connection,
        evidenceRedactionPath(metadata.evidence.evidence_id),
        {
          redactions: parseRedactionSpans(redactionText),
          classification: derivativeClassification,
          confirm_classification: classificationConfirmed,
          idempotency_key: `redaction-ui-${crypto.randomUUID()}`
        }
      );
      setDerivative(created);
      setPreview(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "EVIDENCE_REDACTION_FAILED");
    } finally {
      setBusy(false);
    }
  }

  async function previewRedaction() {
    if (!connection || !derivative) return;
    setBusy(true);
    setError("");
    try {
      const result = await coreRequest(connection, evidencePreviewPath(derivative.derivative_id));
      if (
        result.render_mode !== "plain_text" || result.media_type !== "text/plain"
        || result.active_content_disabled !== true
      ) {
        throw new Error("EVIDENCE_PREVIEW_UNSAFE");
      }
      setPreview(result);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "EVIDENCE_PREVIEW_FAILED");
    } finally {
      setBusy(false);
    }
  }

  const supportsRedaction = metadata?.evidence?.media_type?.startsWith("text/")
    || ["application/json", "application/xml", "application/xhtml+xml"].includes(
      metadata?.evidence?.media_type
    );

  return (
    <section className="panel wide evidence-workspace" aria-busy={busy}>
      <div className="panel-heading">
        <h2><span>6</span> Evidence</h2>
        <strong className="hint">Encrypted immutable custody</strong>
      </div>
      <p className="hint">Capture up to 2 MiB for one exact workflow. Originals are never previewed; only server-generated text redactions can be shown as inactive text.</p>
      <div className="evidence-form-grid">
        <label>Assessment workflow ID<input value={workflowId} onChange={(event) => setWorkflowId(event.target.value)} /></label>
        <label>Evidence kind<select value={kind} onChange={(event) => { setKind(event.target.value); setFile(null); }}>
          <option value="note">Note</option><option value="http_metadata">HTTP metadata</option>
          <option value="response_excerpt">Response excerpt</option><option value="screenshot">Screenshot</option>
          <option value="imported_file">Imported file</option><option value="tool_output">Tool output</option>
        </select></label>
        <label>Original classification<select value={classification} onChange={(event) => setClassification(event.target.value)}><option value="restricted">Restricted</option><option value="internal">Internal</option></select></label>
        <label>Optional matching execution trace UUID<input value={executionTraceId} onChange={(event) => setExecutionTraceId(event.target.value)} /></label>
      </div>
      {kind === "note" ? (
        <label>Evidence note<textarea rows={5} value={note} onChange={(event) => setNote(event.target.value)} /></label>
      ) : (
        <label>Local evidence file (maximum 2 MiB)<input type="file" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></label>
      )}
      <button onClick={captureOriginal} disabled={!connection || busy || !workflowId.trim() || (kind === "note" ? !note : !file)}>Capture encrypted original</button>
      {error && <p className="result bad" role="alert">Denied safely: {error}</p>}
      <div className="evidence-lookup">
        <label>Evidence UUID<input value={evidenceId} onChange={(event) => { setEvidenceId(event.target.value); setMetadata(null); setDerivative(null); setPreview(null); }} /></label>
        <button onClick={loadMetadata} disabled={!connection || busy || !evidenceId.trim()}>Load custody metadata</button>
      </div>
      {metadata?.evidence && (
        <div className="evidence-review">
          <div className="result good">
            <strong>{metadata.evidence.evidence_kind} · {metadata.evidence.classification}</strong>
            <p>{metadata.evidence.size_bytes} bytes · SHA-256 <code>{metadata.evidence.sha256.slice(0, 16)}…</code></p>
            <p>Policy {metadata.evidence.policy_bundle_id}</p>
          </div>
          {supportsRedaction ? <>
            <h3>Create text redaction</h3>
            <p className="hint">Enter one Unicode-codepoint range per line as start:end:reason. Reasons: secret, personal_data, irrelevant, operator_selected.</p>
            <label>Redaction ranges<textarea rows={4} value={redactionText} onChange={(event) => setRedactionText(event.target.value)} placeholder="12:28:secret" /></label>
            <label>Derivative classification<select value={derivativeClassification} onChange={(event) => setDerivativeClassification(event.target.value)}><option value="internal">Internal</option><option value="public">Public</option></select></label>
            <label className="confirmation-check"><input type="checkbox" checked={classificationConfirmed} onChange={(event) => setClassificationConfirmed(event.target.checked)} />I confirm the derivative classification after these exact redactions.</label>
            <button onClick={createRedaction} disabled={busy || !redactionText.trim() || !classificationConfirmed}>Create immutable redaction</button>
          </> : <p className="hint">This binary media type cannot be previewed or redacted in this workspace.</p>}
          {derivative && <button onClick={previewRedaction} disabled={busy}>Preview derivative as inactive text</button>}
          {preview && (
            <div className="inactive-preview">
              <strong>Inactive plain-text preview · {preview.classification}</strong>
              <pre>{preview.content}</pre>
              <p className="hint">Active content disabled · {preview.truncated ? "preview truncated" : "complete bounded preview"}</p>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
