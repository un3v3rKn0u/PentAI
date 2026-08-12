import { useState } from "react";

type Json = Record<string, any>;

export function policyApprovalRequest(decision: "approved" | "rejected", expiresAt: string, reason: string) {
  const normalizedReason = reason.trim();
  if (!normalizedReason || normalizedReason.length > 500) throw new Error("POLICY_APPROVAL_REASON_INVALID");
  if (!expiresAt || !Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= Date.now()) throw new Error("POLICY_APPROVAL_EXPIRY_INVALID");
  return { decision, expires_at: new Date(expiresAt).toISOString(), reason: normalizedReason };
}

export function policyRevocationRequest(reason: string) {
  const normalized = reason.trim();
  if (!normalized || normalized.length > 500) throw new Error("POLICY_REVOCATION_REASON_INVALID");
  return { reason: normalized };
}

export function PolicyWorkspace({
  connected, manifestText, setManifestText, manifest, manifestHistory, manifestDiff,
  policy, policyHistory, state, validate, compile, approve, activate, revoke
}: {
  connected: boolean; manifestText: string; setManifestText: (value: string) => void;
  manifest: Json | null; manifestHistory: Json[]; manifestDiff: Json | null;
  policy: Json | null; policyHistory: Json[]; state: string;
  validate: () => Promise<void>; compile: () => Promise<void>;
  approve: (request: Json) => Promise<void>; activate: () => Promise<void>;
  revoke: (request: Json) => Promise<void>;
}) {
  const [decision, setDecision] = useState<"approved" | "rejected">("approved");
  const [approvalReason, setApprovalReason] = useState("");
  const [approvalExpiry, setApprovalExpiry] = useState("");
  const [approved, setApproved] = useState(false);
  const [revocationReason, setRevocationReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function perform(operation: () => Promise<void>) {
    setBusy(true); setError("");
    try { await operation(); return true; }
    catch (cause) { setError(cause instanceof Error ? cause.message : "POLICY_REQUEST_FAILED"); return false; }
    finally { setBusy(false); }
  }

  async function submitApproval() {
    let request: Json;
    try { request = policyApprovalRequest(decision, approvalExpiry, approvalReason); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "POLICY_APPROVAL_INVALID"); return; }
    if (await perform(() => approve(request))) setApproved(decision === "approved");
  }

  async function submitRevocation() {
    let request: Json;
    try { request = policyRevocationRequest(revocationReason); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "POLICY_REVOCATION_INVALID"); return; }
    if (await perform(() => revoke(request))) { setApproved(false); setRevocationReason(""); }
  }

  return (
    <section className="panel policy-workspace" aria-busy={busy}>
      <div className="panel-heading"><h2><span>4</span> Policy lifecycle</h2><strong className={`state-pill ${state.replace(" ", "-")}`}>{state}</strong></div>
      <p className="hint">Validation, signed compilation, human approval, activation, and revocation remain separate explicit stages.</p>
      <label>Manifest v2 JSON<textarea className="editor" value={manifestText} onChange={(event) => { setManifestText(event.target.value); setApproved(false); }} placeholder="Import a source to create a provenance-linked draft." /></label>
      <div className="button-row">
        <button onClick={() => void perform(validate)} disabled={!connected || busy || !manifestText.trim()}>Validate and canonicalize</button>
        <button onClick={() => void perform(compile)} disabled={!connected || busy || !manifest?.valid}>Compile signed Policy IR v1</button>
      </div>
      {manifest && <div className={manifest.valid ? "result good" : "result bad"}><strong>{manifest.valid ? "Fully resolved" : "Activation blocked"}</strong><ul>{manifest.issues.length === 0 ? <li>Schema, semantics, provenance, validity, and scope passed.</li> : manifest.issues.map((issue: Json) => <li key={`${issue.path}:${issue.code}`}>{issue.code} — {issue.path}</li>)}</ul></div>}
      <div className="policy-history-grid">
        <div><strong>Immutable manifests · {manifestHistory.length}</strong>{manifestHistory.length === 0 ? <p className="hint">No versions saved.</p> : <ol className="source-list">{manifestHistory.map((item) => <li key={item.id}><strong>Version {item.version_number}</strong><span>{item.validation_status}</span><code>{item.content_hash.slice(0, 16)}…</code></li>)}</ol>}</div>
        <div><strong>Signed policies · {policyHistory.length}</strong>{policyHistory.length === 0 ? <p className="hint">No policies compiled.</p> : <ol className="source-list">{policyHistory.map((item) => <li key={item.id}><strong>{item.status}</strong><span>Compiler {item.compiler_version}</span><code>{item.content_hash.slice(0, 16)}…</code></li>)}</ol>}</div>
      </div>
      {manifestDiff && <div className="result"><strong>Changes from version {manifestDiff.from.version_number}</strong><p>{manifestDiff.changed_sections.length ? manifestDiff.changed_sections.join(", ") : "No authorization-bearing sections changed."}</p></div>}
      {policy && <><pre className="preview">{JSON.stringify(policy.policy, null, 2)}</pre><dl className="hash"><dt>Exact compiled policy SHA-256</dt><dd>{policy.content_hash}</dd></dl>
        <div className="policy-approval-grid">
          <label>Decision<select value={decision} onChange={(event) => { setDecision(event.target.value as "approved" | "rejected"); setApproved(false); }}><option value="approved">Approve exact policy</option><option value="rejected">Reject exact policy</option></select></label>
          <label>Approval expires at<input type="datetime-local" value={approvalExpiry} onChange={(event) => { setApprovalExpiry(event.target.value); setApproved(false); }} /></label>
        </div>
        <label>Approval reason (maximum 500 characters)<textarea maxLength={500} rows={3} value={approvalReason} onChange={(event) => { setApprovalReason(event.target.value); setApproved(false); }} /></label>
        <button onClick={() => void submitApproval()} disabled={busy || state === "active"}>Record typed human decision</button>
        <button onClick={() => void perform(activate)} disabled={busy || !approved || decision !== "approved" || state === "active"}>Activate exactly approved policy</button>
        {state === "active" && <><label>Revocation reason (maximum 500 characters)<textarea maxLength={500} rows={3} value={revocationReason} onChange={(event) => setRevocationReason(event.target.value)} /></label><button className="danger" onClick={() => void submitRevocation()} disabled={busy || !revocationReason.trim()}>Revoke active policy</button></>}
      </>}
      {error && <p className="result bad" role="alert">Policy action denied safely: {error}</p>}
    </section>
  );
}
