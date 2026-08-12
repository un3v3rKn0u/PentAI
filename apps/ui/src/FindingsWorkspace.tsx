import { useState } from "react";

import type { CoreConnection } from "./App";
import { coreRequest } from "./App";

type Json = Record<string, any>;

const transitions: Record<string, string[]> = {
  candidate: ["scope_reviewed", "rejected"],
  scope_reviewed: ["duplicate_reviewed", "rejected"],
  duplicate_reviewed: ["validated", "rejected"],
  validated: ["report_ready", "duplicate_reviewed"],
  report_ready: ["closed", "validated"]
};

export function parseFindingIds(value: string, maximum: number) {
  const ids = value.split(",").map((item) => item.trim()).filter(Boolean);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!ids.length || ids.length > maximum || new Set(ids).size !== ids.length || ids.some((id) => !uuid.test(id))) {
    throw new Error("FINDING_SELECTION_INVALID");
  }
  return ids;
}

export function findingNextStates(state: string) {
  return transitions[state] ?? [];
}

export function findingCollectionPath(workflowId: string) {
  return `/workflows/${workflowId}/findings`;
}

export function findingTransitionPath(findingId: string) {
  return `/findings/${findingId}/transition`;
}

export function findingTransitionRequest(
  finding: Json,
  targetState: string,
  reason: string,
  validationStatus: string,
  duplicateStatus: string,
  duplicateOf: string
) {
  return {
    target_state: targetState,
    expected_version: finding.version,
    reason: reason.trim(),
    validation_status: validationStatus,
    duplicate_status: duplicateStatus,
    duplicate_of: duplicateStatus === "duplicate" ? duplicateOf.trim() : null
  };
}

export function FindingsWorkspace({ connection }: { connection: CoreConnection | null }) {
  const [workflowId, setWorkflowId] = useState("");
  const [findings, setFindings] = useState<Json[]>([]);
  const [selected, setSelected] = useState<Json | null>(null);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("critical");
  const [vector, setVector] = useState("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  const [score, setScore] = useState("9.8");
  const [cwe, setCwe] = useState("CWE-79");
  const [confidence, setConfidence] = useState("80");
  const [assetIds, setAssetIds] = useState("");
  const [evidenceIds, setEvidenceIds] = useState("");
  const [reproduction, setReproduction] = useState("");
  const [impact, setImpact] = useState("");
  const [remediation, setRemediation] = useState("");
  const [references, setReferences] = useState("");
  const [targetState, setTargetState] = useState("");
  const [reason, setReason] = useState("");
  const [validationStatus, setValidationStatus] = useState("unverified");
  const [duplicateStatus, setDuplicateStatus] = useState("pending");
  const [duplicateOf, setDuplicateOf] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function refresh() {
    if (!connection || !workflowId.trim()) return;
    setBusy(true);
    setError("");
    try {
      const result = await coreRequest(connection, findingCollectionPath(workflowId.trim()));
      setFindings(result.findings);
      if (selected) {
        setSelected(result.findings.find((item: Json) => item.finding_id === selected.finding_id) ?? null);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "FINDING_LIST_FAILED");
    } finally {
      setBusy(false);
    }
  }

  async function createFinding() {
    if (!connection) return;
    setBusy(true);
    setError("");
    try {
      const created = await coreRequest(connection, findingCollectionPath(workflowId.trim()), {
        idempotency_key: `finding-ui-${crypto.randomUUID()}`,
        title: title.trim(),
        severity,
        cvss_vector: vector.trim(),
        cvss_score: Number(score),
        cwe: cwe.trim(),
        confidence: Number(confidence),
        affected_asset_rule_ids: parseFindingIds(assetIds, 64),
        evidence_ids: parseFindingIds(evidenceIds, 128),
        reproduction: reproduction.trim(),
        impact: impact.trim(),
        remediation: remediation.trim(),
        references: references.split("\n").map((item) => item.trim()).filter(Boolean)
      });
      setFindings((current) => [...current, created]);
      selectFinding(created);
      setTitle("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "FINDING_CREATE_FAILED");
    } finally {
      setBusy(false);
    }
  }

  function selectFinding(finding: Json) {
    setSelected(finding);
    setTargetState(findingNextStates(finding.state)[0] ?? "");
    setValidationStatus(finding.validation_status);
    setDuplicateStatus(finding.duplicate_status);
    setDuplicateOf(finding.duplicate_of ?? "");
    setReason("");
    setError("");
  }

  async function transitionFinding() {
    if (!connection || !selected || !targetState) return;
    setBusy(true);
    setError("");
    try {
      const updated = await coreRequest(
        connection,
        findingTransitionPath(selected.finding_id),
        findingTransitionRequest(
          selected, targetState, reason, validationStatus, duplicateStatus, duplicateOf
        )
      );
      setFindings((current) => current.map((item) => item.finding_id === updated.finding_id ? updated : item));
      selectFinding(updated);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "FINDING_TRANSITION_FAILED");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel wide findings-workspace" aria-busy={busy}>
      <div className="panel-heading">
        <h2><span>6</span> Findings</h2>
        <strong className="hint">Human-supervised lifecycle</strong>
      </div>
      <p className="hint">Create a candidate from exact policy asset and evidence UUIDs. The core recomputes CVSS and denies invalid scope, provenance, or lifecycle changes.</p>
      <div className="finding-toolbar">
        <label>Assessment workflow ID<input value={workflowId} onChange={(event) => {
          setWorkflowId(event.target.value);
          setFindings([]);
          setSelected(null);
        }} /></label>
        <button onClick={refresh} disabled={!connection || busy || !workflowId.trim()}>Load findings</button>
      </div>
      {error && <p className="result bad" role="alert">Denied safely: {error}</p>}
      <details>
        <summary>Create finding candidate</summary>
        <div className="finding-form-grid">
          <label>Title<input value={title} onChange={(event) => setTitle(event.target.value)} /></label>
          <label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}>{["informational", "low", "medium", "high", "critical"].map((item) => <option key={item}>{item}</option>)}</select></label>
          <label>CVSS 3.1 vector<input value={vector} onChange={(event) => setVector(event.target.value)} /></label>
          <label>CVSS score<input type="number" min="0" max="10" step="0.1" value={score} onChange={(event) => setScore(event.target.value)} /></label>
          <label>CWE<input value={cwe} onChange={(event) => setCwe(event.target.value)} /></label>
          <label>Confidence (0–100)<input type="number" min="0" max="100" value={confidence} onChange={(event) => setConfidence(event.target.value)} /></label>
          <label>Allowed asset rule UUIDs (comma-separated)<textarea rows={2} value={assetIds} onChange={(event) => setAssetIds(event.target.value)} /></label>
          <label>Available evidence UUIDs (comma-separated)<textarea rows={2} value={evidenceIds} onChange={(event) => setEvidenceIds(event.target.value)} /></label>
          <label>Reproduction<textarea rows={4} value={reproduction} onChange={(event) => setReproduction(event.target.value)} /></label>
          <label>Impact<textarea rows={4} value={impact} onChange={(event) => setImpact(event.target.value)} /></label>
          <label>Remediation<textarea rows={4} value={remediation} onChange={(event) => setRemediation(event.target.value)} /></label>
          <label>HTTPS or URN references (one per line)<textarea rows={4} value={references} onChange={(event) => setReferences(event.target.value)} /></label>
        </div>
        <button onClick={createFinding} disabled={!connection || busy || !workflowId.trim() || !title.trim() || !reproduction.trim() || !impact.trim() || !remediation.trim()}>Create immutable candidate</button>
      </details>
      <div className="findings-layout">
        <div>
          <h3>Workflow findings</h3>
          {findings.length === 0 ? <p className="hint">No findings loaded.</p> : (
            <ol className="finding-list">{findings.map((finding) => (
              <li key={finding.finding_id}>
                <button className={selected?.finding_id === finding.finding_id ? "selected" : ""} onClick={() => selectFinding(finding)}>
                  <strong>{finding.title}</strong>
                  <span>{finding.severity} · {finding.state} · v{finding.version}</span>
                  <code>{finding.finding_id}</code>
                </button>
              </li>
            ))}</ol>
          )}
        </div>
        {selected && (
          <div className="finding-review">
            <h3>Review selected finding</h3>
            <p>{selected.cwe} · CVSS {selected.cvss.base_score} · confidence {selected.confidence}%</p>
            <p className="hint">Expected version {selected.version}; stale transitions deny.</p>
            {findingNextStates(selected.state).length === 0 ? <p className="result good">Terminal state: {selected.state}</p> : <>
              <label>Next state<select value={targetState} onChange={(event) => setTargetState(event.target.value)}>{findingNextStates(selected.state).map((state) => <option key={state}>{state}</option>)}</select></label>
              <label>Duplicate review<select value={duplicateStatus} onChange={(event) => setDuplicateStatus(event.target.value)}><option value="pending">Pending</option><option value="clear">Clear</option><option value="duplicate">Duplicate</option></select></label>
              {duplicateStatus === "duplicate" && <label>Duplicate finding UUID<input value={duplicateOf} onChange={(event) => setDuplicateOf(event.target.value)} /></label>}
              <label>Validation review<select value={validationStatus} onChange={(event) => setValidationStatus(event.target.value)}><option value="unverified">Unverified</option><option value="confirmed">Confirmed</option><option value="not_reproduced">Not reproduced</option><option value="false_positive">False positive</option><option value="needs_retest">Needs retest</option></select></label>
              <label>Human transition reason<textarea rows={3} value={reason} onChange={(event) => setReason(event.target.value)} /></label>
              <button onClick={transitionFinding} disabled={busy || !reason.trim()}>Apply version-fenced transition</button>
            </>}
          </div>
        )}
      </div>
    </section>
  );
}
