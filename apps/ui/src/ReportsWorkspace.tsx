import { isTauri } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { useState } from "react";

import type { CoreConnection } from "./App";
import { coreRequest } from "./App";

type Json = Record<string, any>;
type ReportKind = "findings" | "no_findings";
type ReportFormat = "markdown" | "html" | "json" | "pdf";
type CoverageOutcome = "tested_no_findings" | "finding_identified" | "blocked" | "not_tested";
type CoverageRule = { ruleId: string; label: string; capability?: string; applicableAssetRuleIds?: string[] };
type CoveragePolicySelection = { assetRules: CoverageRule[]; capabilityRules: CoverageRule[] };

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function parseReportIds(value: string, maximum: number) {
  const ids = value.split(",").map((item) => item.trim()).filter(Boolean);
  if (!ids.length || ids.length > maximum || new Set(ids).size !== ids.length) {
    throw new Error("REPORT_SELECTION_INVALID");
  }
  if (ids.some((item) => !uuid.test(item))) throw new Error("REPORT_SELECTION_INVALID");
  return ids;
}

export function reportDraftPath(kind: ReportKind, workflowId: string) {
  return kind === "findings"
    ? `/workflows/${workflowId}/report-drafts`
    : `/workflows/${workflowId}/no-findings-report-drafts`;
}

export function reportFileExportPath(reportId: string) {
  return `/report-drafts/${reportId}/file-exports`;
}

export function reportFileExportRequest(
  kind: ReportKind,
  format: ReportFormat,
  destinationDirectory: string,
  confirmed: boolean
) {
  return {
    report_kind: kind,
    format,
    destination_directory: destinationDirectory,
    confirm_restricted_export: confirmed
  };
}

export function coveragePath(workflowId: string) { return `/workflows/${workflowId}/coverage`; }

export function coverageRecordRequest(values: { assetRuleId: string; capabilityRuleId: string; capability: string; outcome: CoverageOutcome; startedAt: string; endedAt: string; evidenceIds: string; limitations: string; notes: string; idempotencyKey: string }) {
  const evidenceIds = values.evidenceIds.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
  const limitations = values.limitations.split("\n").map((item) => item.trim()).filter(Boolean);
  const startedAt = new Date(values.startedAt); const endedAt = new Date(values.endedAt);
  if (!uuid.test(values.assetRuleId.trim()) || !uuid.test(values.capabilityRuleId.trim()) || evidenceIds.some((item) => !uuid.test(item)) || new Set(evidenceIds).size !== evidenceIds.length || limitations.length === 0 || new Set(limitations).size !== limitations.length || !values.notes.trim() || !values.capability.match(/^[a-z][a-z0-9_.-]+$/) || !Number.isFinite(startedAt.getTime()) || !Number.isFinite(endedAt.getTime()) || startedAt >= endedAt || (["tested_no_findings", "finding_identified"].includes(values.outcome) && evidenceIds.length === 0)) throw new Error("COVERAGE_RECORD_INVALID");
  return { idempotency_key: values.idempotencyKey, asset_rule_id: values.assetRuleId.trim(), capability_rule_id: values.capabilityRuleId.trim(), capability: values.capability, outcome: values.outcome, started_at: startedAt.toISOString(), ended_at: endedAt.toISOString(), evidence_ids: evidenceIds, limitations, notes: values.notes.trim() };
}

export function verifiedCoverage(response: Json, workflowId: string) {
  if (!response.coverage_id || response.workflow_id !== workflowId || response.coverage_complete !== false || !["tested_no_findings", "finding_identified", "blocked", "not_tested"].includes(response.outcome) || !Array.isArray(response.evidence_ids) || !Array.isArray(response.limitations)) throw new Error("COVERAGE_RESPONSE_INVALID");
  return response;
}

export function selectCoverageId(current: string, coverageId: string) {
  if (!current.trim()) return coverageId;
  const selected = parseReportIds(current, 500);
  return selected.includes(coverageId) ? current : `${current},${coverageId}`;
}

export function coveragePolicySelection(response: Json, workflowId: string, policy: Json, policyState: string): CoveragePolicySelection {
  const workflow = response.workflow;
  const document = policy.policy;
  if (!workflow || workflow.workflow_id !== workflowId || workflow.execution_enabled !== false || !uuid.test(policy.id) || workflow.policy_bundle_id !== policy.id || policyState !== "active" || !document || !Array.isArray(document.asset_rules) || !Array.isArray(document.capability_rules)) throw new Error("COVERAGE_POLICY_BINDING_INVALID");
  const assetRules = document.asset_rules.filter((rule: Json) => rule.effect === "allow").map((rule: Json) => {
    if (!uuid.test(rule.rule_id) || typeof rule.asset_type !== "string" || !rule.matcher || typeof rule.matcher !== "object") throw new Error("COVERAGE_POLICY_RULE_INVALID");
    return { ruleId: rule.rule_id, label: `${rule.asset_type} · ${JSON.stringify(rule.matcher)}` };
  });
  const capabilityRules = document.capability_rules.filter((rule: Json) => ["allow", "conditional"].includes(rule.effect)).map((rule: Json) => {
    const applicable = rule.applicable_asset_rule_ids;
    if (!uuid.test(rule.rule_id) || typeof rule.capability !== "string" || !rule.capability.match(/^[a-z][a-z0-9_.-]+$/) || (applicable !== undefined && (!Array.isArray(applicable) || applicable.some((id: unknown) => typeof id !== "string" || !uuid.test(id))))) throw new Error("COVERAGE_POLICY_RULE_INVALID");
    return { ruleId: rule.rule_id, label: `${rule.capability} · ${rule.effect}`, capability: rule.capability, applicableAssetRuleIds: applicable };
  });
  if (!assetRules.length || !capabilityRules.length || new Set(assetRules.map((item: CoverageRule) => item.ruleId)).size !== assetRules.length || new Set(capabilityRules.map((item: CoverageRule) => item.ruleId)).size !== capabilityRules.length) throw new Error("COVERAGE_POLICY_RULE_INVALID");
  return { assetRules, capabilityRules };
}

export function ReportsWorkspace({ connection, policy, policyState }: { connection: CoreConnection | null; policy: Json | null; policyState: string }) {
  const [workflowId, setWorkflowId] = useState("");
  const [kind, setKind] = useState<ReportKind>("findings");
  const [title, setTitle] = useState("Supervised assessment report");
  const [selectedIds, setSelectedIds] = useState("");
  const [draft, setDraft] = useState<Json | null>(null);
  const [approval, setApproval] = useState<Json | null>(null);
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [exportFormat, setExportFormat] = useState<ReportFormat>("markdown");
  const [exportDirectory, setExportDirectory] = useState("");
  const [exportConfirmed, setExportConfirmed] = useState(false);
  const [receipt, setReceipt] = useState<Json | null>(null);
  const [coverage, setCoverage] = useState<Json[]>([]);
  const [coverageRules, setCoverageRules] = useState<CoveragePolicySelection | null>(null);
  const [assetRuleId, setAssetRuleId] = useState("");
  const [capabilityRuleId, setCapabilityRuleId] = useState("");
  const [capability, setCapability] = useState("");
  const [coverageOutcome, setCoverageOutcome] = useState<CoverageOutcome>("tested_no_findings");
  const [coverageStartedAt, setCoverageStartedAt] = useState("");
  const [coverageEndedAt, setCoverageEndedAt] = useState("");
  const [coverageEvidenceIds, setCoverageEvidenceIds] = useState("");
  const [coverageLimitations, setCoverageLimitations] = useState("");
  const [coverageNotes, setCoverageNotes] = useState("");
  const [coverageKey, setCoverageKey] = useState(() => `coverage-ui-${crypto.randomUUID()}`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function createDraft() {
    if (!connection) return;
    setBusy(true);
    setError("");
    setDraft(null);
    setApproval(null);
    setReceipt(null);
    try {
      const ids = parseReportIds(selectedIds, kind === "findings" ? 100 : 500);
      const body = {
        idempotency_key: `report-ui-${crypto.randomUUID()}`,
        title: title.trim(),
        template: "generic",
        ...(kind === "findings" ? { finding_ids: ids } : { coverage_ids: ids })
      };
      setDraft(await coreRequest(connection, reportDraftPath(kind, workflowId.trim()), body));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "REPORT_REQUEST_FAILED");
    } finally {
      setBusy(false);
    }
  }

  async function refreshCoverage() {
    if (!connection || !workflowId.trim()) return;
    const result = await coreRequest(connection, coveragePath(workflowId.trim()));
    if (!Array.isArray(result.coverage)) throw new Error("COVERAGE_RESPONSE_INVALID");
    setCoverage(result.coverage.map((item: Json) => verifiedCoverage(item, workflowId.trim())));
  }

  async function loadCoverageRules() {
    if (!connection || !policy || !workflowId.trim()) return;
    setBusy(true); setError(""); setCoverageRules(null); setAssetRuleId(""); setCapabilityRuleId(""); setCapability("");
    try { setCoverageRules(coveragePolicySelection(await coreRequest(connection, `/workflows/${workflowId.trim()}`), workflowId.trim(), policy, policyState)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "COVERAGE_POLICY_REQUEST_FAILED"); }
    finally { setBusy(false); }
  }

  async function recordCoverage() {
    if (!connection || !workflowId.trim()) return;
    setBusy(true); setError("");
    try {
      const recorded = verifiedCoverage(await coreRequest(connection, coveragePath(workflowId.trim()), coverageRecordRequest({ assetRuleId, capabilityRuleId, capability, outcome: coverageOutcome, startedAt: coverageStartedAt, endedAt: coverageEndedAt, evidenceIds: coverageEvidenceIds, limitations: coverageLimitations, notes: coverageNotes, idempotencyKey: coverageKey })), workflowId.trim());
      await refreshCoverage(); setSelectedIds(recorded.coverage_id); setCoverageKey(`coverage-ui-${crypto.randomUUID()}`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "COVERAGE_REQUEST_FAILED"); }
    finally { setBusy(false); }
  }

  async function chooseExportDirectory() {
    setError("");
    try {
      const selected = await open({ directory: true, multiple: false, title: "Choose report export folder" });
      if (typeof selected === "string") {
        setExportDirectory(selected);
        setReceipt(null);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "REPORT_EXPORT_DIRECTORY_FAILED");
    }
  }

  async function exportFile() {
    if (!connection || !draft || !approval?.export_ready) return;
    setBusy(true);
    setError("");
    try {
      setReceipt(await coreRequest(
        connection,
        reportFileExportPath(draft.report_id),
        reportFileExportRequest(kind, exportFormat, exportDirectory, exportConfirmed)
      ));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "REPORT_FILE_EXPORT_FAILED");
    } finally {
      setBusy(false);
    }
  }

  async function approveExport() {
    if (!connection || !draft) return;
    setBusy(true);
    setError("");
    try {
      setApproval(await coreRequest(connection, `/report-drafts/${draft.report_id}/export-approval`, {
        report_kind: kind,
        expected_status: "draft",
        reason: reason.trim(),
        confirm_export_ready: confirmed
      }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "REPORT_APPROVAL_FAILED");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel wide reports-workspace" aria-busy={busy}>
      <div className="panel-heading">
        <h2><span>8</span> Reports</h2>
        <strong className={receipt ? "verified" : approval?.export_ready ? "verified" : "hint"}>
          {receipt ? "Export complete" : approval?.export_ready ? "Export-ready" : "Draft review required"}
        </strong>
      </div>
      <p className="hint">
        Create, approve, and save one restricted immutable artifact. Nothing is uploaded or submitted.
      </p>
      <div className="report-form-grid">
        <label>
          Assessment workflow ID
          <input value={workflowId} onChange={(event) => { setWorkflowId(event.target.value); setCoverageRules(null); setAssetRuleId(""); setCapabilityRuleId(""); setCapability(""); }} />
        </label>
        <label>
          Report type
          <select value={kind} onChange={(event) => {
            setKind(event.target.value as ReportKind);
            setDraft(null);
            setApproval(null);
            setReceipt(null);
          }}>
            <option value="findings">Validated findings</option>
            <option value="no_findings">Coverage-aware No Findings</option>
          </select>
        </label>
        <label>
          Report title
          <input value={title} onChange={(event) => setTitle(event.target.value)} />
        </label>
        <label>
          {kind === "findings" ? "Report-ready finding IDs" : "Latest coverage record IDs"} (comma-separated)
          <textarea rows={3} value={selectedIds} onChange={(event) => setSelectedIds(event.target.value)} />
        </label>
      </div>
      {kind === "no_findings" && <div className="report-review">
        <h3>Record supervised coverage</h3>
        <p className="hint">Load the exact workflow policy before selecting an allowed asset/capability pair. Individual records never claim complete coverage.</p>
        <div className="button-row"><button onClick={loadCoverageRules} disabled={!connection || !policy || policyState !== "active" || busy || !workflowId.trim()}>Load authoritative policy rules</button>{coverageRules && <span className="result good">Policy {policy?.id} verified for this workflow.</span>}</div>
        <div className="report-form-grid">
          <label>Allowed asset rule<select value={assetRuleId} disabled={!coverageRules} onChange={(event) => { setAssetRuleId(event.target.value); setCapabilityRuleId(""); setCapability(""); }}><option value="">Select an exact rule</option>{coverageRules?.assetRules.map((rule) => <option key={rule.ruleId} value={rule.ruleId}>{rule.label}</option>)}</select></label>
          <label>Permitted capability rule<select value={capabilityRuleId} disabled={!coverageRules || !assetRuleId} onChange={(event) => { const selected = coverageRules?.capabilityRules.find((rule) => rule.ruleId === event.target.value); setCapabilityRuleId(event.target.value); setCapability(selected?.capability ?? ""); }}><option value="">Select an applicable rule</option>{coverageRules?.capabilityRules.filter((rule) => !rule.applicableAssetRuleIds || rule.applicableAssetRuleIds.includes(assetRuleId)).map((rule) => <option key={rule.ruleId} value={rule.ruleId}>{rule.label}</option>)}</select></label>
          <label>Capability<input value={capability} readOnly /></label>
          <label>Outcome<select value={coverageOutcome} onChange={(event) => setCoverageOutcome(event.target.value as CoverageOutcome)}><option value="tested_no_findings">Tested — no findings</option><option value="finding_identified">Finding identified</option><option value="blocked">Blocked</option><option value="not_tested">Not tested</option></select></label>
          <label>Started<input type="datetime-local" value={coverageStartedAt} onChange={(event) => setCoverageStartedAt(event.target.value)} /></label>
          <label>Ended<input type="datetime-local" value={coverageEndedAt} onChange={(event) => setCoverageEndedAt(event.target.value)} /></label>
        </div>
        <label>Evidence UUIDs (one per line; required for tested outcomes)<textarea rows={2} value={coverageEvidenceIds} onChange={(event) => setCoverageEvidenceIds(event.target.value)} /></label>
        <label>Limitations (one per line; at least one required)<textarea rows={2} value={coverageLimitations} onChange={(event) => setCoverageLimitations(event.target.value)} /></label>
        <label>Human notes<textarea rows={2} value={coverageNotes} onChange={(event) => setCoverageNotes(event.target.value)} /></label>
        <div className="button-row"><button onClick={recordCoverage} disabled={!connection || !coverageRules || !assetRuleId || !capabilityRuleId || policyState !== "active" || busy || !workflowId.trim()}>Record immutable coverage</button><button onClick={() => void refreshCoverage().catch((cause) => setError(cause instanceof Error ? cause.message : "COVERAGE_REQUEST_FAILED"))} disabled={!connection || busy || !workflowId.trim()}>Load coverage history</button></div>
        {coverage.length > 0 && <ol className="workflow-task-list">{coverage.map((item) => <li key={item.coverage_id}><div><strong>{item.capability} · {item.outcome}</strong><span>{item.started_at} → {item.ended_at} · individual completeness: no</span><code>{item.coverage_id}</code></div><button onClick={() => setSelectedIds((current) => selectCoverageId(current, item.coverage_id))}>Select for draft</button></li>)}</ol>}
      </div>}
      <button onClick={createDraft} disabled={!connection || busy || !workflowId.trim() || !title.trim()}>
        {busy ? "Working…" : "Create immutable draft"}
      </button>
      {error && <p className="result bad" role="alert">Denied safely: {error}</p>}
      {draft && (
        <div className="report-review">
          <div className="result good">
            <strong>{draft.title}</strong>
            <p>{draft.status} · {draft.classification} · policy {draft.policy_bundle_id}</p>
          </div>
          <table>
            <caption>Immutable artifact integrity</caption>
            <thead><tr><th>Format</th><th>Size</th><th>SHA-256</th><th>Custody</th></tr></thead>
            <tbody>{draft.artifacts.map((artifact: Json) => (
              <tr key={artifact.format}>
                <td>{artifact.format}</td>
                <td>{artifact.size_bytes} bytes</td>
                <td><code>{artifact.sha256.slice(0, 16)}…</code></td>
                <td>Restricted local artifact</td>
              </tr>
            ))}</tbody>
          </table>
          <label>
            Human review reason
            <textarea rows={3} value={reason} onChange={(event) => setReason(event.target.value)} />
          </label>
          <label className="confirmation-check">
            <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
            I reviewed this exact draft and all four displayed artifact digests.
          </label>
          <button onClick={approveExport} disabled={busy || !confirmed || !reason.trim() || Boolean(approval)}>
            Explicitly approve export-ready status
          </button>
          <p className="hint">Approval does not download, save, upload, or submit the report.</p>
          {approval?.export_ready && (
            <div className="report-export">
              <h3>Save approved artifact</h3>
              <div className="report-form-grid">
                <label>
                  Format
                  <select value={exportFormat} onChange={(event) => {
                    setExportFormat(event.target.value as ReportFormat);
                    setReceipt(null);
                  }}>
                    <option value="markdown">Markdown</option>
                    <option value="html">HTML</option>
                    <option value="json">JSON</option>
                    <option value="pdf">PDF</option>
                  </select>
                </label>
                <label>
                  Destination folder
                  <span className="directory-picker">
                    <input value={exportDirectory} readOnly placeholder="No folder selected" />
                    <button type="button" onClick={chooseExportDirectory} disabled={busy || !isTauri()}>
                      Choose folder
                    </button>
                  </span>
                </label>
              </div>
              <label className="confirmation-check">
                <input type="checkbox" checked={exportConfirmed} onChange={(event) => setExportConfirmed(event.target.checked)} />
                I understand this saves a restricted plaintext file under local OS custody.
              </label>
              <button onClick={exportFile} disabled={busy || !exportDirectory || !exportConfirmed || Boolean(receipt)}>
                Save approved {exportFormat} artifact
              </button>
              {receipt && (
                <div className="result good">
                  <strong>Saved {receipt.filename}</strong>
                  <p>{receipt.size_bytes} bytes · SHA-256 <code>{receipt.artifact_sha256.slice(0, 16)}…</code></p>
                  <p>Restricted local file · no submission performed</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
