import { isTauri } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { useState } from "react";

import type { CoreConnection } from "./App";
import { coreRequest } from "./App";

type Json = Record<string, any>;
type ReportKind = "findings" | "no_findings";
type ReportFormat = "markdown" | "html" | "json" | "pdf";

export function parseReportIds(value: string, maximum: number) {
  const ids = value.split(",").map((item) => item.trim()).filter(Boolean);
  if (!ids.length || ids.length > maximum || new Set(ids).size !== ids.length) {
    throw new Error("REPORT_SELECTION_INVALID");
  }
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
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

export function ReportsWorkspace({ connection }: { connection: CoreConnection | null }) {
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
          <input value={workflowId} onChange={(event) => setWorkflowId(event.target.value)} />
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
