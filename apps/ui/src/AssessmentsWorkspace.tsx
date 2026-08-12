import { useState } from "react";

type Json = Record<string, any>;

const transitions: Record<string, string[]> = {
  planned: ["ready", "cancelled"],
  ready: ["running", "cancelled"],
  running: ["paused", "completed", "cancelled"],
  paused: ["running", "cancelled"]
};

export function workflowPath(workflowId?: string) {
  return workflowId ? `/workflows/${workflowId}` : "/workflows";
}

export function workflowCreateRequest(engagementId: string, idempotencyKey: string) {
  return { engagement_id: engagementId, idempotency_key: idempotencyKey };
}

export function workflowTransitionRequest(workflow: Json, targetStatus: string) {
  if (!transitions[workflow.status]?.includes(targetStatus)) {
    throw new Error("WORKFLOW_TRANSITION_INVALID");
  }
  return { target_status: targetStatus, expected_version: workflow.version };
}

export function allowedWorkflowTransitions(status: string) {
  return transitions[status] ?? [];
}

export function AssessmentsWorkspace({
  connected,
  engagement,
  policy,
  policyState,
  request,
  auditRefresh
}: {
  connected: boolean;
  engagement: Json | null;
  policy: Json | null;
  policyState: string;
  request: (path: string, body?: Json) => Promise<Json>;
  auditRefresh: () => void;
}) {
  const [workflowId, setWorkflowId] = useState("");
  const [workflow, setWorkflow] = useState<Json | null>(null);
  const [idempotencyKey, setIdempotencyKey] = useState(() => `assessment-ui-${crypto.randomUUID()}`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function perform(operation: () => Promise<Json>) {
    setBusy(true);
    setError("");
    try {
      const result = await operation();
      setWorkflow(result);
      setWorkflowId(result.workflow_id);
      auditRefresh();
      return true;
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "WORKFLOW_REQUEST_FAILED");
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function createWorkflow() {
    if (!engagement) return;
    if (await perform(() => request(workflowPath(), workflowCreateRequest(engagement.id, idempotencyKey)))) {
      setIdempotencyKey(`assessment-ui-${crypto.randomUUID()}`);
    }
  }

  async function loadWorkflow() {
    if (!workflowId.trim()) return;
    await perform(() => request(workflowPath(workflowId.trim())));
  }

  async function transition(targetStatus: string) {
    if (!workflow) return;
    await perform(() => request(
      `${workflowPath(workflow.workflow_id)}/transition`,
      workflowTransitionRequest(workflow, targetStatus)
    ));
  }

  const exactAuthority = Boolean(
    engagement && workflow?.engagement_id === engagement.id
    && policy?.id && policyState === "active"
    && policy.id === workflow?.policy_bundle_id
  );

  return (
    <section className="panel assessments-workspace" aria-busy={busy}>
      <div className="panel-heading"><h2><span>3</span> Assessments</h2><strong className="hint">Coordination only · execution disabled</strong></div>
      <p className="hint">Create a planned workflow only after an active policy exists, or load one exact workflow UUID. Status never grants network or worker authority.</p>
      <button onClick={createWorkflow} disabled={!connected || busy || !engagement || !policy || policyState !== "active"}>Create planned assessment</button>
      <div className="assessment-lookup">
        <label>Assessment workflow UUID<input value={workflowId} onChange={(event) => { setWorkflowId(event.target.value); setWorkflow(null); setError(""); }} /></label>
        <button onClick={loadWorkflow} disabled={!connected || busy || !workflowId.trim()}>Load exact assessment</button>
      </div>
      {error && <p className="result bad" role="alert">Assessment denied safely: {error}</p>}
      {workflow && (
        <div className="assessment-review">
          <dl className="assessment-identity">
            <dt>Status and version</dt><dd>{workflow.status} · v{workflow.version}</dd>
            <dt>Workflow ID</dt><dd>{workflow.workflow_id}</dd>
            <dt>Engagement ID</dt><dd>{workflow.engagement_id}</dd>
            <dt>Policy bundle ID</dt><dd>{workflow.policy_bundle_id}</dd>
            <dt>Execution enabled</dt><dd>{workflow.execution_enabled === false ? "No" : "Invalid contract response"}</dd>
          </dl>
          {!exactAuthority && <p className="result bad">The loaded workflow is not bound to the active policy displayed in this workspace. Transitions remain unavailable.</p>}
          {workflow.execution_enabled !== false && <p className="result bad" role="alert">Unexpected execution authority; do not use this workflow.</p>}
          <div className="button-row">
            {allowedWorkflowTransitions(workflow.status).map((target) => (
              <button
                key={target}
                className={target === "cancelled" ? "danger" : ""}
                onClick={() => void transition(target)}
                disabled={busy || !exactAuthority || workflow.execution_enabled !== false}
              >{target === "running" ? workflow.status === "paused" ? "Resume under human supervision" : "Start under human supervision" : `Mark ${target}`}</button>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
