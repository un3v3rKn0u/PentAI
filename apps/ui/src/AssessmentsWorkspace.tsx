import { useState } from "react";

type Json = Record<string, any>;
type TaskKind = "manual_checkpoint" | "supervised_action" | "evidence_capture" | "report_draft";

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

export function workflowTasksPath(workflowId: string) { return `/workflows/${workflowId}/tasks`; }
export function workflowTaskCancelPath(taskId: string) { return `/workflow-tasks/${taskId}/cancel`; }

export function parseTaskInputRefs(value: string) {
  const refs = value.split("\n").map((item) => item.trim()).filter(Boolean);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (refs.length > 64 || refs.some((item) => !uuid.test(item)) || new Set(refs).size !== refs.length) {
    throw new Error("WORKFLOW_TASK_INPUT_REFS_INVALID");
  }
  return refs;
}

export function workflowTaskRequest(taskKind: TaskKind, idempotencyKey: string, inputRefs: string[], parentTaskId: string) {
  return { task_kind: taskKind, idempotency_key: idempotencyKey, input_refs: inputRefs, parent_task_id: parentTaskId.trim() || null };
}

export function workflowSnapshot(response: Json, expectedWorkflowId: string) {
  const workflow = response.workflow;
  const tasks = response.tasks;
  const lifecycles = response.task_lifecycles;
  const checkpoints = response.checkpoints;
  if (
    !workflow || workflow.workflow_id !== expectedWorkflowId || workflow.execution_enabled !== false
    || !Array.isArray(tasks) || !Array.isArray(lifecycles) || !Array.isArray(checkpoints)
    || tasks.some((task) => task.workflow_id !== expectedWorkflowId || task.dispatch_enabled !== false || task.external_effect_enabled !== false)
    || lifecycles.some((lifecycle) => lifecycle.dispatch_enabled !== false || lifecycle.external_effect_enabled !== false)
    || new Set(tasks.map((task) => task.task_id)).size !== tasks.length
    || new Set(lifecycles.map((lifecycle) => lifecycle.task_id)).size !== lifecycles.length
    || tasks.some((task) => !lifecycles.some((lifecycle) => lifecycle.task_id === task.task_id))
    || lifecycles.some((lifecycle) => !tasks.some((task) => task.task_id === lifecycle.task_id))
    || checkpoints.some((checkpoint) => !tasks.some((task) => task.task_id === checkpoint.task_id))
  ) throw new Error("WORKFLOW_SNAPSHOT_INVALID");
  const lifecycleByTask = new Map(lifecycles.map((item) => [item.task_id, item]));
  return {
    workflow,
    tasks: tasks.map((task) => ({ ...task, lifecycle: lifecycleByTask.get(task.task_id), checkpoint_count: checkpoints.filter((item) => item.task_id === task.task_id).length }))
  };
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
  const [tasks, setTasks] = useState<Json[]>([]);
  const [taskKind, setTaskKind] = useState<TaskKind>("manual_checkpoint");
  const [taskInputRefs, setTaskInputRefs] = useState("");
  const [parentTaskId, setParentTaskId] = useState("");
  const [taskIdempotencyKey, setTaskIdempotencyKey] = useState(() => `workflow-task-ui-${crypto.randomUUID()}`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function perform(operation: () => Promise<Json>) {
    setBusy(true);
    setError("");
    try {
      const result = await operation();
      if (workflow?.workflow_id && workflow.workflow_id !== result.workflow_id) setTasks([]);
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

  async function readSnapshot(expectedWorkflowId: string) {
    const snapshot = workflowSnapshot(await request(workflowPath(expectedWorkflowId)), expectedWorkflowId);
    setWorkflow(snapshot.workflow); setTasks(snapshot.tasks); setWorkflowId(expectedWorkflowId);
  }

  async function loadWorkflow() {
    if (!workflowId.trim()) return;
    setBusy(true); setError("");
    try {
      const expectedWorkflowId = workflowId.trim();
      await readSnapshot(expectedWorkflowId); auditRefresh();
    } catch (cause) { setWorkflow(null); setTasks([]); setError(cause instanceof Error ? cause.message : "WORKFLOW_REQUEST_FAILED"); }
    finally { setBusy(false); }
  }

  async function transition(targetStatus: string) {
    if (!workflow) return;
    await perform(() => request(
      `${workflowPath(workflow.workflow_id)}/transition`,
      workflowTransitionRequest(workflow, targetStatus)
    ));
  }

  async function enqueueTask() {
    if (!workflow) return;
    setBusy(true); setError("");
    try {
      const created = await request(workflowTasksPath(workflow.workflow_id), workflowTaskRequest(taskKind, taskIdempotencyKey, parseTaskInputRefs(taskInputRefs), parentTaskId));
      if (created.workflow_id !== workflow.workflow_id || created.dispatch_enabled !== false || created.external_effect_enabled !== false) throw new Error("WORKFLOW_TASK_AUTHORITY_INVALID");
      await readSnapshot(workflow.workflow_id);
      setTaskIdempotencyKey(`workflow-task-ui-${crypto.randomUUID()}`); setTaskInputRefs(""); setParentTaskId(""); auditRefresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "WORKFLOW_TASK_REQUEST_FAILED"); }
    finally { setBusy(false); }
  }

  async function cancelTask(taskId: string) {
    setBusy(true); setError("");
    try {
      const cancelled = await request(workflowTaskCancelPath(taskId), {});
      if (
        cancelled.task_id !== taskId || cancelled.workflow_id !== workflow?.workflow_id
        || cancelled.state !== "cancelled" || cancelled.dispatch_enabled !== false
        || cancelled.external_effect_enabled !== false
      ) throw new Error("WORKFLOW_TASK_CANCEL_INVALID");
      await readSnapshot(cancelled.workflow_id); auditRefresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "WORKFLOW_TASK_CANCEL_FAILED"); }
    finally { setBusy(false); }
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
        <label>Assessment workflow UUID<input value={workflowId} onChange={(event) => { setWorkflowId(event.target.value); setWorkflow(null); setTasks([]); setError(""); }} /></label>
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
          <div className="assessment-tasks">
            <h3>Durable task history</h3>
            <p className="hint">Loading an exact assessment reconstructs its core-authoritative task lifecycle and checkpoints. Lease credentials, dispatch, and external-effect controls are never exposed.</p>
            <div className="task-form-grid">
              <label>Task kind<select value={taskKind} onChange={(event) => setTaskKind(event.target.value as TaskKind)}>
                <option value="manual_checkpoint">Manual checkpoint</option><option value="supervised_action">Supervised action</option><option value="evidence_capture">Evidence capture</option><option value="report_draft">Report draft</option>
              </select></label>
              <label>Optional parent task UUID<input value={parentTaskId} onChange={(event) => setParentTaskId(event.target.value)} /></label>
            </div>
            <label>Input reference UUIDs (one per line, maximum 64)<textarea rows={3} value={taskInputRefs} onChange={(event) => setTaskInputRefs(event.target.value)} /></label>
            <button onClick={enqueueTask} disabled={busy || !exactAuthority || workflow.execution_enabled !== false || !["ready", "running"].includes(workflow.status)}>Queue non-dispatching task</button>
            {tasks.length === 0 && <p className="hint">No durable tasks are recorded for this workflow.</p>}
            {tasks.length > 0 && <ol className="workflow-task-list">{tasks.map((task) => <li key={task.task_id}><div><strong>{task.task_kind}</strong><span>{task.lifecycle?.state ?? task.state} · attempt {task.lifecycle?.attempt_count ?? 0}/{task.lifecycle?.max_attempts ?? 0} · {task.checkpoint_count} checkpoints · no dispatch · no external effects</span>{task.lifecycle?.last_error_code && <span>Last error: {task.lifecycle.last_error_code}</span>}<code>{task.task_id}</code></div><button className="danger" onClick={() => void cancelTask(task.task_id)} disabled={busy || task.lifecycle?.state !== "queued"}>Cancel queued task</button></li>)}</ol>}
          </div>
        </div>
      )}
    </section>
  );
}
