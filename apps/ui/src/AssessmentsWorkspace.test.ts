import { describe, expect, it } from "vitest";
import { allowedWorkflowTransitions, parseTaskInputRefs, workflowCreateRequest, workflowPath, workflowTaskCancelPath, workflowTaskRequest, workflowTasksPath, workflowTransitionRequest } from "./AssessmentsWorkspace";

describe("supervised Assessments workspace", () => {
  it("routes through exact workflow coordination endpoints", () => {
    expect(workflowPath()).toBe("/workflows");
    expect(workflowPath("10000000-0000-4000-8000-000000000001")).toBe("/workflows/10000000-0000-4000-8000-000000000001");
    expect(workflowPath()).not.toMatch(/execute|grant|dispatch/);
  });
  it("binds creation to the exact engagement and stable retry key", () => {
    expect(workflowCreateRequest("engagement-a", "assessment-ui-stable-key")).toEqual({ engagement_id: "engagement-a", idempotency_key: "assessment-ui-stable-key" });
  });
  it("uses only contract-defined lifecycle transitions", () => {
    expect(allowedWorkflowTransitions("planned")).toEqual(["ready", "cancelled"]);
    expect(allowedWorkflowTransitions("running")).toEqual(["paused", "completed", "cancelled"]);
    expect(allowedWorkflowTransitions("completed")).toEqual([]);
  });
  it("version-fences transitions and rejects invalid UI edges", () => {
    expect(workflowTransitionRequest({ status: "ready", version: 3 }, "running")).toEqual({ target_status: "running", expected_version: 3 });
    expect(() => workflowTransitionRequest({ status: "planned", version: 1 }, "completed")).toThrow("WORKFLOW_TRANSITION_INVALID");
  });
  it("routes task coordination without claim, lease, dispatch, or execution paths", () => {
    expect(workflowTasksPath("workflow-a")).toBe("/workflows/workflow-a/tasks");
    expect(workflowTaskCancelPath("task-a")).toBe("/workflow-tasks/task-a/cancel");
    expect(`${workflowTasksPath("workflow-a")}${workflowTaskCancelPath("task-a")}`).not.toMatch(/claim|lease|dispatch|execute/);
  });
  it("parses exact unique UUID input references", () => {
    const first = "10000000-0000-4000-8000-000000000001"; const second = "20000000-0000-4000-8000-000000000002";
    expect(parseTaskInputRefs(`${first}\n ${second} `)).toEqual([first, second]);
    expect(() => parseTaskInputRefs(`${first}\n${first}`)).toThrow("WORKFLOW_TASK_INPUT_REFS_INVALID");
    expect(() => parseTaskInputRefs("not-a-uuid")).toThrow("WORKFLOW_TASK_INPUT_REFS_INVALID");
  });
  it("binds a task request to kind, retry key, refs, and parent", () => {
    expect(workflowTaskRequest("evidence_capture", "workflow-task-ui-stable", ["ref-a"], " parent-a ")).toEqual({ task_kind: "evidence_capture", idempotency_key: "workflow-task-ui-stable", input_refs: ["ref-a"], parent_task_id: "parent-a" });
  });
});
