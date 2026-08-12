import { describe, expect, it } from "vitest";
import { allowedWorkflowTransitions, workflowCreateRequest, workflowPath, workflowTransitionRequest } from "./AssessmentsWorkspace";

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
});
