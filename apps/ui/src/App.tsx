import { invoke, isTauri } from "@tauri-apps/api/core";
import { useEffect, useRef, useState } from "react";

import { ReportsWorkspace } from "./ReportsWorkspace";
import { FindingsWorkspace } from "./FindingsWorkspace";
import { EvidenceWorkspace } from "./EvidenceWorkspace";
import { auditPath, LogsWorkspace } from "./LogsWorkspace";
import { DashboardWorkspace } from "./DashboardWorkspace";
import { ProgramsWorkspace, programsPath } from "./ProgramsWorkspace";
import { IntakeWorkspace, type IntakeState, type SourceBundleReview, type SourceImport } from "./IntakeWorkspace";
import { AssessmentsWorkspace } from "./AssessmentsWorkspace";
import { PolicyWorkspace, reviewedManifestDiff, reviewedPolicy } from "./PolicyWorkspace";
import { NetworkProfilesWorkspace, type NetworkSetupState } from "./NetworkProfilesWorkspace";
import { AuthorizationWorkspace } from "./AuthorizationWorkspace";

type Json = Record<string, any>;
export type CoreConnection = {
  apiBaseUrl: string;
  credential: string;
};

type WorkflowState =
  | "draft"
  | "invalid"
  | "awaiting approval"
  | "active"
  | "paused"
  | "rejected"
  | "revoked"
  | "expired";

type SafetyState = "loading" | "active" | "paused" | "stopped" | "error";
export const phaseOneWorkspaces = [
  { id: "dashboard", label: "Dashboard" },
  { id: "programs", label: "Programs" },
  { id: "intake", label: "Intake" },
  { id: "assessments", label: "Assessments" },
  { id: "evidence", label: "Evidence" },
  { id: "findings", label: "Findings" },
  { id: "reports", label: "Reports" },
  { id: "logs", label: "Logs" }
] as const;
type WorkspaceId = typeof phaseOneWorkspaces[number]["id"];

export async function bootstrapCore(): Promise<CoreConnection> {
  if (isTauri()) {
    return invoke<CoreConnection>("core_bootstrap");
  }
  if (import.meta.env.DEV) {
    const apiBaseUrl = import.meta.env.VITE_PENTAI_CORE_URL;
    const credential = import.meta.env.VITE_PENTAI_LAUNCH_CREDENTIAL;
    if (apiBaseUrl && credential) {
      return { apiBaseUrl, credential };
    }
  }
  throw new Error("CORE_BOOTSTRAP_UNAVAILABLE");
}

function iso(hours: number) {
  return new Date(Date.now() + hours * 3_600_000).toISOString();
}

export async function coreRequest(connection: CoreConnection, path: string, body?: Json) {
  const response = await fetch(`${connection.apiBaseUrl}${path}`, {
    method: body ? "POST" : "GET",
    headers: {
      "Authorization": `Bearer ${connection.credential}`,
      ...(body ? { "Content-Type": "application/json" } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.detail?.code ?? "REQUEST_FAILED");
  }
  return result;
}


export function networkManifestSettings(networkProfile?: Json) {
  return {
    route_mode: "local_gateway",
    route_profile_id: networkProfile?.route_profile_id ?? "network-profile-required",
    registered_source_ipv4: networkProfile?.registered_source_ipv4 ?? [],
    registered_source_ipv6: networkProfile?.registered_source_ipv6 ?? [],
    ipv6_mode: networkProfile?.ipv6_mode ?? "disabled",
    dns_mode: networkProfile?.resolver_mode ?? "tunnel_resolver",
    ...(networkProfile?.resolver_mode === "approved_resolver"
      ? { approved_resolvers: networkProfile.resolver_addresses }
      : {}),
    pause_on_identity_change: true
  };
}

export function buildManifest(program: Json, engagement: Json, review: SourceBundleReview, networkProfile?: Json) {
  const provenance = review.sources.map((source) => ({ source_id: source.id, content_hash: source.content_hash }));
  return {
    schema_version: "2.0.0",
    engagement: {
      id: engagement.id,
      organization: "Synthetic local workspace",
      program_name: program.name,
      program_type: "pentest",
      status: "draft",
      effective_from: engagement.effective_from,
      expires_at: engagement.expires_at,
      timezone: "UTC"
    },
    sources: review.sources.map((source) => ({
      source_id: source.id,
      reference: source.reference,
      authority: source.authority,
      retrieved_at: source.retrieved_at,
      content_hash: source.content_hash,
      ...(source.effective_at ? { effective_at: source.effective_at } : {})
    })),
    field_provenance: Object.fromEntries([
      "/scope", "/techniques", "/operational_limits", "/network",
      "/data_handling", "/reporting", "/agent_controls"
    ].map((field) => [field, provenance])),
    scope: {
      assets: [{
        asset_id: crypto.randomUUID(),
        effect: "allow",
        type: "domain",
        canonical_value: "example.test",
        allowed_paths: ["/api"],
        denied_paths: ["/api/admin"],
        allowed_ports: [443],
        ownership_verified: true,
        source_reference: review.primary.id
      }],
      discovered_assets_default: "deny",
      redirects_outside_scope: "stop",
      third_party_services: "deny"
    },
    techniques: {
      allowed_capabilities: ["network.http.get"],
      denied_capabilities: [],
      conditional_capabilities: [],
      allowed_http_methods: ["GET"]
    },
    operational_limits: {
      requests_per_second: 1,
      per_host_requests_per_second: 1,
      burst_limit: 1,
      concurrent_connections: 1,
      maximum_runtime_minutes: 30,
      maximum_total_requests: 50,
      maximum_request_body_bytes: 0,
      maximum_response_bytes: 100000,
      stop_conditions: ["authorization changes"]
    },
    network: networkManifestSettings(networkProfile),
    data_handling: {
      real_user_data: "avoid_and_stop",
      retention_days: 7,
      approved_storage: "local_encrypted",
      remote_ai_max_classification: "none"
    },
    reporting: {
      submission_channel: "manual",
      submission_requires_human_approval: true,
      automatic_submission: false
    },
    agent_controls: {
      autonomy: "supervised_testing",
      maximum_test_depth: 1,
      maximum_runtime_minutes: 30,
      human_approval_required_for: ["policy_activation"]
    },
    approvals: {
      scope_reviewer: "local-user",
      rules_reviewer: "local-user",
      technical_controls_reviewer: "local-user",
      status: "pending"
    },
    unresolved_questions: [
      ...(!networkProfile ? ["Confirm an active network profile before policy activation."] : []),
      ...review.conflicts.map((reference) => `Resolve conflicting immutable source versions for ${reference}.`)
    ],
    ...(review.normalizationWarnings.length > 0
      ? { normalization_warnings: review.normalizationWarnings }
      : {})
  };
}

export function App() {
  const [activeWorkspace, setActiveWorkspace] = useState<WorkspaceId>("dashboard");
  const [connection, setConnection] = useState<CoreConnection | null>(null);
  const [bootstrapError, setBootstrapError] = useState("");
  const [programs, setPrograms] = useState<Json[]>([]);
  const [sources, setSources] = useState<Json[]>([]);
  const [engagements, setEngagements] = useState<Json[]>([]);
  const [intakeState, setIntakeState] = useState<IntakeState>("empty");
  const [sourceError, setSourceError] = useState("");
  const [manifestText, setManifestText] = useState("");
  const [program, setProgram] = useState<Json | null>(null);
  const [engagement, setEngagement] = useState<Json | null>(null);
  const [sourceReview, setSourceReview] = useState<SourceBundleReview | null>(null);
  const [manifest, setManifest] = useState<Json | null>(null);
  const [manifestHistory, setManifestHistory] = useState<Json[]>([]);
  const [manifestDiff, setManifestDiff] = useState<Json | null>(null);
  const [policy, setPolicy] = useState<Json | null>(null);
  const [policyHistory, setPolicyHistory] = useState<Json[]>([]);
  const [audit, setAudit] = useState<Json>({ events: [], verification: { valid: true } });
  const [state, setState] = useState<WorkflowState>("draft");
  const [safetyState, setSafetyState] = useState<SafetyState>("loading");
  const [safetyReason, setSafetyReason] = useState("Explicit supervised safety control");
  const [networkSetupState, setNetworkSetupState] = useState<NetworkSetupState>("empty");
  const [networkProposal, setNetworkProposal] = useState<Json | null>(null);
  const [networkSetupError, setNetworkSetupError] = useState("");
  const [networkProfiles, setNetworkProfiles] = useState<Json[]>([]);
  const [error, setError] = useState("");
  const selectedProgramId = useRef("");
  const selectedEngagementId = useRef("");

  const statusClass = state.replace(" ", "-");

  useEffect(() => {
    let active = true;
    bootstrapCore()
      .then((result) => {
        if (active) setConnection(result);
      })
      .catch((reason: unknown) => {
        if (active) {
          setBootstrapError(
            reason instanceof Error && reason.message === "AUTHENTICATION_REQUIRED"
              ? "CORE_AUTHENTICATION_FAILED"
              : "CORE_UNAVAILABLE"
          );
          setIntakeState("degraded");
        }
      });
    return () => {
      active = false;
    };
  }, []);

  async function request(path: string, body?: Json) {
    if (!connection) throw new Error("CORE_UNAVAILABLE");
    try {
      return await coreRequest(connection, path, body);
    } catch (reason) {
      if (reason instanceof Error && reason.message === "AUTHENTICATION_REQUIRED") {
        setBootstrapError("CORE_AUTHENTICATION_FAILED");
        setConnection(null);
      }
      throw reason;
    }
  }

  async function run(operation: () => Promise<void>) {
    setError("");
    try {
      await operation();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "REQUEST_FAILED");
    }
  }

  useEffect(() => {
    if (!connection) return;
    let active = true;
    coreRequest(connection, "/safety-state")
      .then((result) => {
        if (active) setSafetyState(result.status as SafetyState);
      })
      .catch(() => {
        if (active) setSafetyState("error");
      });
    coreRequest(connection, "/network-profiles")
      .then((result) => {
        if (!active) return;
        setNetworkProfiles(result.profiles);
        if (result.profiles.some((item: Json) => item.status === "active")) {
          setNetworkSetupState("active");
        }
      })
      .catch(() => {
        if (active) setNetworkSetupState("degraded");
      });
    coreRequest(connection, auditPath())
      .then((result) => {
        if (active) setAudit(result);
      })
      .catch(() => {
        if (active) setAudit({ events: [], verification: { valid: false, event_count: 0 } });
      });
    coreRequest(connection, programsPath())
      .then((result) => {
        if (active) setPrograms(result.programs);
      })
      .catch(() => {
        if (active) setPrograms([]);
      });
    return () => { active = false; };
  }, [connection]);

  async function changeGlobalSafety(status: "active" | "paused" | "stopped") {
    await run(async () => {
      const result = await request("/safety-state", { status, reason: safetyReason });
      setSafetyState(result.status);
      if (status !== "active" && engagement) setState("paused");
      await refreshAudit();
    });
  }

  async function discoverNetworkProfile() {
    setNetworkSetupState("loading");
    setNetworkSetupError("");
    try {
      const proposal = await request("/network-profile-proposal");
      setNetworkProposal(proposal);
      setNetworkSetupState("needs_confirmation");
    } catch (reason) {
      const code = reason instanceof Error ? reason.message : "REQUEST_FAILED";
      setNetworkProposal(null);
      setNetworkSetupError(code);
      setNetworkSetupState(
        code === "NETWORK_PROFILE_DISCOVERY_FAILED" || code === "CORE_UNAVAILABLE"
          ? "degraded"
          : "error"
      );
    }
  }

  async function refreshNetworkProfiles() {
    const result = await request("/network-profiles");
    setNetworkProfiles(result.profiles);
    const activeProfile = result.profiles.find((item: Json) => item.status === "active");
    if (activeProfile) setNetworkSetupState("active");
  }

  async function activateNetworkProfile(activationRequest: Json) {
    setNetworkSetupState("loading");
    setNetworkSetupError("");
    try {
      const activated = await request("/network-profiles/activate", activationRequest);
      await refreshNetworkProfiles();
      setNetworkProposal(null);
      if (program && engagement && sourceReview) {
        setManifestText(JSON.stringify(
          buildManifest(program, engagement, sourceReview, activated),
          null,
          2
        ));
        setManifest(null);
        setPolicy(null);
        setState("draft");
      }
      await refreshAudit();
    } catch (reason) {
      setNetworkSetupError(reason instanceof Error ? reason.message : "REQUEST_FAILED");
      setNetworkSetupState("error");
    }
  }

  async function revokeNetworkProfile(profileId: string, revocationRequest: Json) {
    setNetworkSetupState("loading");
    try {
      await request(`/network-profiles/${profileId}/revoke`, revocationRequest);
      await refreshNetworkProfiles();
      setNetworkSetupState("revoked");
      await refreshAudit();
    } catch (reason) {
      setNetworkSetupError(reason instanceof Error ? reason.message : "REQUEST_FAILED");
      setNetworkSetupState("error");
    }
  }

  async function changeAssessmentSafety(status: "active" | "paused") {
    if (!engagement) return;
    await run(async () => {
      await request(`/engagements/${engagement.id}/safety-state`, {
        status,
        reason: safetyReason
      });
      setState(status === "active" ? "active" : "paused");
      await refreshAudit();
    });
  }

  function selectProgram(selected: Json | null) {
    selectedProgramId.current = selected?.id ?? "";
    setProgram(selected);
    setSources([]);
    setEngagements([]);
    setSourceReview(null);
    setEngagement(null);
    selectedEngagementId.current = "";
    setManifest(null);
    setManifestHistory([]);
    setManifestDiff(null);
    setManifestText("");
    setPolicy(null);
    setPolicyHistory([]);
    setIntakeState("empty");
    setState("draft");
  }

  async function refreshPrograms() {
    const result = await request(programsPath());
    setPrograms(result.programs);
    if (program && !result.programs.some((item: Json) => item.id === program.id)) {
      selectProgram(null);
    }
  }

  async function createProgram(requested: Json) {
    const created = await request(programsPath(), requested);
    setPrograms((current) => [...current, created]);
    selectProgram(created);
    void run(refreshAudit);
  }

  async function refreshSources(programId = program?.id) {
    if (!programId) return;
    const result = await request(`/programs/${programId}/sources`);
    if (selectedProgramId.current !== programId) return;
    setSources(result.sources);
    setIntakeState(result.sources.length ? "ready" : "empty");
  }

  async function refreshEngagements(programId = program?.id) {
    if (!programId) return;
    const result = await request(`/programs/${programId}/engagements`);
    if (selectedProgramId.current !== programId || !Array.isArray(result.engagements)) return;
    setEngagements(result.engagements);
  }

  async function refreshPolicyHistory(engagementId: string) {
    const [manifests, policies] = await Promise.all([
      request(`/engagements/${engagementId}/manifests`),
      request(`/engagements/${engagementId}/policies`)
    ]);
    if (selectedEngagementId.current !== engagementId || !Array.isArray(manifests.manifests) || !Array.isArray(policies.policies)) return;
    setManifestHistory(manifests.manifests);
    setPolicyHistory(policies.policies);
  }

  async function importSource(submission: SourceImport) {
    if (!program) return;
    const programId = program.id;
    setSourceError("");
    setIntakeState("loading");
    try {
      let imported: Json;
      if (submission.mode === "file") {
        imported = await request("/sources/files", {
          program_id: programId,
          authority: submission.authority, filename: submission.filename,
          media_type: submission.mediaType, content_base64: submission.contentBase64,
          effective_at: submission.effectiveAt, source_version: submission.sourceVersion
        });
      } else if (submission.mode === "url") {
        imported = await request("/sources/urls", {
          program_id: programId, authority: submission.authority, url: submission.url,
          effective_at: submission.effectiveAt, source_version: submission.sourceVersion
        });
      } else {
        imported = await request("/sources", {
          program_id: programId, authority: submission.authority,
          reference: "pasted://local-supervised-intake",
          content: submission.content, effective_at: submission.effectiveAt,
          source_version: submission.sourceVersion
        });
      }
      if (selectedProgramId.current !== programId) return;
      const createdEngagement = engagement ?? await request("/engagements", {
          program_id: programId,
          effective_from: iso(-1),
          expires_at: iso(8),
          timezone: "UTC"
        });
      if (selectedProgramId.current !== programId) return;
      setEngagement(createdEngagement);
      selectedEngagementId.current = createdEngagement.id;
      await refreshEngagements(programId);
      const importedReview = { sources: [imported], primary: imported, conflicts: [], normalizationWarnings: [] };
      setSourceReview(importedReview);
      await refreshSources(programId);
      const activeNetworkProfile = networkProfiles.find((item) => item.status === "active");
      setManifestText(JSON.stringify(
        buildManifest(program, createdEngagement, importedReview, activeNetworkProfile),
        null,
        2
      ));
      setState("draft");
    } catch (reason) {
      const code = reason instanceof Error ? reason.message : "REQUEST_FAILED";
      setSourceError(code);
      setIntakeState(
        code.includes("DENIED") || code.includes("INVALID") || code.includes("TOO_LARGE")
          ? "denied"
          : "error"
      );
    }
  }

  function selectSourceBundleForReview(review: SourceBundleReview) {
    if (review.sources.some((selected) => !sources.some((item) => item.id === selected.id && item.content_hash === selected.content_hash))) return;
    setSourceReview(review);
    setManifest(null); setManifestHistory([]); setManifestDiff(null); setPolicy(null); setPolicyHistory([]); setState("draft");
    if (program && engagement) {
      const activeNetworkProfile = networkProfiles.find((item) => item.status === "active");
      setManifestText(JSON.stringify(buildManifest(program, engagement, review, activeNetworkProfile), null, 2));
    } else {
      setManifestText("");
    }
  }

  function selectEngagementForReview(selected: Json) {
    if (!program || !engagements.some((item) => item.id === selected.id && item.program_id === program.id)) return;
    setEngagement(selected);
    selectedEngagementId.current = selected.id;
    setManifest(null); setManifestHistory([]); setManifestDiff(null); setPolicy(null); setPolicyHistory([]); setState("draft");
    if (sourceReview) {
      const activeNetworkProfile = networkProfiles.find((item) => item.status === "active");
      setManifestText(JSON.stringify(buildManifest(program, selected, sourceReview, activeNetworkProfile), null, 2));
    } else setManifestText("");
    void run(() => refreshPolicyHistory(selected.id));
  }

  function selectManifestForReview(selected: Json) {
    if (!engagement || !manifestHistory.some((item) => item.id === selected.id && item.engagement_id === engagement.id)) return;
    setManifest(selected); setManifestText(JSON.stringify(selected.document, null, 2)); setManifestDiff(null); setPolicy(null); setState(selected.valid ? "awaiting approval" : "invalid");
  }

  async function selectPolicyForReview(summary: Json) {
    if (!engagement || !policyHistory.some((item) => item.id === summary.id)) return;
    const recovered = reviewedPolicy(
      await request(`/engagements/${engagement.id}/policies/${summary.id}`),
      summary,
      engagement.id,
      engagement.active_policy_id ?? null
    );
    setPolicy(recovered);
    const matchingManifest = manifestHistory.find((item) => item.id === recovered.manifest_version_id);
    if (matchingManifest) { setManifest(matchingManifest); setManifestText(JSON.stringify(matchingManifest.document, null, 2)); }
    setState(recovered.status === "approved" || recovered.status === "awaiting_approval" ? "awaiting approval" : recovered.status);
  }

  async function compareManifestHistory(fromId: string, toId: string) {
    if (!engagement) return;
    const engagementId = engagement.id;
    const response = await request(`/engagements/${engagementId}/manifests/diff?from_id=${encodeURIComponent(fromId)}&to_id=${encodeURIComponent(toId)}`);
    if (selectedEngagementId.current !== engagementId) return;
    setManifestDiff(reviewedManifestDiff(response, manifestHistory, fromId, toId));
  }

  async function validateManifest() {
    if (!engagement) return;
    let document: Json;
    try { document = JSON.parse(manifestText); }
    catch { setState("invalid"); throw new Error("MANIFEST_JSON_INVALID"); }
    const saved = await request("/manifests", { engagement_id: engagement.id, document });
    setManifest(saved); setManifestText(JSON.stringify(saved.document, null, 2));
    setPolicy(null); setState(saved.valid ? "awaiting approval" : "invalid");
    const history = await request(`/engagements/${engagement.id}/manifests`);
    setManifestHistory(history.manifests);
    setManifestDiff(saved.supersedes_id ? await request(`/engagements/${engagement.id}/manifests/diff?from_id=${encodeURIComponent(saved.supersedes_id)}&to_id=${encodeURIComponent(saved.id)}`) : null);
  }

  async function compilePolicy() {
    if (!manifest?.valid || !engagement) return;
    const compiled = await request(`/manifests/${manifest.id}/compile`, {});
    setPolicy(compiled); setState("awaiting approval");
    const history = await request(`/engagements/${engagement.id}/policies`); setPolicyHistory(history.policies);
  }

  async function approvePolicy(approval: Json) {
    if (!policy || !engagement) return;
    const recorded = await request(`/policies/${policy.id}/approval`, approval);
    if (recorded.subject?.subject_id !== policy.id || recorded.policy_hash !== policy.content_hash || recorded.decision !== approval.decision) throw new Error("POLICY_APPROVAL_RESPONSE_INVALID");
    void run(async () => { const history = await request(`/engagements/${engagement.id}/policies`); setPolicyHistory(history.policies); await refreshAudit(); });
  }

  async function activatePolicy() {
    if (!policy || !engagement) return;
    const activated = await request(`/policies/${policy.id}/activate`, {});
    if (activated.id !== policy.id || activated.status !== "active") throw new Error("POLICY_ACTIVATION_RESPONSE_INVALID");
    setState("active");
    void run(async () => { const history = await request(`/engagements/${engagement.id}/policies`); setPolicyHistory(history.policies); await refreshAudit(); });
  }

  async function revokeActivePolicy(revocation: Json) {
    if (!policy || !engagement) return;
    const revoked = await request(`/policies/${policy.id}/revoke`, revocation);
    if (revoked.id !== policy.id || revoked.status !== "revoked") throw new Error("POLICY_REVOCATION_RESPONSE_INVALID");
    setState("revoked");
    void run(async () => { const history = await request(`/engagements/${engagement.id}/policies`); setPolicyHistory(history.policies); await refreshAudit(); });
  }

  async function refreshAudit() {
    setAudit(await request(auditPath()));
  }

  return (
    <main className="authorization-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Authorization vertical slice</p>
          <h1>PentAI policy workbench</h1>
          <p>Import authoritative sources, approve policy, and simulate decisions under human control.</p>
        </div>
        <span className={`state-pill ${statusClass}`}>{state}</span>
      </header>

      <section className={`safety-banner safety-${safetyState}`} aria-live="polite">
        <div>
          <strong>Global safety: {safetyState}</strong>
          <span>Supervised authorization only; no gateway or target execution exists.</span>
        </div>
        <label>
          Safety reason
          <input value={safetyReason} onChange={(event) => setSafetyReason(event.target.value)} />
        </label>
        <div className="button-row">
          <button onClick={() => changeGlobalSafety("active")} disabled={!connection || safetyState === "active"}>Resume global</button>
          <button onClick={() => changeGlobalSafety("paused")} disabled={!connection || safetyState === "paused"}>Pause all</button>
          <button className="danger" onClick={() => changeGlobalSafety("stopped")} disabled={!connection || safetyState === "stopped"}>Emergency stop</button>
        </div>
      </section>

      {!connection && (
        <div className="error" role="alert">
          <span>{bootstrapError || "Starting authenticated local core…"}</span>
          {bootstrapError && <button onClick={() => window.location.reload()}>Recover local core</button>}
        </div>
      )}

      {error && <p className="error" role="alert">{error}</p>}

      <nav className="workspace-navigation" aria-label="Phase 1 workspaces">
        {phaseOneWorkspaces.map((workspace) => (
          <button
            key={workspace.id}
            type="button"
            className={activeWorkspace === workspace.id ? "current" : ""}
            aria-current={activeWorkspace === workspace.id ? "page" : undefined}
            onClick={() => setActiveWorkspace(workspace.id)}
          >
            {workspace.label}
          </button>
        ))}
      </nav>

      <div className="workflow-grid">
        <div className="workspace-pane" hidden={activeWorkspace !== "dashboard"}>
          <DashboardWorkspace connected={Boolean(connection)} safetyState={safetyState} policyState={state} networkProfiles={networkProfiles} audit={audit} />
        </div>
        <div className="workspace-pane" hidden={activeWorkspace !== "programs"}>
          <ProgramsWorkspace connected={Boolean(connection)} programs={programs} selectedProgramId={program?.id ?? ""} create={createProgram} select={(selected) => { selectProgram(selected); void run(async () => { await Promise.all([refreshSources(selected.id), refreshEngagements(selected.id)]); }); }} refresh={() => run(refreshPrograms)} />
        </div>
        <div className="workspace-pane" hidden={activeWorkspace !== "intake"}>
          <IntakeWorkspace key={program?.id ?? "no-program"} connected={Boolean(connection)} program={program} engagements={engagements} selectedEngagement={engagement} sources={sources} selectedSources={sourceReview?.sources ?? []} state={intakeState} error={sourceError} submit={importSource} selectEngagement={selectEngagementForReview} selectBundle={selectSourceBundleForReview} refresh={() => run(async () => { await Promise.all([refreshSources(), refreshEngagements()]); })} />
        </div>
        <div className="workspace-pane" hidden={activeWorkspace !== "assessments"}>
          <NetworkProfilesWorkspace connected={Boolean(connection)} state={networkSetupState} proposal={networkProposal} profiles={networkProfiles} error={networkSetupError} discover={discoverNetworkProfile} activate={activateNetworkProfile} revoke={revokeNetworkProfile} />
          <AssessmentsWorkspace key={engagement?.id ?? "no-engagement"} connected={Boolean(connection)} engagement={engagement} policy={policy} policyState={state} request={request} auditRefresh={() => void run(refreshAudit)} />
          <PolicyWorkspace key={`${engagement?.id ?? "none"}:${policy?.id ?? "draft"}`} connected={Boolean(connection)} manifestText={manifestText} setManifestText={(value) => { setManifestText(value); if (manifest?.valid) { setManifest(null); setPolicy(null); setState("draft"); } }} manifest={manifest} manifestHistory={manifestHistory} manifestDiff={manifestDiff} policy={policy} policyHistory={policyHistory} state={state} engagementId={engagement?.id ?? ""} activePolicyId={engagement?.active_policy_id ?? null} selectManifest={selectManifestForReview} selectPolicy={selectPolicyForReview} compareManifests={compareManifestHistory} validate={validateManifest} compile={compilePolicy} approve={approvePolicy} activate={activatePolicy} revoke={revokeActivePolicy} />
          <AuthorizationWorkspace key={`${engagement?.id ?? "none"}:${policy?.id ?? "none"}`} connected={Boolean(connection)} engagement={engagement} policy={policy} policyState={state} safetyState={safetyState} request={request} changeAssessmentSafety={changeAssessmentSafety} auditRefresh={() => void run(refreshAudit)} />
        </div>
        <div className="workspace-pane" hidden={activeWorkspace !== "evidence"}><EvidenceWorkspace connection={connection} /></div>
        <div className="workspace-pane" hidden={activeWorkspace !== "findings"}><FindingsWorkspace connection={connection} /></div>
        <div className="workspace-pane" hidden={activeWorkspace !== "reports"}><ReportsWorkspace connection={connection} policy={policy} policyState={state} /></div>
        <div className="workspace-pane" hidden={activeWorkspace !== "logs"}><LogsWorkspace audit={audit} connected={Boolean(connection)} refresh={() => run(refreshAudit)} /></div>
      </div>

      <footer className="state-key" aria-label="Policy state legend">
        {["draft", "invalid", "awaiting approval", "active", "paused", "rejected", "revoked", "expired"].map((item) => (
          <span key={item} className={item === state ? "current" : ""}>{item}</span>
        ))}
      </footer>
    </main>
  );
}
