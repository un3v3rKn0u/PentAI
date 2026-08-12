import { invoke, isTauri } from "@tauri-apps/api/core";
import { useEffect, useRef, useState } from "react";

import { ReportsWorkspace } from "./ReportsWorkspace";
import { FindingsWorkspace } from "./FindingsWorkspace";
import { EvidenceWorkspace } from "./EvidenceWorkspace";
import { auditPath, LogsWorkspace } from "./LogsWorkspace";
import { DashboardWorkspace } from "./DashboardWorkspace";
import { ProgramsWorkspace, programsPath } from "./ProgramsWorkspace";
import { IntakeWorkspace, type IntakeState, type SourceImport } from "./IntakeWorkspace";
import { AssessmentsWorkspace } from "./AssessmentsWorkspace";
import { PolicyWorkspace } from "./PolicyWorkspace";

const emptyHash = "0".repeat(64);

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
type NetworkSetupState = "empty" | "loading" | "needs_confirmation" | "active" | "revoked" | "degraded" | "error";


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


export function networkSetupRequirement(code: string) {
  const messages: Record<string, string> = {
    CONFIRM_ROUTE: "Confirm the detected interface and gateway.",
    CONFIRM_RESOLVER_MODE: "Choose and confirm the controlled resolver mode.",
    ENTER_REGISTERED_SOURCE_IP: "Enter the public source IP registered for the assessment."
  };
  return messages[code] ?? "Resolve an unknown setup requirement before activation.";
}

export function parseSourceAddresses(value: string) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
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

function buildManifest(program: Json, engagement: Json, source: Json, networkProfile?: Json) {
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
    sources: [{
      source_id: source.id,
      reference: source.reference,
      authority: source.authority,
      retrieved_at: source.retrieved_at,
      content_hash: source.content_hash
    }],
    field_provenance: Object.fromEntries([
      "/scope", "/techniques", "/operational_limits", "/network",
      "/data_handling", "/reporting", "/agent_controls"
    ].map((field) => [field, [{ source_id: source.id, content_hash: source.content_hash }]])),
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
        source_reference: source.id
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
    unresolved_questions: networkProfile
      ? []
      : ["Confirm an active network profile before policy activation."]
  };
}

export function buildIntentTarget(url: string) {
  if (url !== url.trim() || url.includes("\\")) {
    throw new Error("TARGET_AMBIGUOUS");
  }
  const parsed = new URL(url);
  const scheme = parsed.protocol.slice(0, -1);
  if (!["http", "https"].includes(scheme) || parsed.username || parsed.password || parsed.hash) {
    throw new Error("TARGET_AMBIGUOUS");
  }
  const port = parsed.port ? Number(parsed.port) : scheme === "https" ? 443 : 80;
  const canonicalUrl = `${scheme}://${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}${parsed.pathname}${parsed.search}`;
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const kind = hostname.includes(":")
    ? "ipv6"
    : /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)
      ? "ipv4"
      : "domain";
  return {
    scheme,
    host: { kind, value: hostname },
    port,
    path: parsed.pathname || "/",
    query: parsed.search.slice(1),
    canonical_url: canonicalUrl
  };
}

export function App() {
  const [connection, setConnection] = useState<CoreConnection | null>(null);
  const [bootstrapError, setBootstrapError] = useState("");
  const [programs, setPrograms] = useState<Json[]>([]);
  const [sources, setSources] = useState<Json[]>([]);
  const [intakeState, setIntakeState] = useState<IntakeState>("empty");
  const [sourceError, setSourceError] = useState("");
  const [manifestText, setManifestText] = useState("");
  const [program, setProgram] = useState<Json | null>(null);
  const [engagement, setEngagement] = useState<Json | null>(null);
  const [source, setSource] = useState<Json | null>(null);
  const [manifest, setManifest] = useState<Json | null>(null);
  const [manifestHistory, setManifestHistory] = useState<Json[]>([]);
  const [manifestDiff, setManifestDiff] = useState<Json | null>(null);
  const [policy, setPolicy] = useState<Json | null>(null);
  const [policyHistory, setPolicyHistory] = useState<Json[]>([]);
  const [currentIntent, setCurrentIntent] = useState<Json | null>(null);
  const [decision, setDecision] = useState<Json | null>(null);
  const [grant, setGrant] = useState<Json | null>(null);
  const [grantStatus, setGrantStatus] = useState("not issued");
  const [audit, setAudit] = useState<Json>({ events: [], verification: { valid: true } });
  const [intentUrl, setIntentUrl] = useState("https://example.test/api/items");
  const [state, setState] = useState<WorkflowState>("draft");
  const [safetyState, setSafetyState] = useState<SafetyState>("loading");
  const [safetyReason, setSafetyReason] = useState("Explicit supervised safety control");
  const [networkSetupState, setNetworkSetupState] = useState<NetworkSetupState>("empty");
  const [networkProposal, setNetworkProposal] = useState<Json | null>(null);
  const [networkSetupError, setNetworkSetupError] = useState("");
  const [networkProfiles, setNetworkProfiles] = useState<Json[]>([]);
  const [registeredSourceIpv4, setRegisteredSourceIpv4] = useState("");
  const [resolverMode, setResolverMode] = useState("tunnel_resolver");
  const [routeConfirmed, setRouteConfirmed] = useState(false);
  const [error, setError] = useState("");
  const selectedProgramId = useRef("");

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
      setGrant(null);
      setGrantStatus(status === "active" ? "not issued" : `revoked by global ${status}`);
      await refreshAudit();
    });
  }

  async function discoverNetworkProfile() {
    setNetworkSetupState("loading");
    setNetworkSetupError("");
    try {
      const proposal = await request("/network-profile-proposal");
      setNetworkProposal(proposal);
      setRouteConfirmed(false);
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

  async function activateNetworkProfile() {
    if (!networkProposal) return;
    setNetworkSetupState("loading");
    setNetworkSetupError("");
    try {
      const activated = await request("/network-profiles/activate", {
        proposal_id: networkProposal.proposal_id,
        confirm_route: routeConfirmed,
        resolver_mode: resolverMode,
        registered_source_ipv4: parseSourceAddresses(registeredSourceIpv4),
        registered_source_ipv6: [],
        ipv6_mode: "disabled"
      });
      await refreshNetworkProfiles();
      setNetworkProposal(null);
      if (program && engagement && source) {
        setManifestText(JSON.stringify(
          buildManifest(program, engagement, source, activated),
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

  async function revokeNetworkProfile(profileId: string) {
    setNetworkSetupState("loading");
    try {
      await request(`/network-profiles/${profileId}/revoke`, {
        reason: "Explicit supervised network profile revocation"
      });
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
      setGrant(null);
      setGrantStatus(status === "active" ? "not issued" : "revoked by assessment pause");
      await refreshAudit();
    });
  }

  function selectProgram(selected: Json | null) {
    selectedProgramId.current = selected?.id ?? "";
    setProgram(selected);
    setSources([]);
    setSource(null);
    setEngagement(null);
    setManifest(null);
    setManifestHistory([]);
    setManifestDiff(null);
    setManifestText("");
    setPolicy(null);
    setPolicyHistory([]);
    setCurrentIntent(null);
    setDecision(null);
    setGrant(null);
    setGrantStatus("not issued");
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
          media_type: submission.mediaType, content_base64: submission.contentBase64
        });
      } else if (submission.mode === "url") {
        imported = await request("/sources/urls", {
          program_id: programId, authority: submission.authority, url: submission.url
        });
      } else {
        imported = await request("/sources", {
          program_id: programId, authority: submission.authority,
          reference: "pasted://local-supervised-intake",
          content: submission.content
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
      setSource(imported);
      await refreshSources(programId);
      const activeNetworkProfile = networkProfiles.find((item) => item.status === "active");
      setManifestText(JSON.stringify(
        buildManifest(program, createdEngagement, imported, activeNetworkProfile),
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

  async function simulate() {
    if (!policy || !engagement) return;
    await run(async () => {
      const created = new Date().toISOString();
      const intent = {
        schema_version: "1.0.0",
        intent_id: crypto.randomUUID(),
        assessment_id: engagement.id,
        policy_hash: policy.content_hash ?? emptyHash,
        actor: { actor_type: "human", actor_id: "local-human-user" },
        capability: "network.http.get",
        target: buildIntentTarget(intentUrl),
        http: {
          method: "GET",
          headers_digest: emptyHash,
          body_digest: null,
          follow_redirects: false
        },
        parameters_digest: "1".repeat(64),
        impact: "benign",
        created_at: created,
        expires_at: new Date(Date.now() + 300_000).toISOString(),
        idempotency_key: crypto.randomUUID()
      };
      setCurrentIntent(intent);
      setGrant(null);
      setGrantStatus("not issued");
      setDecision(await request("/policy-decisions", { engagement_id: engagement.id, intent }));
      await refreshAudit();
    });
  }

  async function mintGrant() {
    if (!decision || decision.outcome !== "allow") return;
    await run(async () => {
      const issued = await request("/action-grants", {
        decision_id: decision.decision_id,
        audience: "pentai-execution-broker"
      });
      setGrant(issued);
      setGrantStatus("issued — no execution");
      await refreshAudit();
    });
  }

  async function consumeGrant() {
    if (!grant || !currentIntent) return;
    await run(async () => {
      await request("/action-grants/consume", {
        grant,
        intent: currentIntent,
        audience: "pentai-execution-broker"
      });
      setGrantStatus("consumed — no execution");
      await refreshAudit();
    });
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

      <section className="network-setup" aria-busy={networkSetupState === "loading"}>
        <div>
          <p className="eyebrow">Guided network setup</p>
          <h2>Discover local settings for review</h2>
          <p>Discovery saves a short-lived proposal only. Human confirmation is required before a non-executing profile becomes active.</p>
        </div>
        <button onClick={discoverNetworkProfile} disabled={!connection || networkSetupState === "loading"}>
          {networkSetupState === "loading" ? "Discovering…" : "Discover network settings"}
        </button>
        {networkSetupState === "empty" && <p className="setup-status">No network proposal has been created.</p>}
        {networkSetupState === "loading" && <p className="setup-status">Reading the local route and resolver. No external observer is contacted.</p>}
        {networkSetupState === "degraded" && <p className="setup-status bad" role="alert">Discovery unavailable: {networkSetupError}. Nothing was activated.</p>}
        {networkSetupState === "error" && <p className="setup-status bad" role="alert">Network setup failed safely: {networkSetupError}</p>}
        {networkSetupState === "revoked" && <p className="setup-status">The profile was revoked. Networking remains disabled.</p>}
        {networkProfiles.filter((item) => item.status === "active").map((item) => (
          <div className="setup-proposal active-profile" role="status" key={item.profile_id}>
            <strong>Confirmed profile — execution still disabled</strong>
            <p>{item.route_interface} · {item.resolver_mode} · {item.registered_source_ipv4.join(", ")}</p>
            <button className="danger" onClick={() => revokeNetworkProfile(item.profile_id)}>Revoke profile</button>
          </div>
        ))}
        {networkProposal && networkSetupState === "needs_confirmation" && (
          <div className="setup-proposal" role="status">
            <dl>
              <div><dt>Interface</dt><dd>{networkProposal.route_interface}</dd></div>
              <div><dt>Gateway</dt><dd>{networkProposal.route_gateway ?? "None detected"}</dd></div>
              <div><dt>Resolvers</dt><dd>{networkProposal.resolver_addresses.join(", ")}</dd></div>
              <div><dt>Expires</dt><dd>{new Date(networkProposal.expires_at).toLocaleTimeString()}</dd></div>
            </dl>
            <strong>Human confirmation still required</strong>
            <ul>{networkProposal.requirements.map((item: string) => <li key={item}>{networkSetupRequirement(item)}</li>)}</ul>
            <label>
              Registered public IPv4 address
              <input value={registeredSourceIpv4} onChange={(event) => setRegisteredSourceIpv4(event.target.value)} placeholder="Public IP registered for this assessment" />
            </label>
            <label>
              Controlled resolver mode
              <select value={resolverMode} onChange={(event) => setResolverMode(event.target.value)}>
                <option value="tunnel_resolver">Resolver supplied by the approved route</option>
                <option value="approved_resolver">Explicit approved resolver</option>
              </select>
            </label>
            <label className="confirmation-check">
              <input type="checkbox" checked={routeConfirmed} onChange={(event) => setRouteConfirmed(event.target.checked)} />
              I confirm the detected interface, gateway, and resolver addresses.
            </label>
            <button onClick={activateNetworkProfile} disabled={!routeConfirmed || parseSourceAddresses(registeredSourceIpv4).length === 0}>
              Confirm and activate profile
            </button>
          </div>
        )}
      </section>

      <div className="workflow-grid">
        <DashboardWorkspace
          connected={Boolean(connection)}
          safetyState={safetyState}
          policyState={state}
          networkProfiles={networkProfiles}
          audit={audit}
        />
        <ProgramsWorkspace
          connected={Boolean(connection)}
          programs={programs}
          selectedProgramId={program?.id ?? ""}
          create={createProgram}
          select={(selected) => { selectProgram(selected); void run(() => refreshSources(selected.id)); }}
          refresh={() => run(refreshPrograms)}
        />
        <IntakeWorkspace key={program?.id ?? "no-program"} connected={Boolean(connection)} program={program} sources={sources} selectedSource={source} state={intakeState} error={sourceError} submit={importSource} refresh={() => run(() => refreshSources())} />
        <AssessmentsWorkspace
          key={engagement?.id ?? "no-engagement"}
          connected={Boolean(connection)}
          engagement={engagement}
          policy={policy}
          policyState={state}
          request={request}
          auditRefresh={() => void run(refreshAudit)}
        />

        <PolicyWorkspace key={`${engagement?.id ?? "none"}:${policy?.id ?? "draft"}`} connected={Boolean(connection)} manifestText={manifestText} setManifestText={(value) => { setManifestText(value); if (manifest?.valid) { setManifest(null); setPolicy(null); setState("draft"); } }} manifest={manifest} manifestHistory={manifestHistory} manifestDiff={manifestDiff} policy={policy} policyHistory={policyHistory} state={state} validate={validateManifest} compile={compilePolicy} approve={approvePolicy} activate={activatePolicy} revoke={revokeActivePolicy} />

        <section className="panel">
          <h2><span>4</span> ActionIntent simulator</h2>
          <div className="button-row assessment-safety">
            <button onClick={() => changeAssessmentSafety("active")} disabled={!connection || !engagement || safetyState !== "active"}>Resume assessment</button>
            <button onClick={() => changeAssessmentSafety("paused")} disabled={!connection || !engagement}>Pause assessment</button>
          </div>
          <label>Canonical HTTPS URL<input value={intentUrl} onChange={(event) => setIntentUrl(event.target.value)} /></label>
          <button onClick={simulate} disabled={!connection || state !== "active" || safetyState !== "active"}>Evaluate intent</button>
          {decision && (
            <div className={`decision ${decision.outcome}`}>
              <strong>{decision.outcome}</strong>
              <code>{decision.reason_codes.join(", ")}</code>
            </div>
          )}
          <button onClick={mintGrant} disabled={!connection || decision?.outcome !== "allow" || Boolean(grant)}>
            Issue single-use grant
          </button>
          <button onClick={consumeGrant} disabled={!connection || !grant || grantStatus.startsWith("consumed")}>
            Verify and consume locally
          </button>
          <p className="hint">Grant status: {grantStatus}</p>
          {grant && <code>{grant.grant_id} · expires {grant.expires_at}</code>}
        </section>

        <LogsWorkspace audit={audit} connected={Boolean(connection)} refresh={() => run(refreshAudit)} />
        <EvidenceWorkspace connection={connection} />
        <FindingsWorkspace connection={connection} />
        <ReportsWorkspace connection={connection} />
      </div>

      <footer className="state-key" aria-label="Policy state legend">
        {["draft", "invalid", "awaiting approval", "active", "paused", "rejected", "revoked", "expired"].map((item) => (
          <span key={item} className={item === state ? "current" : ""}>{item}</span>
        ))}
      </footer>
    </main>
  );
}
