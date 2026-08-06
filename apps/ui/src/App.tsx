import { useMemo, useState } from "react";

export const policyStates = [
  "draft", "invalid", "awaiting approval", "active", "rejected", "revoked", "expired"
] as const;

type Json = Record<string, any>;
const coreUrl = "http://127.0.0.1:8741";

async function api(path: string, options?: RequestInit): Promise<Json> {
  const response = await fetch(`${coreUrl}${path}`, {
    headers: { "content-type": "application/json" },
    ...options
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail ?? "The local core rejected the request.");
  return body;
}

function post(path: string, body: Json = {}) {
  return api(path, { method: "POST", body: JSON.stringify(body) });
}

function draftManifest(source: Json): Json {
  const start = new Date();
  const end = new Date(start);
  end.setUTCFullYear(end.getUTCFullYear() + 1);
  const engagementId = crypto.randomUUID();
  return {
    schema_version: "2.0.0",
    engagement: {
      id: engagementId, organization: "Synthetic Organization", program_name: "Supervised Web Review",
      program_type: "vdp", status: "draft", effective_from: start.toISOString(),
      expires_at: end.toISOString(), timezone: "UTC"
    },
    sources: [{
      source_id: source.id, reference: source.reference, authority: source.authority,
      retrieved_at: source.retrieved_at, content_hash: source.content_hash
    }],
    scope: {
      assets: [{
        asset_id: crypto.randomUUID(), effect: "allow", type: "url",
        canonical_value: "https://api.example.test/api", allowed_paths: ["/api"],
        denied_paths: ["/api/admin"], allowed_ports: [443], source_reference: source.id
      }],
      discovered_assets_default: "deny", redirects_outside_scope: "stop",
      third_party_services: "deny"
    },
    techniques: {
      allowed_capabilities: ["network.http.get"], denied_capabilities: [],
      conditional_capabilities: [], allowed_http_methods: ["GET"]
    },
    operational_limits: {
      requests_per_second: 2, per_host_requests_per_second: 1, burst_limit: 2,
      concurrent_connections: 1, maximum_runtime_minutes: 30, maximum_total_requests: 100,
      maximum_response_bytes: 1048576, stop_conditions: ["authorization changes"]
    },
    network: {
      route_mode: "local_gateway", route_profile_id: "simulation-only",
      registered_source_ipv4: [], registered_source_ipv6: [], ipv6_mode: "disabled",
      dns_mode: "approved_resolver", pause_on_identity_change: true
    },
    data_handling: {
      real_user_data: "avoid_and_stop", retention_days: 30,
      approved_storage: "local_encrypted", remote_ai_max_classification: "none"
    },
    reporting: {
      submission_channel: "manual", submission_requires_human_approval: true,
      automatic_submission: false
    },
    agent_controls: {
      autonomy: "supervised_testing", maximum_test_depth: 0, maximum_runtime_minutes: 30,
      human_approval_required_for: []
    },
    approvals: {
      scope_reviewer: "local reviewer", rules_reviewer: "local reviewer",
      technical_controls_reviewer: "local reviewer", status: "pending"
    },
    unresolved_questions: []
  };
}

export function App() {
  const [programName, setProgramName] = useState("Synthetic authorization demo");
  const [sourceText, setSourceText] = useState("Synthetic authorization for api.example.test only.");
  const [program, setProgram] = useState<Json>();
  const [source, setSource] = useState<Json>();
  const [manifestText, setManifestText] = useState("");
  const [manifestVersion, setManifestVersion] = useState<Json>();
  const [policy, setPolicy] = useState<Json>();
  const [state, setState] = useState<(typeof policyStates)[number]>("draft");
  const [approver, setApprover] = useState("local-human-reviewer");
  const [simulatorUrl, setSimulatorUrl] = useState("https://api.example.test/api/items");
  const [decision, setDecision] = useState<Json>();
  const [audit, setAudit] = useState<Json>({ events: [], verification: { valid: true } });
  const [error, setError] = useState("");
  const manifest = useMemo(() => {
    try { return manifestText ? JSON.parse(manifestText) : undefined; } catch { return undefined; }
  }, [manifestText]);

  async function act(work: () => Promise<void>) {
    setError("");
    try { await work(); } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The operation failed closed.");
    }
  }

  const createAndImport = () => act(async () => {
    const created = await post("/api/v1/programs", { name: programName, platform: "manual" });
    const imported = await post(`/api/v1/programs/${created.id}/sources`, {
      reference: "pasted authorization", authority: "contract", content: sourceText
    });
    setProgram(created); setSource(imported);
    setManifestText(JSON.stringify(draftManifest(imported), null, 2));
  });

  const validate = () => act(async () => {
    if (!program || !manifest) throw new Error("Create the program and provide valid manifest JSON first.");
    const path = manifestVersion
      ? `/api/v1/engagements/${manifest.engagement.id}/manifests`
      : `/api/v1/programs/${program.id}/engagements`;
    const result = await post(path, manifest);
    setManifestVersion(result);
    setManifestText(JSON.stringify(result.canonical_document, null, 2));
    setState(result.valid ? "draft" : "invalid");
  });

  const compile = () => act(async () => {
    if (!manifestVersion?.valid) throw new Error("Resolve every blocking validation issue first.");
    const result = await post(`/api/v1/manifests/${manifestVersion.id}/compile`);
    setPolicy(result); setState("awaiting approval");
  });

  const approve = () => act(async () => {
    if (!policy) throw new Error("Compile a policy preview first.");
    const expires = new Date(); expires.setUTCDate(expires.getUTCDate() + 7);
    await post(`/api/v1/policies/${policy.policy_id}/approval`, {
      approver_id: approver, expires_at: expires.toISOString(), decision: "approved"
    });
    setState("awaiting approval"); await refreshAudit();
  });

  const reject = () => act(async () => {
    if (!policy) throw new Error("Compile a policy preview first.");
    const expires = new Date(); expires.setUTCDate(expires.getUTCDate() + 7);
    await post(`/api/v1/policies/${policy.policy_id}/approval`, {
      approver_id: approver, expires_at: expires.toISOString(), decision: "rejected"
    });
    setState("rejected"); await refreshAudit();
  });

  const activate = () => act(async () => {
    if (!policy) throw new Error("Compile and approve a policy first.");
    await post(`/api/v1/policies/${policy.policy_id}/activate`, { actor_id: approver });
    setState("active"); await refreshAudit();
  });

  const revoke = () => act(async () => {
    if (!policy) throw new Error("An active policy is required.");
    await post(`/api/v1/policies/${policy.policy_id}/revoke`, { actor_id: approver });
    setState("revoked"); await refreshAudit();
  });

  async function refreshAudit() {
    setAudit(await api("/api/v1/audit"));
  }

  const simulate = () => act(async () => {
    if (!policy) throw new Error("An immutable compiled policy is required.");
    const url = new URL(simulatorUrl);
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
    const request = {
      schema_version: "1.0.0", intent_id: crypto.randomUUID(), assessment_id: crypto.randomUUID(),
      policy_hash: policy.content_hash, actor: { actor_type: "human", actor_id: approver },
      capability: "network.http.get",
      target: {
        scheme: url.protocol.slice(0, -1), host: { kind: "domain", value: url.hostname.toLowerCase() },
        port, path: url.pathname, query: url.search.slice(1), canonical_url: url.toString()
      },
      http: { method: "GET", headers_digest: "0".repeat(64), body_digest: null, follow_redirects: false },
      parameters_digest: "1".repeat(64), impact: "benign",
      created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 300000).toISOString(),
      idempotency_key: crypto.randomUUID()
    };
    setDecision(await post(`/api/v1/policies/${policy.policy_id}/evaluate`, request));
    await refreshAudit();
  });

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">P</span><div><strong>PentAI</strong><small>Authorization lab</small></div></div>
        <nav aria-label="Workflow"><span className="nav-item active">Authorization slice</span><span className="nav-item">Audit trail</span></nav>
        <div className="network-lock">NETWORK<br/><strong>DISABLED</strong></div>
      </aside>
      <main>
        <header className="topbar"><div><small>Local supervised workflow</small><h1>Policy authorization</h1></div><span className={`state ${state.replace(" ", "-")}`}>{state}</span></header>
        <section className="safety-banner"><div><strong>Decision simulation only</strong><p>No grants, sockets, HTTP requests, or target execution exist in this milestone.</p></div><span className="status">DEFAULT DENY</span></section>
        {error && <div className="error" role="alert">{error}</div>}
        <div className="workflow-grid">
          <section className="panel">
            <div className="step-title"><span>1</span><div><h2>Program & source</h2><small>Import pasted authorization locally and hash it.</small></div></div>
            <label>Program name<input value={programName} onChange={event => setProgramName(event.target.value)} /></label>
            <label>Authoritative source<textarea rows={4} value={sourceText} onChange={event => setSourceText(event.target.value)} /></label>
            <button onClick={createAndImport}>Create program & import source</button>
            {source && <code className="hash">SHA-256 {source.content_hash}</code>}
          </section>
          <section className="panel wide">
            <div className="step-title"><span>2</span><div><h2>Manifest v2</h2><small>Edit exact scope, provenance, limits, warnings, and unresolved questions.</small></div></div>
            <textarea className="editor" rows={16} value={manifestText} onChange={event => setManifestText(event.target.value)} placeholder="Create a program to generate a Manifest v2 draft." />
            <button onClick={validate}>Validate & canonicalize</button>
            {manifestVersion && <div className={manifestVersion.valid ? "result allow" : "result deny"}>
              <strong>{manifestVersion.valid ? "Valid and fully resolved" : "Blocked"}</strong>
              <span>{manifestVersion.issues.length} blocking issue(s)</span>
              {manifestVersion.issues.map((issue: Json) => <code key={issue.path}>{issue.code} · {issue.path}</code>)}
            </div>}
          </section>
          <section className="panel">
            <div className="step-title"><span>3</span><div><h2>Compile & approve</h2><small>Approval binds the exact manifest and Policy IR hashes.</small></div></div>
            <button onClick={compile}>Compile Policy IR v1</button>
            {policy && <><code className="hash">Manifest {policy.manifest_hash}</code><code className="hash">Policy {policy.content_hash}</code></>}
            <label>Human approver<input value={approver} onChange={event => setApprover(event.target.value)} /></label>
            <div className="button-row"><button onClick={approve}>Approve exact policy</button><button onClick={reject}>Reject</button><button className="primary" onClick={activate}>Activate</button><button onClick={revoke}>Revoke active policy</button></div>
          </section>
          <section className="panel">
            <div className="step-title"><span>4</span><div><h2>ActionIntent simulator</h2><small>Change the URL to test scope and path boundaries.</small></div></div>
            <label>Canonical target URL<input value={simulatorUrl} onChange={event => setSimulatorUrl(event.target.value)} /></label>
            <button onClick={simulate}>Evaluate without execution</button>
            {decision && <div className={`decision ${decision.outcome}`}>
              <strong>{decision.outcome.toUpperCase()}</strong><code>{decision.reason_codes.join(", ")}</code>
            </div>}
          </section>
          <section className="panel wide">
            <div className="step-title"><span>5</span><div><h2>Tamper-evident audit</h2><small>Approval, activation, rejection, revocation, and every decision extend one hash chain.</small></div></div>
            <button onClick={() => act(refreshAudit)}>Verify & refresh trail</button>
            <div className={`chain ${audit.verification.valid ? "allow" : "deny"}`}>
              Chain {audit.verification.valid ? "verified" : "broken"} · {audit.events.length} events
            </div>
            <div className="events">{audit.events.map((event: Json) =>
              <div key={event.event_id}><strong>{event.action}</strong><span>{event.occurred_at}</span><code>{event.event_hash.slice(0, 16)}…</code></div>
            )}</div>
          </section>
        </div>
      </main>
      <footer className="statusbar"><span>Policy: {state}</span><span>Execution: unavailable</span><span>Network: blocked</span></footer>
    </div>
  );
}
