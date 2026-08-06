import { FormEvent, useMemo, useState } from "react";

const API = "http://127.0.0.1:8741/api/v1";
const emptyHash = "0".repeat(64);

type Json = Record<string, any>;
type WorkflowState =
  | "draft"
  | "invalid"
  | "awaiting approval"
  | "active"
  | "rejected"
  | "revoked"
  | "expired";

function iso(hours: number) {
  return new Date(Date.now() + hours * 3_600_000).toISOString();
}

async function request(path: string, body?: Json) {
  const response = await fetch(`${API}${path}`, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.detail?.code ?? "REQUEST_FAILED");
  }
  return result;
}

function buildManifest(program: Json, engagement: Json, source: Json) {
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
    network: {
      route_mode: "local_gateway",
      route_profile_id: "local-simulator-only",
      registered_source_ipv4: [],
      registered_source_ipv6: [],
      ipv6_mode: "disabled",
      dns_mode: "tunnel_resolver",
      pause_on_identity_change: true
    },
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
    unresolved_questions: []
  };
}

function target(url: string) {
  const parsed = new URL(url);
  const scheme = parsed.protocol.slice(0, -1);
  const port = parsed.port ? Number(parsed.port) : scheme === "https" ? 443 : 80;
  const canonicalUrl = `${scheme}://${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}${parsed.pathname}${parsed.search}`;
  return {
    scheme,
    host: { kind: "domain", value: parsed.hostname.toLowerCase() },
    port,
    path: parsed.pathname || "/",
    query: parsed.search.slice(1),
    canonical_url: canonicalUrl
  };
}

export function App() {
  const [programName, setProgramName] = useState("Synthetic authorization program");
  const [sourceText, setSourceText] = useState(
    "Synthetic authorization for HTTPS GET requests to example.test/api."
  );
  const [manifestText, setManifestText] = useState("");
  const [program, setProgram] = useState<Json | null>(null);
  const [engagement, setEngagement] = useState<Json | null>(null);
  const [source, setSource] = useState<Json | null>(null);
  const [manifest, setManifest] = useState<Json | null>(null);
  const [policy, setPolicy] = useState<Json | null>(null);
  const [decision, setDecision] = useState<Json | null>(null);
  const [audit, setAudit] = useState<Json>({ events: [], verification: { valid: true } });
  const [intentUrl, setIntentUrl] = useState("https://example.test/api/items");
  const [state, setState] = useState<WorkflowState>("draft");
  const [error, setError] = useState("");

  const canImport = Boolean(program);
  const canValidate = Boolean(engagement && source && manifestText);
  const statusClass = state.replace(" ", "-");
  const policyPreview = useMemo(
    () => policy?.policy ? JSON.stringify(policy.policy, null, 2) : "Compile a valid manifest to preview Policy IR v1.",
    [policy]
  );

  async function run(operation: () => Promise<void>) {
    setError("");
    try {
      await operation();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "REQUEST_FAILED");
    }
  }

  async function createProgram(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      const created = await request("/programs", { name: programName, platform: "local" });
      setProgram(created);
      setState("draft");
    });
  }

  async function importSource(event: FormEvent) {
    event.preventDefault();
    if (!program) return;
    await run(async () => {
      const createdEngagement = await request("/engagements", {
        program_id: program.id,
        effective_from: iso(-1),
        expires_at: iso(8),
        timezone: "UTC"
      });
      const imported = await request("/sources", {
        program_id: program.id,
        authority: "contract",
        reference: "synthetic://local-ui",
        content: sourceText
      });
      setEngagement(createdEngagement);
      setSource(imported);
      setManifestText(JSON.stringify(buildManifest(program, createdEngagement, imported), null, 2));
      setState("draft");
    });
  }

  async function validateManifest() {
    if (!engagement) return;
    await run(async () => {
      let document: Json;
      try {
        document = JSON.parse(manifestText);
      } catch {
        setState("invalid");
        throw new Error("MANIFEST_JSON_INVALID");
      }
      const saved = await request("/manifests", {
        engagement_id: engagement.id,
        document
      });
      setManifest(saved);
      setManifestText(JSON.stringify(saved.document, null, 2));
      setState(saved.valid ? "awaiting approval" : "invalid");
    });
  }

  async function compilePolicy() {
    if (!manifest?.valid) return;
    await run(async () => {
      const compiled = await request(`/manifests/${manifest.id}/compile`, {});
      setPolicy(compiled);
      setState("awaiting approval");
    });
  }

  async function approveAndActivate() {
    if (!policy) return;
    await run(async () => {
      await request(`/policies/${policy.id}/approval`, {
        approver_id: "local-human-user",
        decision: "approved"
      });
      await request(`/policies/${policy.id}/activate`, { actor_id: "local-human-user" });
      setState("active");
      await refreshAudit();
    });
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
        target: target(intentUrl),
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
      setDecision(await request("/policy-decisions", { engagement_id: engagement.id, intent }));
      await refreshAudit();
    });
  }

  async function refreshAudit() {
    setAudit(await request("/audit"));
  }

  return (
    <main className="authorization-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Authorization vertical slice</p>
          <h1>PentAI policy workbench</h1>
          <p>Import, resolve, approve, activate, and simulate. No request leaves this device.</p>
        </div>
        <span className={`state-pill ${statusClass}`}>{state}</span>
      </header>

      <section className="safety-banner">
        <strong>Simulation only</strong>
        <span>No ActionGrants, sockets, HTTP, HTTPS, DNS, or target execution.</span>
      </section>

      {error && <p className="error" role="alert">{error}</p>}

      <div className="workflow-grid">
        <section className="panel">
          <h2><span>1</span> Program and source</h2>
          <form onSubmit={createProgram}>
            <label>Program name<input value={programName} onChange={(event) => setProgramName(event.target.value)} /></label>
            <button type="submit">Create program</button>
          </form>
          <form onSubmit={importSource}>
            <label>Authoritative source<textarea rows={4} value={sourceText} onChange={(event) => setSourceText(event.target.value)} /></label>
            <button type="submit" disabled={!canImport}>Import and hash source</button>
          </form>
          {source && <dl className="hash"><dt>SHA-256 provenance</dt><dd>{source.content_hash}</dd></dl>}
        </section>

        <section className="panel wide">
          <h2><span>2</span> Manifest v2</h2>
          <textarea
            className="editor"
            aria-label="Manifest v2 JSON"
            value={manifestText}
            onChange={(event) => {
              setManifestText(event.target.value);
              if (manifest?.valid) setState("draft");
            }}
            placeholder="Import a source to create a provenance-linked draft."
          />
          <div className="button-row">
            <button onClick={validateManifest} disabled={!canValidate}>Validate and canonicalize</button>
            <button onClick={compilePolicy} disabled={!manifest?.valid}>Compile Policy IR v1</button>
          </div>
          {manifest && (
            <div className={manifest.valid ? "result good" : "result bad"}>
              <strong>{manifest.valid ? "Fully resolved" : "Activation blocked"}</strong>
              <ul>
                {manifest.issues.length === 0
                  ? <li>Schema, semantics, provenance, validity, and scope passed.</li>
                  : manifest.issues.map((issue: Json) => <li key={`${issue.path}:${issue.code}`}>{issue.code} — {issue.path}</li>)}
              </ul>
            </div>
          )}
        </section>

        <section className="panel">
          <h2><span>3</span> Review and activation</h2>
          <pre className="preview">{policyPreview}</pre>
          <button onClick={approveAndActivate} disabled={!policy || state === "active"}>
            Explicitly approve and activate
          </button>
          <p className="hint">Approval binds the exact manifest and compiled-policy hashes.</p>
        </section>

        <section className="panel">
          <h2><span>4</span> ActionIntent simulator</h2>
          <label>Canonical HTTPS URL<input value={intentUrl} onChange={(event) => setIntentUrl(event.target.value)} /></label>
          <button onClick={simulate} disabled={state !== "active"}>Evaluate intent</button>
          {decision && (
            <div className={`decision ${decision.outcome}`}>
              <strong>{decision.outcome}</strong>
              <code>{decision.reason_codes.join(", ")}</code>
            </div>
          )}
        </section>

        <section className="panel wide audit-panel">
          <div className="panel-heading">
            <h2><span>5</span> Tamper-evident audit</h2>
            <button onClick={() => run(refreshAudit)}>Refresh and verify</button>
          </div>
          <p className={audit.verification.valid ? "verified" : "error"}>
            Chain {audit.verification.valid ? "verified" : "invalid"} · {audit.verification.event_count ?? 0} events
          </p>
          <ol className="audit-list">
            {audit.events.map((event: Json) => (
              <li key={event.event_id}>
                <strong>{event.action}</strong>
                <span>{event.data.outcome ?? event.data.decision ?? event.subject_type}</span>
                <code>{event.event_hash.slice(0, 16)}…</code>
              </li>
            ))}
          </ol>
        </section>
      </div>

      <footer className="state-key" aria-label="Policy state legend">
        {["draft", "invalid", "awaiting approval", "active", "rejected", "revoked", "expired"].map((item) => (
          <span key={item} className={item === state ? "current" : ""}>{item}</span>
        ))}
      </footer>
    </main>
  );
}
