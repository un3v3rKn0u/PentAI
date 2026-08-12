import { useEffect, useState } from "react";

type Json = Record<string, any>;
const emptyHash = "0".repeat(64);

export function buildIntentTarget(url: string) {
  if (url !== url.trim() || url.includes("\\")) throw new Error("TARGET_AMBIGUOUS");
  const parsed = new URL(url);
  const scheme = parsed.protocol.slice(0, -1);
  if (!["http", "https"].includes(scheme) || parsed.username || parsed.password || parsed.hash) throw new Error("TARGET_AMBIGUOUS");
  const port = parsed.port ? Number(parsed.port) : scheme === "https" ? 443 : 80;
  const canonicalUrl = `${scheme}://${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}${parsed.pathname}${parsed.search}`;
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const kind = hostname.includes(":") ? "ipv6" : /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) ? "ipv4" : "domain";
  return { scheme, host: { kind, value: hostname }, port, path: parsed.pathname || "/", query: parsed.search.slice(1), canonical_url: canonicalUrl };
}

export function actionIntent(assessmentId: string, policyHash: string, url: string, now = new Date()) {
  return {
    schema_version: "1.0.0", intent_id: crypto.randomUUID(), assessment_id: assessmentId,
    policy_hash: policyHash, actor: { actor_type: "human", actor_id: "local-human-user" },
    capability: "network.http.get", target: buildIntentTarget(url),
    http: { method: "GET", headers_digest: emptyHash, body_digest: null, follow_redirects: false },
    parameters_digest: "1".repeat(64), impact: "benign", created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + 300_000).toISOString(), idempotency_key: crypto.randomUUID()
  };
}

export function verifiedDecision(response: Json, intent: Json) {
  if (!response.decision_id || response.intent_id !== intent.intent_id || response.assessment_id !== intent.assessment_id || response.policy_hash !== intent.policy_hash || !["allow", "deny", "approval_required"].includes(response.outcome) || !Array.isArray(response.reason_codes) || response.reason_codes.length === 0 || (response.outcome === "allow" && !response.reason_codes.includes("EXPLICIT_ALLOW"))) throw new Error("POLICY_DECISION_RESPONSE_INVALID");
  return response;
}

export function verifiedGrant(response: Json, decision: Json, intent: Json) {
  if (!response.grant_id || response.intent_id !== intent.intent_id || response.decision_id !== decision.decision_id || response.assessment_id !== intent.assessment_id || response.policy_hash !== intent.policy_hash || response.audience !== "pentai-execution-broker" || response.capability !== intent.capability || response.parameters_digest !== intent.parameters_digest || response.single_use !== true) throw new Error("ACTION_GRANT_RESPONSE_INVALID");
  return response;
}

export function verifiedConsumption(response: Json, grant: Json) {
  if (response.grant_id !== grant.grant_id || response.status !== "consumed" || response.policy_hash !== grant.policy_hash) throw new Error("ACTION_GRANT_CONSUMPTION_INVALID");
  return response;
}

export function AuthorizationWorkspace(props: { connected: boolean; engagement: Json | null; policy: Json | null; policyState: string; safetyState: string; request: (path: string, body?: Json) => Promise<Json>; changeAssessmentSafety: (status: "active" | "paused") => Promise<void>; auditRefresh: () => void }) {
  const [intentUrl, setIntentUrl] = useState("https://example.test/api/items");
  const [intent, setIntent] = useState<Json | null>(null);
  const [decision, setDecision] = useState<Json | null>(null);
  const [grant, setGrant] = useState<Json | null>(null);
  const [grantStatus, setGrantStatus] = useState("not issued");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const exactAuthority = Boolean(props.engagement && props.policy?.content_hash && props.policyState === "active" && props.safetyState === "active");

  useEffect(() => {
    if (props.safetyState === "active" && props.policyState === "active") return;
    setIntent(null); setDecision(null); setGrant(null);
    setGrantStatus(props.safetyState === "active" ? "not issued" : `revoked by ${props.safetyState}`);
  }, [props.policyState, props.safetyState]);

  async function evaluate() {
    if (!props.engagement || !props.policy) return;
    setBusy(true); setError(""); setDecision(null); setGrant(null); setGrantStatus("not issued");
    try {
      const created = actionIntent(props.engagement.id, props.policy.content_hash, intentUrl);
      const result = verifiedDecision(await props.request("/policy-decisions", { engagement_id: props.engagement.id, intent: created }), created);
      setIntent(created); setDecision(result); props.auditRefresh();
    } catch (cause) { setIntent(null); setError(cause instanceof Error ? cause.message : "POLICY_DECISION_FAILED"); }
    finally { setBusy(false); }
  }

  async function mint() {
    if (!intent || decision?.outcome !== "allow") return;
    setBusy(true); setError("");
    try {
      const issued = verifiedGrant(await props.request("/action-grants", { decision_id: decision.decision_id, audience: "pentai-execution-broker" }), decision, intent);
      setGrant(issued); setGrantStatus("issued — no execution"); props.auditRefresh();
    } catch (cause) { setGrant(null); setError(cause instanceof Error ? cause.message : "ACTION_GRANT_FAILED"); }
    finally { setBusy(false); }
  }

  async function consume() {
    if (!grant || !intent) return;
    setBusy(true); setError("");
    try {
      verifiedConsumption(await props.request("/action-grants/consume", { grant, intent, audience: "pentai-execution-broker" }), grant);
      setGrantStatus("consumed — no execution"); props.auditRefresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "ACTION_GRANT_CONSUMPTION_FAILED"); }
    finally { setBusy(false); }
  }

  return <section className="panel" aria-busy={busy}>
    <div className="panel-heading"><h2><span>4</span> Authorization</h2><strong className="hint">Deterministic evaluation only · no network request</strong></div>
    <div className="button-row assessment-safety"><button onClick={() => void props.changeAssessmentSafety("active")} disabled={!props.connected || !props.engagement || props.safetyState !== "active"}>Resume assessment</button><button onClick={() => void props.changeAssessmentSafety("paused")} disabled={!props.connected || !props.engagement}>Pause assessment</button></div>
    <label>Canonical HTTP(S) URL<input value={intentUrl} onChange={(event) => { setIntentUrl(event.target.value); setIntent(null); setDecision(null); setGrant(null); setGrantStatus("not issued"); }} /></label>
    <button onClick={() => void evaluate()} disabled={!props.connected || busy || !exactAuthority}>Evaluate without connecting</button>
    {error && <p className="result bad" role="alert">Authorization denied safely: {error}</p>}
    {decision && <div className={`decision ${decision.outcome}`}><strong>{decision.outcome}</strong><code>{decision.reason_codes.join(", ")}</code><span>No connection was attempted.</span></div>}
    <button onClick={() => void mint()} disabled={!props.connected || busy || decision?.outcome !== "allow" || Boolean(grant)}>Issue single-use local grant</button>
    <button onClick={() => void consume()} disabled={!props.connected || busy || !grant || grantStatus.startsWith("consumed")}>Verify and consume locally</button>
    <p className="hint">Grant status: {grantStatus}</p>
    {grant && <code>{grant.grant_id} · expires {grant.expires_at}</code>}
  </section>;
}
