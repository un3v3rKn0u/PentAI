import { useState } from "react";

type Json = Record<string, any>;
export type NetworkSetupState = "empty" | "loading" | "needs_confirmation" | "active" | "revoked" | "degraded" | "error";

export function networkSetupRequirement(code: string) {
  const messages: Record<string, string> = {
    CONFIRM_ROUTE: "Confirm the detected interface and gateway.",
    CONFIRM_RESOLVER_MODE: "Choose and confirm the controlled resolver mode.",
    ENTER_REGISTERED_SOURCE_IP: "Enter the public source IP registered for the assessment."
  };
  return messages[code] ?? "Resolve an unknown setup requirement before activation.";
}

export function parseSourceAddresses(value: string) {
  return [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))];
}

export function networkProfileActivationRequest(
  proposalId: string,
  routeConfirmed: boolean,
  resolverMode: string,
  registeredSourceIpv4: string
) {
  const addresses = parseSourceAddresses(registeredSourceIpv4);
  if (!routeConfirmed || addresses.length === 0) throw new Error("NETWORK_PROFILE_CONFIRMATION_INCOMPLETE");
  if (!["tunnel_resolver", "approved_resolver"].includes(resolverMode)) throw new Error("NETWORK_PROFILE_RESOLVER_MODE_INVALID");
  return { proposal_id: proposalId, confirm_route: true, resolver_mode: resolverMode, registered_source_ipv4: addresses, registered_source_ipv6: [], ipv6_mode: "disabled" };
}

export function networkProfileRevocationRequest(reason: string) {
  const normalized = reason.trim();
  if (!normalized || normalized.length > 500) throw new Error("NETWORK_PROFILE_REVOCATION_REASON_INVALID");
  return { reason: normalized };
}

export function NetworkProfilesWorkspace(props: {
  connected: boolean;
  state: NetworkSetupState;
  proposal: Json | null;
  profiles: Json[];
  error: string;
  discover: () => Promise<void>;
  activate: (request: Json) => Promise<void>;
  revoke: (profileId: string, request: Json) => Promise<void>;
}) {
  const [registeredSourceIpv4, setRegisteredSourceIpv4] = useState("");
  const [resolverMode, setResolverMode] = useState("tunnel_resolver");
  const [routeConfirmed, setRouteConfirmed] = useState(false);
  const [revocationReasons, setRevocationReasons] = useState<Record<string, string>>({});
  const [localError, setLocalError] = useState("");
  const activeProfiles = props.profiles.filter((item) => item.status === "active");

  function submitActivation() {
    if (!props.proposal) return;
    setLocalError("");
    try {
      void props.activate(networkProfileActivationRequest(props.proposal.proposal_id, routeConfirmed, resolverMode, registeredSourceIpv4));
    } catch (reason) {
      setLocalError(reason instanceof Error ? reason.message : "NETWORK_PROFILE_CONFIRMATION_INCOMPLETE");
    }
  }

  function submitRevocation(profileId: string) {
    setLocalError("");
    try {
      void props.revoke(profileId, networkProfileRevocationRequest(revocationReasons[profileId] ?? ""));
    } catch (reason) {
      setLocalError(reason instanceof Error ? reason.message : "NETWORK_PROFILE_REVOCATION_REASON_INVALID");
    }
  }

  return (
    <section className="network-setup" aria-busy={props.state === "loading"}>
      <div><p className="eyebrow">Network profiles</p><h2>Review the local route before activation</h2><p>Discovery creates a short-lived proposal only. A confirmed profile remains configuration, not attestation or execution authority.</p></div>
      <button onClick={() => void props.discover()} disabled={!props.connected || props.state === "loading"}>{props.state === "loading" ? "Discovering…" : "Discover network settings"}</button>
      {props.state === "empty" && <p className="setup-status">No network proposal has been created.</p>}
      {props.state === "loading" && <p className="setup-status">Reading the local route and resolver. No external observer is contacted.</p>}
      {props.state === "degraded" && <p className="setup-status bad" role="alert">Discovery unavailable: {props.error}. Nothing was activated.</p>}
      {props.state === "error" && <p className="setup-status bad" role="alert">Network setup failed safely: {props.error}</p>}
      {props.state === "revoked" && <p className="setup-status">The profile was revoked. Networking remains disabled.</p>}
      {localError && <p className="setup-status bad" role="alert">{localError}</p>}
      {activeProfiles.length > 1 && <p className="setup-status bad" role="alert">Multiple active profiles are ambiguous. Activation and execution remain blocked by the core.</p>}
      {activeProfiles.map((item) => (
        <div className="setup-proposal active-profile" role="status" key={item.profile_id}>
          <strong>Confirmed profile — execution still disabled</strong>
          <dl><div><dt>Profile</dt><dd><code>{item.profile_id}</code></dd></div><div><dt>Interface</dt><dd>{item.route_interface}</dd></div><div><dt>Resolver</dt><dd>{item.resolver_mode}</dd></div><div><dt>Registered IPv4</dt><dd>{item.registered_source_ipv4.join(", ")}</dd></div></dl>
          <label>Revocation reason<input value={revocationReasons[item.profile_id] ?? ""} onChange={(event) => setRevocationReasons((current) => ({ ...current, [item.profile_id]: event.target.value }))} maxLength={500} /></label>
          <button className="danger" onClick={() => submitRevocation(item.profile_id)}>Revoke profile</button>
        </div>
      ))}
      {props.proposal && props.state === "needs_confirmation" && (
        <div className="setup-proposal" role="status">
          <dl><div><dt>Interface</dt><dd>{props.proposal.route_interface}</dd></div><div><dt>Gateway</dt><dd>{props.proposal.route_gateway ?? "None detected"}</dd></div><div><dt>Resolvers</dt><dd>{props.proposal.resolver_addresses.join(", ")}</dd></div><div><dt>Expires</dt><dd>{new Date(props.proposal.expires_at).toLocaleTimeString()}</dd></div></dl>
          <strong>Human confirmation still required</strong>
          <ul>{props.proposal.requirements.map((item: string) => <li key={item}>{networkSetupRequirement(item)}</li>)}</ul>
          <label>Registered public IPv4 address<input value={registeredSourceIpv4} onChange={(event) => setRegisteredSourceIpv4(event.target.value)} placeholder="Public IP registered for this assessment" /></label>
          <label>Controlled resolver mode<select value={resolverMode} onChange={(event) => setResolverMode(event.target.value)}><option value="tunnel_resolver">Resolver supplied by the approved route</option><option value="approved_resolver">Explicit approved resolver</option></select></label>
          <label className="confirmation-check"><input type="checkbox" checked={routeConfirmed} onChange={(event) => setRouteConfirmed(event.target.checked)} />I confirm the detected interface, gateway, and resolver addresses.</label>
          <button onClick={submitActivation} disabled={!routeConfirmed || parseSourceAddresses(registeredSourceIpv4).length === 0}>Confirm and activate profile</button>
        </div>
      )}
    </section>
  );
}
