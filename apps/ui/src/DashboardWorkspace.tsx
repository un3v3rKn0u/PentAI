type Json = Record<string, any>;
type Tone = "ready" | "attention" | "blocked";

export type DashboardCard = {
  label: string;
  value: string;
  detail: string;
  tone: Tone;
};

export function operationalDashboardCards({
  connected,
  safetyState,
  policyState,
  networkProfiles,
  audit
}: {
  connected: boolean;
  safetyState: string;
  policyState: string;
  networkProfiles: Json[];
  audit: Json;
}): DashboardCard[] {
  const activeProfiles = networkProfiles.filter((profile) => profile.status === "active");
  const verificationComplete = audit.verification?.valid === true
    && Number.isSafeInteger(audit.verification?.event_count);

  return [
    {
      label: "Authenticated core",
      value: connected ? "Connected" : "Unavailable",
      detail: connected ? "Loopback session established" : "No authenticated local session",
      tone: connected ? "ready" : "blocked"
    },
    {
      label: "Global safety",
      value: safetyState,
      detail: safetyState === "active" ? "Supervised actions may be evaluated" : "New authority remains unavailable",
      tone: safetyState === "active" ? "ready" : safetyState === "paused" ? "attention" : "blocked"
    },
    {
      label: "Policy lifecycle",
      value: policyState,
      detail: policyState === "active" ? "Active policy selected in this workspace" : "No active workspace policy",
      tone: policyState === "active" ? "ready" : ["draft", "awaiting approval"].includes(policyState) ? "attention" : "blocked"
    },
    {
      label: "Network profile",
      value: activeProfiles.length === 1 ? "Active" : activeProfiles.length > 1 ? "Ambiguous" : "Not active",
      detail: activeProfiles.length === 1
        ? `${activeProfiles[0].route_interface} · ${activeProfiles[0].resolver_mode}`
        : activeProfiles.length > 1 ? "Multiple active profiles must not be treated as safe" : "Execution remains disabled",
      tone: activeProfiles.length === 1 ? "ready" : activeProfiles.length > 1 ? "blocked" : "attention"
    },
    {
      label: "Audit integrity",
      value: verificationComplete ? "Verified" : audit.verification?.valid === false ? "Invalid" : "Not verified",
      detail: verificationComplete
        ? `${audit.verification.event_count} hash-chained events`
        : "Refresh Logs before relying on audit history",
      tone: verificationComplete ? "ready" : audit.verification?.valid === false ? "blocked" : "attention"
    }
  ];
}

export function DashboardWorkspace(props: {
  connected: boolean;
  safetyState: string;
  policyState: string;
  networkProfiles: Json[];
  audit: Json;
}) {
  const cards = operationalDashboardCards(props);
  const blocked = cards.filter((card) => card.tone === "blocked").length;
  const attention = cards.filter((card) => card.tone === "attention").length;
  const posture: Tone = blocked ? "blocked" : attention ? "attention" : "ready";

  return (
    <section className="panel dashboard-workspace">
      <div className="panel-heading">
        <h2><span>0</span> Dashboard</h2>
        <strong className={`dashboard-posture ${posture}`}>{posture}</strong>
      </div>
      <p className="hint">Operational summary only. Every protected action is independently revalidated by the core.</p>
      <div className="dashboard-grid">
        {cards.map((card) => (
          <article className={`dashboard-card ${card.tone}`} key={card.label}>
            <span>{card.label}</span>
            <strong>{card.value}</strong>
            <small>{card.detail}</small>
          </article>
        ))}
      </div>
    </section>
  );
}
