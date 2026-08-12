import { useMemo, useState } from "react";

type Json = Record<string, any>;

export function auditPath() {
  return "/audit";
}

export function filterAuditEvents(events: Json[], query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return events;
  return events.filter((event) => [
    event.event_id,
    event.action,
    event.actor_type,
    event.actor_id,
    event.subject_type,
    event.subject_id
  ].some((value) => String(value ?? "").toLowerCase().includes(normalized)));
}

export function LogsWorkspace({
  audit,
  connected,
  refresh
}: {
  audit: Json;
  connected: boolean;
  refresh: () => void;
}) {
  const [query, setQuery] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const events = useMemo(
    () => filterAuditEvents(audit.events ?? [], query),
    [audit.events, query]
  );
  const selected = events.find((event: Json) => event.event_id === selectedId) ?? null;
  const valid = audit.verification?.valid === true;

  return (
    <section className="panel wide logs-workspace">
      <div className="panel-heading">
        <h2><span>5</span> Logs</h2>
        <button onClick={refresh} disabled={!connected}>Refresh and verify chain</button>
      </div>
      <p className={valid ? "verified" : "error"} role={valid ? "status" : "alert"}>
        Audit chain {valid ? "verified" : "invalid — do not trust displayed events"} · {audit.verification?.event_count ?? 0} events
      </p>
      <p className="hint">Read-only authenticated audit history. Filtering stays in this UI and does not alter or export the ledger.</p>
      <label>Filter by action, actor, subject, or event ID
        <input
          type="search"
          maxLength={128}
          value={query}
          onChange={(event) => { setQuery(event.target.value); setSelectedId(""); }}
          placeholder="policy, evidence, workflow, UUID…"
        />
      </label>
      <div className="logs-layout">
        <ol className="audit-list detailed-audit-list">
          {events.map((event: Json) => (
            <li key={event.event_id}>
              <button type="button" className={selectedId === event.event_id ? "selected" : ""} onClick={() => setSelectedId(event.event_id)}>
                <strong>{event.action}</strong>
                <span>#{event.sequence} · {event.subject_type}</span>
                <code>{event.event_hash.slice(0, 16)}…</code>
              </button>
            </li>
          ))}
        </ol>
        {events.length === 0 && <p className="hint">No audit events match this filter.</p>}
        {selected && (
          <dl className="audit-detail">
            <dt>Occurred</dt><dd>{selected.occurred_at}</dd>
            <dt>Event ID</dt><dd>{selected.event_id}</dd>
            <dt>Actor</dt><dd>{selected.actor_type} · {selected.actor_id}</dd>
            <dt>Subject</dt><dd>{selected.subject_type} · {selected.subject_id}</dd>
            <dt>Event SHA-256</dt><dd>{selected.event_hash}</dd>
            <dt>Previous SHA-256</dt><dd>{selected.previous_hash ?? "Chain origin"}</dd>
          </dl>
        )}
      </div>
    </section>
  );
}
