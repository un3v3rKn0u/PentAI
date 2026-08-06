const navigation = [
  "Dashboard",
  "Intake",
  "Programs",
  "Assessments",
  "Agents",
  "Evidence",
  "Findings",
  "Reports",
  "Logs"
];

export function App() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">P</span>
          <div>
            <strong>PentAI</strong>
            <small>Supervised security</small>
          </div>
        </div>
        <nav aria-label="Primary navigation">
          {navigation.map((item, index) => (
            <button className={index === 0 ? "nav-item active" : "nav-item"} key={item}>
              {item}
            </button>
          ))}
        </nav>
        <button className="settings">Settings</button>
      </aside>

      <main>
        <header className="topbar">
          <div>
            <small>Workspace</small>
            <h1>Dashboard</h1>
          </div>
          <button className="emergency" type="button">
            Emergency stop
          </button>
        </header>

        <section className="safety-banner" aria-live="polite">
          <div>
            <strong>Execution safely disabled</strong>
            <p>No active policy or attested network route. Phase 0 does not execute target traffic.</p>
          </div>
          <span className="status">DEFAULT DENY</span>
        </section>

        <section className="cards" aria-label="Safety status">
          <article>
            <small>Active policy</small>
            <strong>None</strong>
            <p>An approved policy is required before execution.</p>
          </article>
          <article>
            <small>Network route</small>
            <strong>Not attested</strong>
            <p>Source IP and gateway checks have not run.</p>
          </article>
          <article>
            <small>Running actions</small>
            <strong>0</strong>
            <p>No action grants have been issued.</p>
          </article>
        </section>

        <section className="workspace">
          <div>
            <small>Phase 0 milestone</small>
            <h2>Build the authorization contract first</h2>
            <p>
              Import authoritative program material, preserve provenance, review a normalized
              manifest, and prove ambiguous actions are denied before enabling network execution.
            </p>
          </div>
          <ol>
            <li><span>1</span> Create a program and import sources</li>
            <li><span>2</span> Resolve scope and Rules of Engagement</li>
            <li><span>3</span> Review and activate deterministic policy</li>
          </ol>
        </section>
      </main>

      <footer className="statusbar">
        <span>Core: scaffold</span>
        <span>Policy: inactive</span>
        <span>Network: blocked</span>
      </footer>
    </div>
  );
}
