import { FormEvent, useState } from "react";

type Json = Record<string, any>;

export function programsPath() {
  return "/programs";
}

export function programCreateRequest(name: string) {
  return { name: name.trim(), platform: "local" };
}

export function ProgramsWorkspace({
  connected,
  programs,
  selectedProgramId,
  create,
  select,
  refresh
}: {
  connected: boolean;
  programs: Json[];
  selectedProgramId: string;
  create: (request: Json) => Promise<void>;
  select: (program: Json) => void;
  refresh: () => Promise<void>;
}) {
  const [name, setName] = useState("Synthetic authorization program");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError("");
    try {
      await create(programCreateRequest(name));
      setName("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "PROGRAM_CREATE_FAILED");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel programs-workspace" aria-busy={busy}>
      <div className="panel-heading">
        <h2><span>1</span> Programs</h2>
        <button type="button" onClick={() => void refresh()} disabled={!connected || busy}>Refresh</button>
      </div>
      <p className="hint">Create or explicitly select one local program. Selection clears downstream intake and authorization state.</p>
      <form className="program-create" onSubmit={submit}>
        <label>Program name<input maxLength={200} value={name} onChange={(event) => setName(event.target.value)} /></label>
        <button type="submit" disabled={!connected || busy || !name.trim()}>Create draft program</button>
      </form>
      {error && <p className="result bad" role="alert">Program creation denied: {error}</p>}
      {programs.length === 0 ? <p className="hint">No programs are available.</p> : (
        <ol className="program-list">
          {programs.map((program) => (
            <li key={program.id}>
              <button
                type="button"
                className={program.id === selectedProgramId ? "selected" : ""}
                onClick={() => select(program)}
              >
                <strong>{program.name}</strong>
                <span>{program.platform ?? "No platform"} · {program.status}</span>
                <code>{program.id}</code>
              </button>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
