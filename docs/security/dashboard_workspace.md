# Operational Dashboard workspace

The Dashboard is a read-only summary of state already held by the authenticated local
workspace: core connectivity, global safety, the currently displayed policy lifecycle,
active network profiles, and complete audit-chain verification. It issues no mutations
and grants no authority. Every protected operation continues to be independently
revalidated by the core at its existing boundary.

The presentation defaults away from ready. A disconnected core, stopped/error safety
state, invalid audit chain, or multiple active profiles is blocked. Draft or awaiting
policy, paused safety, no active profile, and incomplete audit verification require
attention. Audit verification is ready only when both `valid: true` and an integer event
count came from the authenticated audit response.

The dashboard adds no endpoint, schema, migration, persistence, network access, or
execution capability. Its policy status is local presentation state, not a substitute
for authoritative policy selection. Rollback removes only the summary cards.
