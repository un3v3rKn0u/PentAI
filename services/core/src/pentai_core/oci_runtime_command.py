from __future__ import annotations


def oci_run_command(executable: str, *arguments: str) -> tuple[str, ...]:
    """Build a container launch that never inherits host logging defaults."""
    return (executable, "run", "--log-driver=none", *arguments)
