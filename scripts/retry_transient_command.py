"""Run a command again only when it fails with a recognized transient network error."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from collections.abc import Callable, Sequence

TRANSIENT_NETWORK_ERRORS = (
    "peer disconnected",
    "connection reset by peer",
    "connection timed out",
    "operation timed out",
    "temporary failure in name resolution",
    "could not resolve host",
    "failed to connect",
    "unexpected eof",
)


def is_transient_network_failure(output: str) -> bool:
    normalized = output.casefold()
    return any(message in normalized for message in TRANSIENT_NETWORK_ERRORS)


def run_with_retry(
    command: Sequence[str],
    *,
    attempts: int,
    base_delay: float,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    sleeper: Callable[[float], None] = time.sleep,
) -> int:
    """Return the command exit code after bounded, network-only retries."""
    if attempts < 1:
        raise ValueError("attempts must be at least 1")

    for attempt in range(1, attempts + 1):
        result = runner(command, capture_output=True, text=True, check=False)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)

        if result.returncode == 0:
            return 0

        output = f"{result.stdout}\n{result.stderr}"
        if attempt == attempts or not is_transient_network_failure(output):
            return result.returncode

        delay = base_delay * attempt
        print(
            f"Transient network failure detected; retrying in {delay:g}s "
            f"(attempt {attempt + 1}/{attempts})",
            file=sys.stderr,
        )
        sleeper(delay)

    raise AssertionError("retry loop exited unexpectedly")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--base-delay", type=float, default=5)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    return run_with_retry(command, attempts=args.attempts, base_delay=args.base_delay)


if __name__ == "__main__":
    raise SystemExit(main())
