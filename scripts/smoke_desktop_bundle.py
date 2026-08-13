from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "apps" / "desktop" / "target" / "release"
BOOTSTRAP_TIMEOUT_SECONDS = 30
SHUTDOWN_TIMEOUT_SECONDS = 5
MAX_DIAGNOSTIC_BYTES = 4_000


def desktop_executable() -> Path:
    if sys.platform == "darwin":
        return RELEASE / "bundle" / "macos" / "PentAI.app" / "Contents" / "MacOS" / "pentai-desktop"
    extension = ".exe" if sys.platform == "win32" else ""
    return RELEASE / f"pentai-desktop{extension}"


def process_group_options() -> dict[str, Any]:
    """Start the desktop in a group that can be cleaned up as one unit."""
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Forcefully stop the desktop and any sidecars that inherited its handles."""
    if sys.platform == "win32":
        subprocess.run(  # noqa: S603 - taskkill is the Windows process-tree primitive
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],  # noqa: S607
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=SHUTDOWN_TIMEOUT_SECONDS,
            check=False,
        )
    else:
        os.killpg(process.pid, signal.SIGKILL)


def run_bootstrap(executable: Path) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(  # noqa: S603 - executable is the locally built desktop
        [str(executable)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **process_group_options(),
    )
    try:
        stdout, stderr = process.communicate(timeout=BOOTSTRAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as timeout:
        terminate_process_tree(process)
        try:
            stdout, stderr = process.communicate(timeout=SHUTDOWN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
            stdout = timeout.output or b""
            stderr = timeout.stderr or b""
        diagnostic = (stdout + stderr)[-MAX_DIAGNOSTIC_BYTES:].decode(errors="replace")
        detail = f": {diagnostic.strip()}" if diagnostic.strip() else ""
        raise RuntimeError(
            f"bundled desktop bootstrap timed out after {BOOTSTRAP_TIMEOUT_SECONDS} seconds{detail}"
        ) from None
    if process.returncode is None:
        raise RuntimeError("bundled desktop bootstrap process did not finish")
    return subprocess.CompletedProcess([str(executable)], process.returncode, stdout, stderr)


def main() -> None:
    executable = desktop_executable()
    if not executable.is_file():
        raise RuntimeError(f"bundled desktop executable is missing: {executable}")
    completed = run_bootstrap(executable)
    if completed.returncode != 0:
        diagnostic = (completed.stdout + completed.stderr)[-MAX_DIAGNOSTIC_BYTES:].decode(
            errors="replace"
        )
        raise RuntimeError(f"bundled desktop bootstrap failed: {diagnostic.strip()}")
    print("Bundled desktop bootstrap lifecycle smoke test passed")


if __name__ == "__main__":
    main()
