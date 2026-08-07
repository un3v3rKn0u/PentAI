from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "apps" / "desktop" / "target" / "release"


def desktop_executable() -> Path:
    if sys.platform == "darwin":
        return RELEASE / "bundle" / "macos" / "PentAI.app" / "Contents" / "MacOS" / "pentai-desktop"
    extension = ".exe" if sys.platform == "win32" else ""
    return RELEASE / f"pentai-desktop{extension}"


def main() -> None:
    executable = desktop_executable()
    if not executable.is_file():
        raise RuntimeError(f"bundled desktop executable is missing: {executable}")
    completed = subprocess.run(  # noqa: S603 - executable is the locally built desktop
        [str(executable)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        diagnostic = (completed.stdout + completed.stderr)[-4_000:].decode(errors="replace")
        raise RuntimeError(f"bundled desktop bootstrap failed: {diagnostic.strip()}")
    print("Bundled desktop bootstrap lifecycle smoke test passed")


if __name__ == "__main__":
    main()
