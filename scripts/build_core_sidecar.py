from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import PyInstaller.__main__  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
DESKTOP = ROOT / "apps" / "desktop"
BUILD_ROOT = ROOT / "build" / "core-sidecar"


def host_triple() -> str:
    rustc = shutil.which("rustc")
    if rustc is None:
        raise RuntimeError("rustc is required to build the core sidecar")
    completed = subprocess.run(  # noqa: S603 - resolved rustc executable is intentional
        [rustc, "--print", "host-tuple"],
        check=True,
        capture_output=True,
        text=True,
    )
    triple = completed.stdout.strip()
    if not triple or any(character.isspace() for character in triple):
        raise RuntimeError("Rust host tuple is invalid")
    return triple


def main() -> None:
    triple = host_triple()
    extension = ".exe" if sys.platform == "win32" else ""
    output_directory = DESKTOP / "binaries"
    output_directory.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(BUILD_ROOT, ignore_errors=True)
    distribution = BUILD_ROOT / "dist"
    work = BUILD_ROOT / "work"
    specification = BUILD_ROOT / "spec"
    os.environ["PYINSTALLER_CONFIG_DIR"] = str(BUILD_ROOT / "config")
    schema_source = ROOT / "schemas" / "v1"
    schema_destination = "pentai_policy/schemas"
    migrations_source = ROOT / "migrations"
    migrations_destination = "pentai_core/migrations"

    PyInstaller.__main__.run(
        [
            "--noconfirm",
            "--clean",
            "--onefile",
            "--name",
            "pentai-core",
            "--distpath",
            str(distribution),
            "--workpath",
            str(work),
            "--specpath",
            str(specification),
            "--paths",
            str(ROOT / "services" / "core" / "src"),
            "--paths",
            str(ROOT / "packages" / "policy" / "src"),
            "--add-data",
            f"{schema_source}{os.pathsep}{schema_destination}",
            "--add-data",
            f"{migrations_source}{os.pathsep}{migrations_destination}",
            str(ROOT / "scripts" / "core_sidecar_entry.py"),
        ]
    )
    built = distribution / f"pentai-core{extension}"
    if not built.is_file():
        raise RuntimeError("PyInstaller did not produce the core sidecar")
    destination = output_directory / f"pentai-core-{triple}{extension}"
    shutil.copy2(built, destination)
    if sys.platform != "win32":
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    print(f"Built {destination.relative_to(ROOT)} (sha256:{digest})")


if __name__ == "__main__":
    main()
