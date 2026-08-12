from __future__ import annotations

import http.client
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

ROOT = Path(__file__).resolve().parents[1]
MAX_DIAGNOSTIC_BYTES = 4_000


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    forced_kill: bool


class BoundedBinaryProcess(Protocol):
    returncode: int | None

    def communicate(
        self, input: bytes | None = None, timeout: float | None = None
    ) -> tuple[bytes, bytes]: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


def communicate_bounded(
    process: BoundedBinaryProcess,
    *,
    process_input: bytes,
    timeout: float,
    shutdown_timeout: float = 5,
) -> BoundedProcessResult:
    """Collect a child process without leaving it running after a timeout."""
    timed_out = False
    forced_kill = False
    try:
        stdout, stderr = process.communicate(input=process_input, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=shutdown_timeout)
        except subprocess.TimeoutExpired:
            forced_kill = True
            process.kill()
            stdout, stderr = process.communicate()
    if process.returncode is None:
        raise RuntimeError("bounded child process cleanup did not finish")
    return BoundedProcessResult(
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        forced_kill=forced_kill,
    )


def host_triple() -> str:
    rustc = shutil.which("rustc")
    if rustc is None:
        raise RuntimeError("rustc is required to locate the core sidecar")
    return subprocess.run(  # noqa: S603 - resolved rustc executable is intentional
        [rustc, "--print", "host-tuple"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def sidecar_path() -> Path:
    extension = ".exe" if sys.platform == "win32" else ""
    return ROOT / "apps" / "desktop" / "binaries" / (f"pentai-core-{host_triple()}{extension}")


def reserve_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def request(port: int, path: str, token: str | None = None, method: str = "GET") -> int:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        connection.request(method, path, body=b"" if method == "POST" else None, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def environment(port: int, database: Path, credential: str, source_store: Path) -> dict[str, str]:
    return {
        **os.environ,
        "PENTAI_ENVIRONMENT": "production",
        "PENTAI_CORE_HOST": "127.0.0.1",
        "PENTAI_CORE_PORT": str(port),
        "PENTAI_DATABASE_PATH": str(database),
        "PENTAI_SOURCE_STORE_PATH": str(source_store),
        "PENTAI_SOURCE_KEY_STDIN": "1",
        "PENTAI_LAUNCH_CREDENTIAL": credential,
    }


def child_diagnostic(stdout: bytes, stderr: bytes, credential: str) -> str:
    combined = (stdout + stderr).replace(credential.encode(), b"<redacted>")
    return combined[-MAX_DIAGNOSTIC_BYTES:].decode(errors="replace").strip()


def main() -> None:
    executable = sidecar_path()
    if not executable.is_file():
        raise RuntimeError("core sidecar has not been built")
    credential = secrets.token_urlsafe(32)
    source_key = secrets.token_urlsafe(32)
    port = reserve_port()
    with tempfile.TemporaryDirectory() as temporary:
        process = subprocess.Popen(  # noqa: S603 - executable is the locally built sidecar
            [str(executable)],
            env=environment(
                port,
                Path(temporary) / "pentai.db",
                credential,
                Path(temporary) / "source-blobs",
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdin is None:
            raise RuntimeError("core source-key channel is unavailable")
        process.stdin.write(f"{source_key}\n".encode())
        process.stdin.close()
        process.stdin = None
        deadline = time.monotonic() + 20
        try:
            while True:
                if process.poll() is not None:
                    stdout, stderr = process.communicate(timeout=1)
                    diagnostic = child_diagnostic(stdout, stderr, credential)
                    detail = f": {diagnostic}" if diagnostic else ""
                    raise RuntimeError(f"core sidecar exited before readiness{detail}")
                try:
                    if request(port, "/api/v1/readiness", credential) == 200:
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("core sidecar readiness timed out") from None
                    time.sleep(0.1)
            if request(port, "/api/v1/readiness") != 401:
                raise RuntimeError("rogue caller reached the core sidecar")
            if request(port, "/api/v1/readiness", secrets.token_urlsafe(32)) != 401:
                raise RuntimeError("incorrect credential reached the core sidecar")
            if request(port, "/api/v1/shutdown", credential, "POST") != 200:
                raise RuntimeError("authenticated shutdown failed")
            stdout, stderr = process.communicate(timeout=10)
            if process.returncode != 0:
                raise RuntimeError("core sidecar did not exit cleanly")
            if credential.encode() in stdout + stderr or source_key.encode() in stdout + stderr:
                raise RuntimeError("credential material appeared in core output")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

        collision_port = reserve_port()
        collision_credential = secrets.token_urlsafe(32)
        collision_source_key = secrets.token_urlsafe(32)
        with socket.socket() as collision:
            collision.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            collision.bind(("127.0.0.1", collision_port))
            collision.listen()
            blocked_process = subprocess.Popen(  # noqa: S603 - locally built sidecar
                [str(executable)],
                env=environment(
                    collision_port,
                    Path(temporary) / "collision.db",
                    collision_credential,
                    Path(temporary) / "collision-sources",
                ),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            blocked = communicate_bounded(
                blocked_process,
                process_input=f"{collision_source_key}\n".encode(),
                timeout=10,
            )
        if blocked.returncode == 0:
            raise RuntimeError("core sidecar accepted an occupied port")
        if (
            collision_credential.encode() in blocked.stdout + blocked.stderr
            or collision_source_key.encode() in blocked.stdout + blocked.stderr
        ):
            raise RuntimeError("credential material appeared in collision output")
    print("Core sidecar lifecycle smoke test passed")


if __name__ == "__main__":
    main()
