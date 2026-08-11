from __future__ import annotations

import asyncio
import http.client
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from pentai_core.config import Settings, allowed_origins
from pentai_core.main import create_app
from pentai_core.network_attestation_adapters import HostRouteSnapshot
from pentai_core.network_profile_setup import NetworkProfileSetupService


def runtime_settings(database_path: Path, credential: str | None = None) -> Settings:
    return Settings(
        environment="production",
        host="127.0.0.1",
        port=8741,
        database_path=database_path,
        launch_credential=credential or secrets.token_urlsafe(32),
    )


@dataclass(frozen=True)
class AppResponse:
    status_code: int
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def text(self) -> str:
        return self.body.decode()


@dataclass
class FixtureRuntimeSupervisor:
    state: str = "ready"
    reason_code: str | None = None
    starts: int = 0
    stops: int = 0

    def start(self) -> None:
        self.starts += 1

    def stop(self) -> None:
        self.stops += 1

    def status(self) -> dict[str, object]:
        return {
            "status": self.state,
            "reason_code": self.reason_code,
            "recovered_instances": 0,
            "watchdog_running": self.state == "ready",
            "execution_enabled": False,
        }


@dataclass
class FixtureNetworkSupervisor:
    state: str = "ready"
    reason_code: str | None = None
    starts: int = 0
    stops: int = 0

    def start(self) -> None:
        self.starts += 1

    def stop(self) -> None:
        self.stops += 1

    def status(self) -> dict[str, object]:
        return {
            "status": self.state,
            "reason_code": self.reason_code,
            "monitored_assessments": 1,
            "watchdog_running": self.state == "ready",
            "execution_enabled": False,
        }


def app_request(
    app: FastAPI,
    method: str,
    path: str,
    *,
    authorization: str | None = None,
    json_body: dict[str, Any] | None = None,
) -> AppResponse:
    body = json.dumps(json_body).encode() if json_body is not None else b""
    headers = [(b"host", b"127.0.0.1")]
    if authorization is not None:
        headers.append((b"authorization", authorization.encode()))
    if json_body is not None:
        headers.append((b"content-type", b"application/json"))
    messages: list[dict[str, Any]] = []
    received = False

    async def receive() -> dict[str, Any]:
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    async def invoke() -> None:
        await app(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": method,
                "scheme": "http",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "root_path": "",
                "headers": headers,
                "server": ("127.0.0.1", 8741),
                "client": ("127.0.0.1", 50000),
            },
            receive,
            send,
        )

    asyncio.run(invoke())
    start = next(message for message in messages if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"") for message in messages if message["type"] == "http.response.body"
    )
    return AppResponse(start["status"], response_body)


@pytest.fixture
def authenticated_client(tmp_path: Path) -> tuple[FastAPI, str]:
    settings = runtime_settings(tmp_path / "pentai.db")
    return create_app(settings), settings.launch_credential or ""


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/v1/health"),
        ("GET", "/api/v1/readiness"),
        ("GET", "/api/v1/runtime-supervision"),
        ("GET", "/api/v1/network-safety-supervision"),
        ("GET", "/api/v1/network-profile-proposal"),
        ("GET", "/api/v1/network-profiles"),
        ("GET", "/api/v1/safety-state"),
        ("GET", "/api/v1/audit"),
        ("GET", "/api/v1/execution-traces/unknown"),
        ("POST", "/api/v1/shutdown"),
        ("POST", "/api/v1/programs"),
        ("POST", "/api/v1/engagements"),
        ("POST", "/api/v1/sources"),
        ("POST", "/api/v1/manifests"),
        ("POST", "/api/v1/manifests/unknown/compile"),
        ("POST", "/api/v1/policies/unknown/approval"),
        ("POST", "/api/v1/policies/unknown/activate"),
        ("POST", "/api/v1/policy-decisions"),
        ("POST", "/api/v1/action-grants"),
        ("POST", "/api/v1/action-grants/consume"),
        ("POST", "/api/v1/safety-state"),
        ("POST", "/api/v1/network-profiles/activate"),
        ("POST", "/api/v1/network-profiles/unknown/revoke"),
        ("POST", "/api/v1/engagements/unknown/safety-state"),
        ("POST", "/api/v1/workflows"),
        ("GET", "/api/v1/workflows/unknown"),
        ("POST", "/api/v1/workflows/unknown/transition"),
        ("POST", "/api/v1/workflows/unknown/tasks"),
        ("POST", "/api/v1/workflow-tasks/unknown/cancel"),
        ("POST", "/api/v1/workflow-tasks/unknown/claim"),
        ("POST", "/api/v1/workflow-tasks/unknown/heartbeat"),
        ("POST", "/api/v1/workflow-tasks/unknown/checkpoints"),
        ("POST", "/api/v1/workflow-tasks/unknown/finalize"),
    ],
)
def test_every_api_route_rejects_missing_credentials(
    authenticated_client: tuple[FastAPI, str], method: str, path: str
) -> None:
    app, _ = authenticated_client
    response = app_request(app, method, path)
    assert response.status_code == 401
    assert response.json() == {
        "detail": {
            "code": "AUTHENTICATION_REQUIRED",
            "message": "Authentication required",
        }
    }


def test_authenticated_network_profile_discovery_is_review_only(tmp_path: Path) -> None:
    class Probe:
        def inspect(self) -> HostRouteSnapshot:
            return HostRouteSnapshot("fixture0", "192.0.2.1", ("192.0.2.53",))

    settings = runtime_settings(tmp_path / "pentai.db")
    app = create_app(
        settings,
        network_profile_setup_service=NetworkProfileSetupService(Probe()),
    )
    response = app_request(
        app,
        "GET",
        "/api/v1/network-profile-proposal",
        authorization=f"Bearer {settings.launch_credential}",
    )

    assert response.status_code == 200
    assert response.json()["status"] == "needs_confirmation"
    assert response.json()["execution_enabled"] is False
    assert response.json()["registered_source_ipv4"] == []

    activated = app_request(
        app,
        "POST",
        "/api/v1/network-profiles/activate",
        authorization=f"Bearer {settings.launch_credential}",
        json_body={
            "proposal_id": response.json()["proposal_id"],
            "confirm_route": True,
            "resolver_mode": "tunnel_resolver",
            "registered_source_ipv4": ["8.8.8.8"],
            "registered_source_ipv6": [],
            "ipv6_mode": "disabled",
        },
    )
    assert activated.status_code == 200
    assert activated.json()["execution_enabled"] is False

    listed = app_request(
        app,
        "GET",
        "/api/v1/network-profiles",
        authorization=f"Bearer {settings.launch_credential}",
    )
    assert listed.json()["profiles"] == [activated.json()]

    revoked = app_request(
        app,
        "POST",
        f"/api/v1/network-profiles/{activated.json()['profile_id']}/revoke",
        authorization=f"Bearer {settings.launch_credential}",
        json_body={"reason": "Explicit local test revocation"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"


def test_network_profile_discovery_failure_is_fixed_and_non_sensitive(tmp_path: Path) -> None:
    class FailingProbe:
        def inspect(self) -> HostRouteSnapshot:
            raise RuntimeError("private route command output")

    settings = runtime_settings(tmp_path / "pentai.db")
    app = create_app(
        settings,
        network_profile_setup_service=NetworkProfileSetupService(FailingProbe()),
    )
    response = app_request(
        app,
        "GET",
        "/api/v1/network-profile-proposal",
        authorization=f"Bearer {settings.launch_credential}",
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": {
            "code": "NETWORK_PROFILE_DISCOVERY_FAILED",
            "message": "Local network settings could not be discovered safely",
        }
    }
    assert "private" not in response.text


@pytest.mark.parametrize(
    "authorization",
    ["", "Bearer", "Bearer ", "Basic abc", "Bearer incorrect-credential"],
)
def test_malformed_or_incorrect_credentials_are_uniformly_denied(
    authenticated_client: tuple[FastAPI, str], authorization: str
) -> None:
    app, credential = authenticated_client
    response = app_request(app, "GET", "/api/v1/readiness", authorization=authorization)
    assert response.status_code == 401
    assert credential not in response.text
    if authorization:
        assert authorization not in response.text


def test_correct_credential_reaches_protected_readiness(
    authenticated_client: tuple[FastAPI, str],
) -> None:
    app, credential = authenticated_client
    response = app_request(
        app,
        "GET",
        "/api/v1/readiness",
        authorization=f"Bearer {credential}",
    )
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "execution_enabled": False}


def test_runtime_supervisor_degradation_blocks_readiness_without_exposing_details(
    tmp_path: Path,
) -> None:
    settings = runtime_settings(tmp_path / "degraded.db")
    supervisor = FixtureRuntimeSupervisor(
        state="degraded", reason_code="GATEWAY_WATCHDOG_FAILED"
    )
    app = create_app(settings, runtime_supervisor=supervisor)
    credential = settings.launch_credential or ""
    readiness = app_request(
        app, "GET", "/api/v1/readiness", authorization=f"Bearer {credential}"
    )
    assert readiness.status_code == 503
    assert readiness.json() == {
        "status": "degraded",
        "reason_code": "GATEWAY_WATCHDOG_FAILED",
        "execution_enabled": False,
    }
    health = app_request(app, "GET", "/api/v1/health", authorization=f"Bearer {credential}")
    assert health.status_code == 200
    assert health.json()["status"] == "degraded"
    runtime = app_request(
        app,
        "GET",
        "/api/v1/runtime-supervision",
        authorization=f"Bearer {credential}",
    )
    assert runtime.json()["watchdog_running"] is False
    assert supervisor.starts == 1


def test_storage_failure_latch_degrades_health_and_readiness(tmp_path: Path) -> None:
    settings = runtime_settings(tmp_path / "storage-degraded.db")
    app = create_app(
        settings,
        runtime_supervisor=FixtureRuntimeSupervisor(),
        network_safety_supervisor=FixtureNetworkSupervisor(),
    )
    app.state.storage_safety.trip("STORAGE_FAILURE")
    credential = settings.launch_credential or ""

    readiness = app_request(
        app, "GET", "/api/v1/readiness", authorization=f"Bearer {credential}"
    )
    assert readiness.status_code == 503
    assert readiness.json() == {
        "status": "degraded",
        "reason_code": "STORAGE_FAILURE",
        "execution_enabled": False,
    }
    health = app_request(app, "GET", "/api/v1/health", authorization=f"Bearer {credential}")
    assert health.status_code == 200
    assert health.json()["status"] == "degraded"


def test_authenticated_shutdown_stops_runtime_supervision(tmp_path: Path) -> None:
    settings = runtime_settings(tmp_path / "shutdown-supervisor.db")
    supervisor = FixtureRuntimeSupervisor()
    app = create_app(settings, runtime_supervisor=supervisor)
    response = app_request(
        app,
        "POST",
        "/api/v1/shutdown",
        authorization=f"Bearer {settings.launch_credential}",
    )
    assert response.status_code == 200
    assert supervisor.stops == 1


def test_network_supervisor_degradation_blocks_readiness_and_shutdown_stops_it(
    tmp_path: Path,
) -> None:
    settings = runtime_settings(tmp_path / "network-degraded.db")
    runtime_supervisor = FixtureRuntimeSupervisor()
    network_supervisor = FixtureNetworkSupervisor(
        state="degraded", reason_code="NETWORK_IDENTITY_WATCHDOG_FAILED"
    )
    app = create_app(
        settings,
        runtime_supervisor=runtime_supervisor,
        network_safety_supervisor=network_supervisor,
    )
    credential = settings.launch_credential or ""
    readiness = app_request(
        app, "GET", "/api/v1/readiness", authorization=f"Bearer {credential}"
    )
    assert readiness.status_code == 503
    assert readiness.json() == {
        "status": "degraded",
        "reason_code": "NETWORK_IDENTITY_WATCHDOG_FAILED",
        "execution_enabled": False,
    }
    status = app_request(
        app,
        "GET",
        "/api/v1/network-safety-supervision",
        authorization=f"Bearer {credential}",
    )
    assert status.json()["monitored_assessments"] == 1
    shutdown = app_request(
        app, "POST", "/api/v1/shutdown", authorization=f"Bearer {credential}"
    )
    assert shutdown.status_code == 200
    assert network_supervisor.starts == 1
    assert network_supervisor.stops == 1


def test_startup_safety_state_is_durably_paused(
    authenticated_client: tuple[FastAPI, str],
) -> None:
    app, credential = authenticated_client
    response = app_request(
        app,
        "GET",
        "/api/v1/safety-state",
        authorization=f"Bearer {credential}",
    )
    assert response.status_code == 200
    assert response.json()["status"] == "paused"
    assert response.json()["execution_enabled"] is False


def test_shutdown_requires_authentication_and_sets_server_signal(
    authenticated_client: tuple[FastAPI, str],
) -> None:
    app, credential = authenticated_client
    assert not app.state.shutdown_requested.is_set()
    response = app_request(
        app,
        "POST",
        "/api/v1/shutdown",
        authorization=f"Bearer {credential}",
    )
    assert response.status_code == 200
    assert response.json() == {"status": "shutting_down"}
    assert app.state.shutdown_requested.is_set()


def test_caller_actor_identity_is_not_accepted_as_authority(
    authenticated_client: tuple[FastAPI, str],
) -> None:
    app, credential = authenticated_client
    response = app_request(
        app,
        "POST",
        "/api/v1/policies/unknown/approval",
        authorization=f"Bearer {credential}",
        json_body={"decision": "approved", "approver_id": "forged-human"},
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "settings",
    [
        Settings(launch_credential=None),
        Settings(launch_credential=""),
        Settings(launch_credential="not-base64url!"),
        Settings(launch_credential="a" * 42),
        Settings(host="0.0.0.0", launch_credential=secrets.token_urlsafe(32)),  # noqa: S104
        Settings(port=0, launch_credential=secrets.token_urlsafe(32)),
    ],
)
def test_insecure_startup_configuration_fails_closed(settings: Settings) -> None:
    with pytest.raises(ValueError):
        settings.validate()


def test_test_mode_requires_explicit_test_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENTAI_TEST_MODE", "1")
    monkeypatch.setenv("PENTAI_ENVIRONMENT", "production")
    monkeypatch.delenv("PENTAI_LAUNCH_CREDENTIAL", raising=False)
    with pytest.raises(ValueError):
        Settings.from_environment()


def test_production_origins_exclude_development_servers(tmp_path: Path) -> None:
    production = runtime_settings(tmp_path / "production.db")
    assert "http://127.0.0.1:1420" not in allowed_origins(production)
    development = Settings(
        **{
            **production.__dict__,
            "environment": "development",
        }
    )
    assert "http://127.0.0.1:1420" in allowed_origins(development)


def test_core_process_requires_authentication_and_shuts_down_gracefully(
    tmp_path: Path,
) -> None:
    credential = secrets.token_urlsafe(32)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    repository_root = Path(__file__).resolve().parents[1]
    python_path = os.pathsep.join(
        [
            str(repository_root / "services" / "core" / "src"),
            str(repository_root / "packages" / "policy" / "src"),
        ]
    )
    environment = {
        **os.environ,
        "PYTHONPATH": python_path,
        "PENTAI_ENVIRONMENT": "production",
        "PENTAI_CORE_HOST": "127.0.0.1",
        "PENTAI_CORE_PORT": str(port),
        "PENTAI_DATABASE_PATH": str(tmp_path / "process.db"),
        "PENTAI_LAUNCH_CREDENTIAL": credential,
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "pentai_core.server"],
        cwd=repository_root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def request(path: str, *, token: str | None = None, method: str = "GET") -> int:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            connection.request(
                method,
                path,
                body=b"" if method == "POST" else None,
                headers=headers,
            )
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    deadline = time.monotonic() + 10
    try:
        while True:
            if process.poll() is not None:
                pytest.fail("core exited before readiness")
            try:
                if request("/api/v1/readiness", token=credential) == 200:
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    pytest.fail("core readiness timed out")
                time.sleep(0.05)

        assert request("/api/v1/readiness") == 401
        assert request("/api/v1/shutdown", token=credential, method="POST") == 200
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
