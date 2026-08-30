from __future__ import annotations

import asyncio
import http.client
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from pentai_core.config import Settings, allowed_origins
from pentai_core.main import create_app
from pentai_core.migrate import migrate
from pentai_core.network_attestation_adapters import HostRouteSnapshot
from pentai_core.network_profile_setup import NetworkProfileSetupService
from pentai_core.orchestration import DurablePlanGraphService
from pentai_core.policy_signing import PolicySigner
from pentai_policy import content_hash

from scripts.owned_fixture_authority import prepare_owned_fixture_session

APPROVAL_PLAN = "33333333-3333-4333-8333-333333333333"
APPROVAL_TASK = "44444444-4444-4444-8444-444444444444"


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


@dataclass
class FixtureWorkerSupervisor:
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
            "monitored_workers": 0,
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


def orchestration_approval_client(
    tmp_path: Path,
) -> tuple[FastAPI, str, dict[str, Any]]:
    database = tmp_path / "orchestration-approval-api.db"
    seed = b"\x07" * 32
    settings = runtime_settings(database)
    settings = Settings(**{**settings.__dict__, "policy_signing_key": seed})
    migrate(database)
    _, session = prepare_owned_fixture_session(
        database_path=database,
        source_store_path=tmp_path / "approval-sources",
        policy_signer=PolicySigner(seed),
    )
    with closing(sqlite3.connect(database)) as connection:
        assessment_id, policy_id, policy_hash = connection.execute(
            """SELECT e.id, e.active_policy_id, p.content_hash FROM engagements e
            JOIN policy_bundles p ON p.id = e.active_policy_id
            JOIN budget_reservations b ON b.engagement_id = e.id
            WHERE b.reservation_id = ?""",
            (session["reservation_id"],),
        ).fetchone()
    now = datetime.now(UTC).replace(microsecond=0).isoformat()
    DurablePlanGraphService(database).create(
        {
            "schema_version": "1.0.0",
            "plan_id": APPROVAL_PLAN,
            "assessment_id": assessment_id,
            "idempotency_key": "synthetic-authenticated-approval-plan",
            "revision": 1,
            "state": "active",
            "tasks": [
                {
                    "task_id": APPROVAL_TASK,
                    "task_type": "validation",
                    "objective": "Review synthetic authenticated approval metadata.",
                    "input_refs": [],
                    "requires_human_approval": True,
                    "state": "pending",
                    "revision": 1,
                    "created_at": now,
                    "updated_at": now,
                    "authority": "none",
                    "execution_enabled": False,
                }
            ],
            "dependencies": [],
            "created_at": now,
            "updated_at": now,
            "authority": "none",
            "execution_enabled": False,
        }
    )
    app = create_app(settings)
    credential = settings.launch_credential or ""
    resumed = app_request(
        app,
        "POST",
        "/api/v1/safety-state",
        authorization=f"Bearer {credential}",
        json_body={
            "status": "active",
            "reason": "Synthetic authenticated approval API fixture setup.",
        },
    )
    assert resumed.status_code == 200
    assessment_resumed = app_request(
        app,
        "POST",
        f"/api/v1/engagements/{assessment_id}/safety-state",
        authorization=f"Bearer {credential}",
        json_body={
            "status": "active",
            "reason": "Synthetic authenticated approval assessment setup.",
        },
    )
    assert assessment_resumed.status_code == 200
    return (
        app,
        credential,
        {
            "assessment_id": assessment_id,
            "expected_plan_revision": 1,
            "expected_task_revision": 1,
            "policy_bundle_id": policy_id,
            "policy_hash": policy_hash,
        },
    )


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
        ("POST", "/api/v1/workflows/unknown/findings"),
        ("GET", "/api/v1/workflows/unknown/findings"),
        ("GET", "/api/v1/findings/unknown"),
        ("GET", "/api/v1/findings/unknown/history"),
        ("POST", "/api/v1/findings/unknown/transition"),
        ("POST", "/api/v1/workflows/unknown/report-drafts"),
        ("GET", "/api/v1/report-drafts/unknown"),
        ("GET", "/api/v1/report-drafts/unknown/artifacts/json"),
        ("POST", "/api/v1/report-drafts/unknown/file-exports"),
        (
            "POST",
            "/api/v1/orchestration/plans/unknown/tasks/unknown/approval-request",
        ),
        ("POST", "/api/v1/orchestration/task-approval-requests/unknown/decision"),
        ("POST", "/api/v1/orchestration/task-approval-requests/unknown/consume"),
        ("POST", "/api/v1/ai/provider-registry-snapshots"),
        ("POST", "/api/v1/ai/provider-registry-snapshots/unknown/activate"),
        (
            "POST",
            "/api/v1/ai/provider-registry-activations/unknown/configuration-snapshots",
        ),
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


def test_registry_snapshot_uses_server_derived_authenticated_identity(tmp_path: Path) -> None:
    settings = runtime_settings(tmp_path / "registry-api.db")
    app = create_app(settings)
    now = datetime.now(UTC).replace(microsecond=0)
    registry_id = str(uuid4())
    safety = app_request(
        app,
        "POST",
        "/api/v1/safety-state",
        authorization=f"Bearer {settings.launch_credential}",
        json_body={"status": "active", "reason": "synthetic registry setup"},
    )
    assert safety.status_code == 200
    response = app_request(
        app,
        "POST",
        "/api/v1/ai/provider-registry-snapshots",
        authorization=f"Bearer {settings.launch_credential}",
        json_body={
            "command_id": str(uuid4()),
            "requested_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "registry": {
                "schema_version": "1.0.0",
                "registry_id": registry_id,
                "revision": 1,
                "providers": [
                    {
                        "provider_id": "local-synthetic",
                        "provider_type": "local_runtime",
                        "models": ["synthetic-model-q4"],
                        "allowed_input_classifications": ["public"],
                        "state": "enabled",
                    }
                ],
                "budget_ceilings": {
                    "max_input_tokens": 1000,
                    "max_output_tokens": 500,
                    "max_requests": 2,
                    "max_cost_microusd": 0,
                    "max_runtime_seconds": 30,
                },
                "remote_providers_enabled": False,
                "configured_at": (now - timedelta(minutes=1)).isoformat(),
                "expires_at": (now + timedelta(days=1)).isoformat(),
                "execution_enabled": False,
            },
        },
    )
    assert response.status_code == 200
    assert response.json()["requester"]["actor_id"] == "local-desktop-session"
    assert response.json()["authority"] == "none"
    assert response.json()["execution_enabled"] is False

    activation = app_request(
        app,
        "POST",
        f"/api/v1/ai/provider-registry-snapshots/{response.json()['snapshot_id']}/activate",
        authorization=f"Bearer {settings.launch_credential}",
        json_body={
            "command_id": str(uuid4()),
            "requested_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
        },
    )
    assert activation.status_code == 200
    assert activation.json()["requester"]["actor_id"] == "local-desktop-session"
    assert activation.json()["configuration_snapshot_enabled"] is False
    assert activation.json()["authority"] == "none"
    assert activation.json()["execution_enabled"] is False

    configuration = app_request(
        app,
        "POST",
        "/api/v1/ai/provider-registry-activations/"
        f"{activation.json()['activation_id']}/configuration-snapshots",
        authorization=f"Bearer {settings.launch_credential}",
        json_body={
            "command_id": str(uuid4()),
            "requested_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "configuration": {
                "schema_version": "1.0.0",
                "configuration_id": str(uuid4()),
                "provider_type": "local_runtime",
                "provider_id": "local-synthetic",
                "model_id": "synthetic-model-q4",
                "secret_ref": None,
                "privacy_classification": "local_device",
                "allowed_input_classifications": ["public"],
                "budgets": {
                    "max_input_tokens": 1000,
                    "max_output_tokens": 500,
                    "max_requests": 2,
                    "max_cost_microusd": 0,
                    "max_runtime_seconds": 30,
                },
                "remote_provider_opt_in": False,
                "configured_at": (now - timedelta(seconds=1)).isoformat(),
                "expires_at": (now + timedelta(hours=12)).isoformat(),
                "execution_enabled": False,
            },
        },
    )
    assert configuration.status_code == 200
    assert configuration.json()["requester"]["actor_id"] == "local-desktop-session"
    assert configuration.json()["state"] == "inactive"
    assert configuration.json()["authority"] == "none"
    assert configuration.json()["execution_enabled"] is False

    activation_injected = app_request(
        app,
        "POST",
        f"/api/v1/ai/provider-registry-snapshots/{response.json()['snapshot_id']}/activate",
        authorization=f"Bearer {settings.launch_credential}",
        json_body={
            "command_id": str(uuid4()),
            "requested_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "actor_id": "caller-selected",
        },
    )
    assert activation_injected.status_code == 422

    injected = app_request(
        app,
        "POST",
        "/api/v1/ai/provider-registry-snapshots",
        authorization=f"Bearer {settings.launch_credential}",
        json_body={
            "command_id": str(uuid4()),
            "requested_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "registry": {},
            "actor_id": "caller-selected",
        },
    )
    assert injected.status_code == 422


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
    supervisor = FixtureRuntimeSupervisor(state="degraded", reason_code="GATEWAY_WATCHDOG_FAILED")
    app = create_app(settings, runtime_supervisor=supervisor)
    credential = settings.launch_credential or ""
    readiness = app_request(app, "GET", "/api/v1/readiness", authorization=f"Bearer {credential}")
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

    readiness = app_request(app, "GET", "/api/v1/readiness", authorization=f"Bearer {credential}")
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
    readiness = app_request(app, "GET", "/api/v1/readiness", authorization=f"Bearer {credential}")
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
    shutdown = app_request(app, "POST", "/api/v1/shutdown", authorization=f"Bearer {credential}")
    assert shutdown.status_code == 200
    assert network_supervisor.starts == 1
    assert network_supervisor.stops == 1


def test_worker_supervisor_degradation_blocks_readiness_and_shutdown_stops_it(
    tmp_path: Path,
) -> None:
    settings = runtime_settings(tmp_path / "worker-degraded.db")
    worker_supervisor = FixtureWorkerSupervisor(
        state="degraded", reason_code="WORKER_RECOVERY_INCOMPLETE"
    )
    app = create_app(settings, worker_runtime_supervisor=worker_supervisor)
    credential = settings.launch_credential or ""
    readiness = app_request(app, "GET", "/api/v1/readiness", authorization=f"Bearer {credential}")
    assert readiness.status_code == 503
    assert readiness.json() == {
        "status": "degraded",
        "reason_code": "WORKER_RECOVERY_INCOMPLETE",
        "execution_enabled": False,
    }
    status = app_request(
        app,
        "GET",
        "/api/v1/worker-runtime-supervision",
        authorization=f"Bearer {credential}",
    )
    assert status.json()["watchdog_running"] is False
    shutdown = app_request(app, "POST", "/api/v1/shutdown", authorization=f"Bearer {credential}")
    assert shutdown.status_code == 200
    assert worker_supervisor.starts == 1
    assert worker_supervisor.stops == 1


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


def test_authenticated_orchestration_approval_derives_human_identity(tmp_path: Path) -> None:
    app, credential, create_body = orchestration_approval_client(tmp_path)
    created = app_request(
        app,
        "POST",
        f"/api/v1/orchestration/plans/{APPROVAL_PLAN}/tasks/{APPROVAL_TASK}/approval-request",
        authorization=f"Bearer {credential}",
        json_body=create_body,
    )
    assert created.status_code == 200
    request_document = created.json()
    assert request_document["schema_version"] == "2.0.0"
    assert request_document["requester"]["actor_type"] == "human"
    assert request_document["requester"]["actor_id"] == "local-desktop-session"
    assert request_document["requester"]["session_id"]
    assert request_document["authentication_context"] == "local_core_authenticated_session"

    decided = app_request(
        app,
        "POST",
        f"/api/v1/orchestration/task-approval-requests/{request_document['request_id']}/decision",
        authorization=f"Bearer {credential}",
        json_body={
            "decision": "approved",
            "reason": "Synthetic authenticated review complete.",
            "explicit_confirmation": True,
        },
    )
    assert decided.status_code == 200
    decision = decided.json()
    assert decision["schema_version"] == "2.0.0"
    assert decision["approver"]["actor_id"] == "local-desktop-session"
    assert decision["approver"]["session_id"] == request_document["requester"]["session_id"]
    assert decision["authentication_context"] == "local_core_authenticated_session"
    assert decision["resulting_task_state"] == "awaiting_human"
    assert decision["authority"] == "none" and decision["execution_enabled"] is False

    consumed = app_request(
        app,
        "POST",
        f"/api/v1/orchestration/task-approval-requests/{request_document['request_id']}/consume",
        authorization=f"Bearer {credential}",
        json_body={
            "consumption_id": "99999999-9999-4999-8999-999999999999",
            "decision_id": decision["decision_id"],
            "request_digest": "sha256:" + content_hash(request_document),
            "decision_digest": "sha256:" + content_hash(decision),
            "expected_plan_revision": 1,
            "expected_task_revision": 1,
        },
    )
    assert consumed.status_code == 200
    assert consumed.json()["resulting_task_state"] == "ready"
    assert consumed.json()["human_actor"]["actor_id"] == "local-desktop-session"
    assert consumed.json()["authority"] == "none"


def test_orchestration_approval_consumption_rejects_caller_identity_fields(tmp_path: Path) -> None:
    app, credential, create_body = orchestration_approval_client(tmp_path)
    response = app_request(
        app,
        "POST",
        "/api/v1/orchestration/task-approval-requests/unknown/consume",
        authorization=f"Bearer {credential}",
        json_body={
            "consumption_id": "99999999-9999-4999-8999-999999999999",
            "decision_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "request_digest": "sha256:" + "0" * 64,
            "decision_digest": "sha256:" + "1" * 64,
            "expected_plan_revision": 1,
            "expected_task_revision": 1,
            "approver_id": "forged-human",
        },
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "forged_field",
    ["approver_id", "requester", "authentication_context", "actor_type", "delegated_by"],
)
def test_orchestration_approval_rejects_caller_identity_fields(
    tmp_path: Path, forged_field: str
) -> None:
    app, credential, create_body = orchestration_approval_client(tmp_path)
    forged = {**create_body, forged_field: "forged-human"}
    response = app_request(
        app,
        "POST",
        f"/api/v1/orchestration/plans/{APPROVAL_PLAN}/tasks/{APPROVAL_TASK}/approval-request",
        authorization=f"Bearer {credential}",
        json_body=forged,
    )
    assert response.status_code == 422


def test_orchestration_approval_requires_explicit_confirmation(tmp_path: Path) -> None:
    app, credential, create_body = orchestration_approval_client(tmp_path)
    created = app_request(
        app,
        "POST",
        f"/api/v1/orchestration/plans/{APPROVAL_PLAN}/tasks/{APPROVAL_TASK}/approval-request",
        authorization=f"Bearer {credential}",
        json_body=create_body,
    ).json()
    cases = (
        ({"decision": "approved", "reason": "Synthetic missing confirmation."}, 422),
        (
            {
                "decision": "approved",
                "reason": "Synthetic false confirmation.",
                "explicit_confirmation": False,
            },
            409,
        ),
        (
            {
                "decision": "approved",
                "reason": "Synthetic forged actor.",
                "explicit_confirmation": True,
                "approver_id": "forged-human",
            },
            422,
        ),
    )
    for body, expected_status in cases:
        response = app_request(
            app,
            "POST",
            f"/api/v1/orchestration/task-approval-requests/{created['request_id']}/decision",
            authorization=f"Bearer {credential}",
            json_body=body,
        )
        assert response.status_code == expected_status


def test_report_draft_api_exposes_no_submission_capability(
    authenticated_client: tuple[FastAPI, str],
) -> None:
    app, _ = authenticated_client
    paths = {route.path for route in app.routes}
    assert not any("submit" in path or "submission" in path for path in paths)
    assert "/api/v1/workflows/{workflow_id}/report-drafts" in paths
    assert "/api/v1/report-drafts/{report_id}/artifacts/{format_name}" in paths
    assert "/api/v1/workflows/{workflow_id}/coverage" in paths
    assert "/api/v1/workflows/{workflow_id}/no-findings-report-drafts" in paths
    assert "/api/v1/no-findings-report-drafts/{report_id}/artifacts/{format_name}" in paths
    assert "/api/v1/report-drafts/{report_id}/export-approval" in paths
    assert "/api/v1/report-drafts/{report_id}/file-exports" in paths


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
