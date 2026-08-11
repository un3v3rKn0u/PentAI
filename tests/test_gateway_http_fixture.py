from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pentai_core.gateway_http_fixture import (
    GatewayHttpFixtureError,
    OciGatewayHttpFixtureTransport,
)
from pentai_core.runtime_snapshot_collector import CommandResult

RUNTIME = Path("/usr/local/bin/podman")
IMAGE = "sha256:" + "a" * 64
NETWORK = "fixture-network"


def containment(**updates: object) -> dict[str, object]:
    now = datetime.now(UTC)
    document: dict[str, object] = {
        "schema_version": "1.0.0",
        "attestation_id": "11111111-1111-4111-8111-111111111111",
        "runtime": "podman",
        "runtime_instance_id": "fixture-runtime",
        "rootless": True,
        "read_only_root": True,
        "capabilities_dropped": True,
        "no_new_privileges": True,
        "host_pid_disabled": True,
        "host_ipc_disabled": True,
        "host_network_disabled": True,
        "runtime_socket_mounted": False,
        "resource_limits_supported": True,
        "temporary_mounts_only": True,
        "gateway_network_id": NETWORK,
        "direct_egress_disabled": True,
        "external_dns_disabled": True,
        "ipv6_disabled": True,
        "observed_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
    }
    document.update(updates)
    return document


@dataclass
class FixtureExecutor:
    result: CommandResult
    calls: list[tuple[tuple[str, ...], float, int]] = field(default_factory=list)

    def execute(
        self, argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
    ) -> CommandResult:
        self.calls.append((argv, timeout_seconds, max_output_bytes))
        return self.result


def output(
    outcome: object = "completed", observed: object = 17, retained: object = 17
) -> CommandResult:
    return CommandResult(
        0,
        json.dumps(
            {
                "outcome": outcome,
                "observed_response_bytes": observed,
                "retained_response_bytes": retained,
            }
        ).encode(),
    )


def test_fixture_transport_uses_only_fixed_contained_http_arguments() -> None:
    executor = FixtureExecutor(output())
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME, image_digest=IMAGE, executor=executor
    )

    measurement = transport.execute(
        network_id=NETWORK,
        containment=containment(),
        maximum_response_bytes=32,
        timeout_milliseconds=500,
    )

    assert measurement.outcome == "completed"
    assert measurement.observed_response_bytes == 17
    command, timeout, output_limit = executor.calls[0]
    assert command[:3] == (str(RUNTIME), "run", "--rm")
    assert "--network" in command
    assert NETWORK in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--target=192.0.2.20:8080" in command
    assert "--host=example.test" in command
    assert "--path=/fixture" in command
    assert (timeout, output_limit) == (2.5, 4096)


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        (output(outcome="unknown"), "HTTP_FIXTURE_INVALID"),
        (output(observed=True, retained=True), "HTTP_FIXTURE_INVALID"),
        (
            output(outcome="response_limit_exceeded", observed=32, retained=32),
            "HTTP_FIXTURE_INVALID",
        ),
        (output(observed=33, retained=32), "HTTP_FIXTURE_INVALID"),
        (CommandResult(0, b"not-json"), "HTTP_FIXTURE_INVALID"),
        (CommandResult(1, b""), "HTTP_FIXTURE_FAILED"),
    ],
)
def test_fixture_transport_rejects_malformed_or_contradictory_output(
    document: CommandResult, expected: str
) -> None:
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        image_digest=IMAGE,
        executor=FixtureExecutor(document),
    )
    with pytest.raises(GatewayHttpFixtureError) as raised:
        transport.execute(
            network_id=NETWORK,
            containment=containment(),
            maximum_response_bytes=32,
            timeout_milliseconds=500,
        )
    assert raised.value.code == expected


@pytest.mark.parametrize(
    ("network", "limit", "timeout"),
    [
        ("bad/network", 32, 500),
        (NETWORK, 0, 500),
        (NETWORK, 1_048_577, 500),
        (NETWORK, 32, 0),
        (NETWORK, 32, 5_001),
    ],
)
def test_fixture_transport_denies_unbounded_or_unsafe_inputs(
    network: str, limit: int, timeout: int
) -> None:
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME, image_digest=IMAGE, executor=FixtureExecutor(output())
    )
    with pytest.raises(GatewayHttpFixtureError, match="fixture bounds are invalid"):
        transport.execute(
            network_id=network,
            containment=containment(),
            maximum_response_bytes=limit,
            timeout_milliseconds=timeout,
        )


def test_fixture_transport_requires_fresh_matching_containment() -> None:
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME, image_digest=IMAGE, executor=FixtureExecutor(output())
    )
    for evidence in (
        containment(gateway_network_id="other-network"),
        containment(rootless=False),
        {},
    ):
        with pytest.raises(GatewayHttpFixtureError) as raised:
            transport.execute(
                network_id=NETWORK,
                containment=evidence,
                maximum_response_bytes=32,
                timeout_milliseconds=500,
            )
        assert raised.value.code == "HTTP_FIXTURE_CONTAINMENT_DENIED"
