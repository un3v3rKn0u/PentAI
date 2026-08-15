from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pentai_core.gateway_http_fixture import (
    GatewayHttpFixtureError,
    GatewayHttpFixtureExecution,
    OciGatewayHttpFixtureTransport,
)
from pentai_core.policy_signing import (
    PolicySigner,
    gateway_fixture_execution_claim_v2_payload,
)
from pentai_core.runtime_snapshot_collector import CommandResult, SnapshotCollectionError
from pentai_policy.document import contract_issues

RUNTIME = Path("/usr/local/bin/podman")
IMAGE = "sha256:" + "a" * 64
NETWORK = "fixture-network"
SIGNER = PolicySigner(b"f" * 32)
VERIFIER = SIGNER.verifier()


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


def claim(**updates: object) -> dict[str, object]:
    now = datetime.now(UTC)
    document: dict[str, object] = {
        "schema_version": "2.0.0",
        "claim_id": "22222222-2222-4222-8222-222222222222",
        "start_id": "33333333-3333-4333-8333-333333333333",
        "session_id": "44444444-4444-4444-8444-444444444444",
        "runtime_id": "55555555-5555-4555-8555-555555555555",
        "containment_attestation_id": "11111111-1111-4111-8111-111111111111",
        "gateway_network_id": NETWORK,
        "image_digest": IMAGE,
        "method": "GET",
        "target_ip": "192.0.2.20",
        "port": 8080,
        "host": "example.test",
        "path": "/fixture",
        "response_bytes_limit": 32,
        "deadline_at": (now + timedelta(seconds=4)).isoformat().replace("+00:00", "Z"),
        "claimed_at": now.isoformat().replace("+00:00", "Z"),
        "status": "claimed",
        "fixture_execution_enabled": True,
        "external_execution_enabled": False,
    }
    document.update(updates)
    document["signature"] = {
        "algorithm": "Ed25519",
        "key_id": SIGNER.key_id,
        "value": SIGNER.sign(gateway_fixture_execution_claim_v2_payload(document)),
    }
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


def test_signed_claim_uses_v2_without_breaking_unsigned_v1_contract() -> None:
    signed_v2 = claim()
    assert contract_issues(signed_v2, "gateway-fixture-execution-claim-v2.schema.json") == ()
    assert contract_issues(signed_v2, "gateway-fixture-execution-claim-v1.schema.json")

    unsigned_v1 = {key: value for key, value in signed_v2.items() if key != "signature"}
    unsigned_v1["schema_version"] = "1.0.0"
    assert contract_issues(unsigned_v1, "gateway-fixture-execution-claim-v1.schema.json") == ()
    assert contract_issues(unsigned_v1, "gateway-fixture-execution-claim-v2.schema.json")


def test_fixture_transport_uses_only_fixed_contained_http_arguments() -> None:
    now = datetime.now(UTC)
    executor = FixtureExecutor(output())
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        executor=executor,
        pause_safety=lambda _reason: None,
        claim_verifier=VERIFIER,
        clock=lambda: now,
    )

    measurement = transport.execute(
        claim=claim(deadline_at=(now + timedelta(seconds=2)).isoformat()),
        containment=containment(),
    )

    assert measurement.outcome == "completed"
    assert measurement.observed_response_bytes == 17
    command, timeout, output_limit = executor.calls[0]
    assert command[:4] == (str(RUNTIME), "run", "--log-driver=none", "--rm")
    assert "--name" in command
    assert f"pentai-fixture-{claim()['claim_id']}" in command
    assert "--label=com.pentai.managed=true" in command
    assert "--label=com.pentai.role=gateway-http-fixture" in command
    assert f"--label=com.pentai.execution-claim={claim()['claim_id']}" in command
    assert f"--label=com.pentai.runtime-id={claim()['runtime_id']}" in command
    assert f"--label=com.pentai.gateway-network={NETWORK}" in command
    assert f"--label=com.pentai.image-digest={IMAGE}" in command
    assert "--network" in command
    assert NETWORK in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--target=192.0.2.20:8080" in command
    assert "--host=example.test" in command
    assert "--path=/fixture" in command
    assert any(item.startswith("--deadline-unix-milliseconds=") for item in command)
    assert any(item.startswith("--claim-payload=") for item in command)
    assert any(item.startswith("--claim-signature=") for item in command)
    assert timeout == pytest.approx(2, abs=0.001)
    assert output_limit == 4096


def test_fixture_transport_maps_host_timeout_to_deadline_denial() -> None:
    @dataclass
    class TimeoutExecutor:
        cleanup_returncode: int = 0
        calls: list[tuple[tuple[str, ...], float, int]] = field(default_factory=list)

        def execute(
            self, argv: tuple[str, ...], *, timeout_seconds: float, max_output_bytes: int
        ) -> CommandResult:
            self.calls.append((argv, timeout_seconds, max_output_bytes))
            if len(self.calls) == 1:
                raise SnapshotCollectionError("RUNTIME_COMMAND_TIMEOUT", "synthetic timeout")
            return CommandResult(self.cleanup_returncode, b"")

    executor = TimeoutExecutor()
    successful_cleanup_pauses: list[str] = []
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        executor=executor,
        pause_safety=successful_cleanup_pauses.append,
        claim_verifier=VERIFIER,
    )
    with pytest.raises(GatewayHttpFixtureError) as raised:
        transport.execute(claim=claim(), containment=containment())
    assert raised.value.code == "HTTP_FIXTURE_DEADLINE"
    assert executor.calls[1] == (
        (
            str(RUNTIME),
            "rm",
            "--force",
            f"pentai-fixture-{claim()['claim_id']}",
        ),
        2,
        4096,
    )
    assert successful_cleanup_pauses == []

    pauses: list[str] = []
    failed_cleanup = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        executor=TimeoutExecutor(cleanup_returncode=1),
        pause_safety=pauses.append,
        claim_verifier=VERIFIER,
    )
    with pytest.raises(GatewayHttpFixtureError) as cleanup_failed:
        failed_cleanup.execute(claim=claim(), containment=containment())
    assert cleanup_failed.value.code == "HTTP_FIXTURE_CLEANUP_FAILED"
    assert pauses == ["GATEWAY_FIXTURE_CLEANUP_FAILED"]

    failed_pause = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        executor=TimeoutExecutor(cleanup_returncode=1),
        pause_safety=lambda _reason: (_ for _ in ()).throw(RuntimeError("private")),
        claim_verifier=VERIFIER,
    )
    with pytest.raises(GatewayHttpFixtureError) as pause_failed:
        failed_pause.execute(claim=claim(), containment=containment())
    assert pause_failed.value.code == "HTTP_FIXTURE_SAFETY_PAUSE_FAILED"


def test_fixture_transport_reclassifies_completion_observed_after_deadline() -> None:
    now = datetime.now(UTC)
    observations = iter((now, now + timedelta(seconds=2)))
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        executor=FixtureExecutor(output()),
        pause_safety=lambda _reason: None,
        claim_verifier=VERIFIER,
        clock=lambda: next(observations),
    )
    measurement = transport.execute(
        claim=claim(deadline_at=(now + timedelta(seconds=1)).isoformat()),
        containment=containment(),
    )
    assert measurement.outcome == "deadline_exceeded"


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
        executor=FixtureExecutor(document),
        pause_safety=lambda _reason: None,
        claim_verifier=VERIFIER,
    )
    with pytest.raises(GatewayHttpFixtureError) as raised:
        transport.execute(
            claim=claim(),
            containment=containment(),
        )
    assert raised.value.code == expected


@pytest.mark.parametrize(
    ("claim_updates", "containment_updates"),
    [
        ({"gateway_network_id": "bad/network"}, {}),
        ({"response_bytes_limit": 0}, {}),
        ({"response_bytes_limit": 1_048_577}, {}),
        ({"target_ip": "192.0.2.21"}, {}),
        ({"external_execution_enabled": True}, {}),
    ],
)
def test_fixture_transport_denies_unbounded_or_unsafe_inputs(
    claim_updates: dict[str, object], containment_updates: dict[str, object]
) -> None:
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        executor=FixtureExecutor(output()),
        pause_safety=lambda _reason: None,
        claim_verifier=VERIFIER,
    )
    with pytest.raises(GatewayHttpFixtureError):
        transport.execute(
            claim=claim(**claim_updates),
            containment=containment(**containment_updates),
        )


def test_fixture_transport_requires_fresh_matching_containment() -> None:
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        executor=FixtureExecutor(output()),
        pause_safety=lambda _reason: None,
        claim_verifier=VERIFIER,
    )
    for evidence in (
        containment(gateway_network_id="other-network"),
        containment(rootless=False),
        {},
    ):
        with pytest.raises(GatewayHttpFixtureError) as raised:
            transport.execute(
                claim=claim(),
                containment=evidence,
            )
        assert raised.value.code == "HTTP_FIXTURE_CONTAINMENT_DENIED"


def test_fixture_transport_denies_claim_mutation_before_runtime_launch() -> None:
    executor = FixtureExecutor(output())
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        executor=executor,
        pause_safety=lambda _reason: None,
        claim_verifier=VERIFIER,
    )
    issued_claim = claim()
    issued_claim["response_bytes_limit"] = 64

    with pytest.raises(GatewayHttpFixtureError) as raised:
        transport.execute(claim=issued_claim, containment=containment())

    assert raised.value.code == "HTTP_FIXTURE_DENIED"
    assert executor.calls == []


def test_fixture_transport_denies_claim_from_untrusted_public_key() -> None:
    executor = FixtureExecutor(output())
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        executor=executor,
        pause_safety=lambda _reason: None,
        claim_verifier=PolicySigner(b"g" * 32).verifier(),
    )

    with pytest.raises(GatewayHttpFixtureError) as raised:
        transport.execute(claim=claim(), containment=containment())

    assert raised.value.code == "HTTP_FIXTURE_DENIED"
    assert executor.calls == []


@dataclass
class FixtureAuthority:
    issued_claim: dict[str, object]
    calls: list[tuple[str, object]] = field(default_factory=list)

    def claim_gateway_fixture_execution(
        self, start_id: str, *, containment: dict[str, object]
    ) -> dict[str, object]:
        self.calls.append(("claim", (start_id, containment)))
        return self.issued_claim

    def finalize_gateway_request(
        self,
        start_id: str,
        measurement: object,
        *,
        execution_claim_id: str | None = None,
    ) -> dict[str, object]:
        self.calls.append(("finalize", (start_id, measurement, execution_claim_id)))
        return {"status": "completed"}


def test_fixture_execution_claims_before_transport_and_binds_finalization() -> None:
    authority = FixtureAuthority(claim())
    transport = OciGatewayHttpFixtureTransport(
        executable=RUNTIME,
        executor=FixtureExecutor(output()),
        pause_safety=lambda _reason: None,
        claim_verifier=VERIFIER,
    )
    execution = GatewayHttpFixtureExecution(authority=authority, transport=transport)

    result = execution.execute(str(authority.issued_claim["start_id"]), containment=containment())

    assert result == {"status": "completed"}
    assert [call[0] for call in authority.calls] == ["claim", "finalize"]
    assert authority.calls[1][1][2] == authority.issued_claim["claim_id"]
