from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from pentai_core.network_attestation_adapters import HostRouteSnapshot
from pentai_core.network_profile_setup import (
    NetworkProfileSetupError,
    NetworkProfileSetupService,
)
from pentai_policy.document import contract_issues


@dataclass
class FixtureProbe:
    snapshot: HostRouteSnapshot | None = HostRouteSnapshot(
        " utun7 ", "192.0.2.1", ("2001:0db8::53", "192.0.2.53", "192.0.2.53")
    )
    failure: Exception | None = None

    def inspect(self) -> HostRouteSnapshot:
        if self.failure is not None:
            raise self.failure
        assert self.snapshot is not None
        return self.snapshot


def service(probe: FixtureProbe) -> NetworkProfileSetupService:
    return NetworkProfileSetupService(
        probe,
        clock=lambda: datetime(2026, 8, 10, 12, 0, tzinfo=UTC),
    )


def test_proposal_is_contract_valid_deterministic_and_non_authoritative() -> None:
    setup = service(FixtureProbe())

    first = setup.discover()
    second = setup.discover()

    assert contract_issues(first, "network-profile-proposal-v1.schema.json") == ()
    assert first["proposal_id"] != second["proposal_id"]
    assert first["route_profile_id"] == second["route_profile_id"]
    assert first["resolver_id"] == second["resolver_id"]
    assert first["route_interface"] == "utun7"
    assert first["route_gateway"] == "192.0.2.1"
    assert first["resolver_addresses"] == ["192.0.2.53", "2001:db8::53"]
    assert first["registered_source_ipv4"] == []
    assert first["registered_source_ipv6"] == []
    assert first["execution_enabled"] is False
    assert first["expires_at"] == "2026-08-10T12:05:00.000000Z"


@pytest.mark.parametrize(
    "snapshot",
    [
        HostRouteSnapshot("", None, ("192.0.2.53",)),
        HostRouteSnapshot("x" * 129, None, ("192.0.2.53",)),
        HostRouteSnapshot("utun7", "not-an-ip", ("192.0.2.53",)),
        HostRouteSnapshot("utun7", None, ()),
        HostRouteSnapshot("utun7", None, ("fe80::1%utun7",)),
        HostRouteSnapshot("utun7", None, tuple(f"192.0.2.{value}" for value in range(1, 18))),
    ],
)
def test_invalid_or_ambiguous_observation_fails_closed(snapshot: HostRouteSnapshot) -> None:
    with pytest.raises(NetworkProfileSetupError) as raised:
        service(FixtureProbe(snapshot=snapshot)).discover()

    assert raised.value.code == "NETWORK_PROFILE_DISCOVERY_FAILED"
    assert str(raised.value) == "Local network settings could not be discovered safely"


def test_probe_details_are_not_exposed() -> None:
    with pytest.raises(NetworkProfileSetupError) as raised:
        service(FixtureProbe(failure=RuntimeError("secret command output"))).discover()

    assert "secret" not in str(raised.value)


def test_lifetime_is_bounded_and_clock_must_be_aware() -> None:
    with pytest.raises(ValueError):
        NetworkProfileSetupService(FixtureProbe(), lifetime_seconds=601)
    setup = NetworkProfileSetupService(
        FixtureProbe(), clock=lambda: datetime(2026, 8, 10, 12, 0)
    )
    with pytest.raises(NetworkProfileSetupError):
        setup.discover()
