from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any, Protocol
from uuid import uuid4

from pentai_policy.document import content_hash, contract_issues

from pentai_core.network_attestation_adapters import HostRouteSnapshot


class HostNetworkProbe(Protocol):
    def inspect(self) -> HostRouteSnapshot: ...


class NetworkProfileSetupError(Exception):
    def __init__(self, code: str = "NETWORK_PROFILE_DISCOVERY_FAILED") -> None:
        super().__init__("Local network settings could not be discovered safely")
        self.code = code


class NetworkProfileSetupService:
    """Produces an expiring review proposal without creating network authority."""

    def __init__(
        self,
        probe: HostNetworkProbe,
        *,
        lifetime_seconds: int = 300,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1 <= lifetime_seconds <= 600:
            raise ValueError("proposal lifetime must be between 1 and 600 seconds")
        self._probe = probe
        self._lifetime = timedelta(seconds=lifetime_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))

    def discover(self) -> dict[str, Any]:
        try:
            snapshot = self._probe.inspect()
            interface = snapshot.interface.strip()
            if not interface or len(interface) > 128:
                raise ValueError("invalid interface")
            gateway = ip_address(snapshot.gateway).compressed if snapshot.gateway else None
            resolvers = tuple(
                sorted({ip_address(value).compressed for value in snapshot.resolver_addresses})
            )
            if not resolvers or len(resolvers) > 16:
                raise ValueError("invalid resolvers")
            clock_value = self._clock()
            if clock_value.tzinfo is None:
                raise ValueError("naive clock")
            observed_at = clock_value.astimezone(UTC)
            route_identity = {
                "interface": interface,
                "gateway": gateway,
                "resolver_addresses": resolvers,
            }
            proposal: dict[str, Any] = {
                "schema_version": "1.0.0",
                "proposal_id": str(uuid4()),
                "status": "needs_confirmation",
                "route_profile_id": f"route-{content_hash(route_identity)[:24]}",
                "route_interface": interface,
                "route_gateway": gateway,
                "resolver_id": f"resolver-{content_hash(resolvers)[:24]}",
                "resolver_addresses": list(resolvers),
                "registered_source_ipv4": [],
                "registered_source_ipv6": [],
                "ipv6_mode": "disabled",
                "requirements": [
                    "CONFIRM_ROUTE",
                    "CONFIRM_RESOLVER_MODE",
                    "ENTER_REGISTERED_SOURCE_IP",
                ],
                "observed_at": _timestamp(observed_at),
                "expires_at": _timestamp(observed_at + self._lifetime),
                "execution_enabled": False,
            }
            if contract_issues(proposal, "network-profile-proposal-v1.schema.json"):
                raise ValueError("invalid proposal")
            return proposal
        except NetworkProfileSetupError:
            raise
        except Exception as exc:
            raise NetworkProfileSetupError() from exc


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
