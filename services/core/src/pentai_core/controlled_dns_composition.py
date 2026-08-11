from __future__ import annotations

from ipaddress import ip_address
from typing import Any, Protocol

from pentai_core.config import Settings
from pentai_core.controlled_dns import ControlledResolver
from pentai_core.controlled_dns_transport import DnsWireTransport, PinnedDnsBackend


class NetworkProfileControl(Protocol):
    def network_profile_for_assessment(self, engagement_id: str) -> dict[str, Any]: ...


class ControlledResolverProvider:
    """Build a resolver from the current policy-bound profile for each assessment."""

    def __init__(
        self,
        *,
        settings: Settings,
        profile_control: NetworkProfileControl,
        transport: DnsWireTransport | None = None,
    ) -> None:
        self._settings = settings
        self._profile_control = profile_control
        self._transport = transport

    def for_assessment(self, assessment_id: str) -> ControlledResolver:
        profile = self._profile_control.network_profile_for_assessment(assessment_id)
        server_ip = self._settings.controlled_dns_server_ip
        if server_ip is None:
            raise ValueError("controlled DNS transport is incomplete")
        try:
            server = ip_address(server_ip).compressed
            allowed = {ip_address(value).compressed for value in profile["resolver_addresses"]}
            resolver_mode = str(profile["resolver_mode"])
            resolver_id = str(profile["resolver_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("network profile resolver binding is invalid") from exc
        if server not in allowed:
            raise ValueError("controlled DNS server is absent from the active network profile")
        tls_hostname = self._settings.controlled_dns_tls_hostname
        if (resolver_mode == "tunnel_resolver" and tls_hostname is not None) or (
            resolver_mode == "approved_resolver" and tls_hostname is None
        ):
            raise ValueError("controlled DNS transport does not match the active network profile")
        backend = PinnedDnsBackend(
            resolver_mode=resolver_mode,
            server_ip=server,
            tls_hostname=tls_hostname,
            timeout_seconds=self._settings.controlled_dns_timeout_seconds,
            transport=self._transport,
        )
        return ControlledResolver(backend, resolver_mode=resolver_mode, resolver_id=resolver_id)


def compose_controlled_resolver_provider(
    *,
    settings: Settings,
    profile_control: NetworkProfileControl,
    transport: DnsWireTransport | None = None,
) -> ControlledResolverProvider | None:
    if not settings.controlled_dns_enabled:
        return None
    return ControlledResolverProvider(
        settings=settings, profile_control=profile_control, transport=transport
    )
