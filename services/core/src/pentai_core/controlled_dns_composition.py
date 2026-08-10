from __future__ import annotations

from pentai_core.config import Settings
from pentai_core.controlled_dns import ControlledResolver
from pentai_core.controlled_dns_transport import DnsWireTransport, PinnedDnsBackend


def compose_controlled_resolver(
    *, settings: Settings, transport: DnsWireTransport | None = None
) -> ControlledResolver | None:
    if not settings.controlled_dns_enabled:
        return None
    server_ip = settings.controlled_dns_server_ip
    resolver_mode = settings.network_resolver_mode
    resolver_id = settings.network_resolver_id
    if server_ip is None or resolver_mode is None or resolver_id is None:
        raise ValueError("controlled DNS configuration is incomplete")
    backend = PinnedDnsBackend(
        resolver_mode=resolver_mode,
        server_ip=server_ip,
        tls_hostname=settings.controlled_dns_tls_hostname,
        timeout_seconds=settings.controlled_dns_timeout_seconds,
        transport=transport,
    )
    return ControlledResolver(
        backend,
        resolver_mode=resolver_mode,
        resolver_id=resolver_id,
    )
