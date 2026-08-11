from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol
from urllib.parse import urlsplit

from pentai_core.config import Settings
from pentai_core.network_attestation import NetworkAttestor
from pentai_core.network_attestation_adapters import (
    ExactRouteInspector,
    HttpsSourceObserver,
    ObservationTransport,
    RouteProbe,
    SystemRouteProbe,
)
from pentai_core.network_safety_supervisor import (
    AuthorizationNetworkIdentityMonitor,
    NetworkSafetySnapshot,
    NetworkSafetySupervisor,
    NetworkSafetySupervisorControl,
    UnconfiguredNetworkSafetySupervisor,
)


class NetworkSafetyControl(Protocol):
    def has_network_authority(self) -> bool: ...

    def network_authority_assessments(self) -> tuple[str, ...]: ...

    def network_profile_for_assessment(self, engagement_id: str) -> dict[str, Any]: ...

    def verify_network_identity(
        self, engagement_id: str, *, attestor: Any, attestor_id: str
    ) -> dict[str, Any]: ...

    def set_global_safety(
        self, *, status: str, reason: str, actor_id: str
    ) -> dict[str, Any]: ...


class UnavailableConfiguredNetworkSafetySupervisor:
    def __init__(self, *, pause_safety: Callable[[str], Any]) -> None:
        self._pause_safety = pause_safety
        self._reason: str | None = None

    def start(self) -> None:
        reason = "NETWORK_ATTESTATION_COMPOSITION_FAILED"
        try:
            self._pause_safety(reason)
        except Exception:
            reason = "NETWORK_SAFETY_PAUSE_FAILED"
        self._reason = reason

    def stop(self) -> None:
        return

    def status(self) -> dict[str, object]:
        return NetworkSafetySnapshot(
            "degraded", self._reason or "NETWORK_ATTESTATION_COMPOSITION_FAILED", 0, False
        ).document()


def compose_network_safety_supervisor(
    *,
    settings: Settings,
    safety_control: NetworkSafetyControl,
    transport: ObservationTransport | None = None,
    route_probe: RouteProbe | None = None,
) -> NetworkSafetySupervisorControl:
    def pause_safety(reason: str) -> dict[str, Any]:
        return safety_control.set_global_safety(
            status="paused", reason=reason, actor_id="network-safety-supervisor"
        )

    if not settings.network_attestation_enabled:
        return UnconfiguredNetworkSafetySupervisor(
            authority_exists=safety_control.has_network_authority,
            pause_safety=pause_safety,
        )
    try:
        observers = _observers(
            settings.network_observers,
            settings.network_observer_timeout_seconds,
            transport,
        )
        probe = route_probe or SystemRouteProbe(
            timeout_seconds=settings.network_route_timeout_seconds
        )

        def attestor_for(assessment_id: str) -> NetworkAttestor:
            profile = safety_control.network_profile_for_assessment(assessment_id)
            inspector = ExactRouteInspector(
                probe=probe,
                route_profile_id=str(profile["route_profile_id"]),
                expected_interface=str(profile["route_interface"]),
                expected_gateway=profile["route_gateway"],
                resolver_mode=str(profile["resolver_mode"]),
                resolver_id=str(profile["resolver_id"]),
                expected_resolvers=tuple(profile["resolver_addresses"]),
            )
            return NetworkAttestor(observers, inspector)

        monitor = AuthorizationNetworkIdentityMonitor(
            control=safety_control,
            attestor_for=attestor_for,
            attestor_id="system-network-attestor",
        )
        return NetworkSafetySupervisor(
            monitor=monitor,
            pause_safety=pause_safety,
            interval_seconds=settings.network_watchdog_interval_seconds,
        )
    except Exception:
        return UnavailableConfiguredNetworkSafetySupervisor(pause_safety=pause_safety)


def _observers(
    specifications: tuple[str, ...],
    timeout_seconds: float,
    transport: ObservationTransport | None,
) -> tuple[HttpsSourceObserver, ...]:
    parsed: list[tuple[str, str, str]] = []
    for specification in specifications:
        parts = specification.split("|", 2)
        if len(parts) != 3:
            raise ValueError("network observer specification is invalid")
        parsed.append((parts[0], parts[1], parts[2]))
    endpoint_ids = [item[0] for item in parsed]
    origins = [(urlsplit(item[2]).hostname, urlsplit(item[2]).port) for item in parsed]
    if len(set(endpoint_ids)) != len(endpoint_ids) or len(set(origins)) != len(origins):
        raise ValueError("network observers must have unique identities and origins")
    return tuple(
        HttpsSourceObserver(
            endpoint_id=endpoint_id,
            address_family=address_family,
            url=url,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )
        for endpoint_id, address_family, url in parsed
    )
