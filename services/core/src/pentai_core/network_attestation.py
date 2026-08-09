from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from pentai_policy import CanonicalizationError, canonicalize_ip


class AttestationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RouteSnapshot:
    route_profile_id: str
    resolver_mode: str
    resolver_id: str


@dataclass(frozen=True)
class SourceObservation:
    endpoint_id: str
    source_ipv4: str | None = None
    source_ipv6: str | None = None


class SourceObserver(Protocol):
    def observe(self) -> SourceObservation: ...


class RouteInspector(Protocol):
    def inspect(self) -> RouteSnapshot: ...


class NetworkAttestor:
    def __init__(
        self,
        observers: tuple[SourceObserver, ...],
        route_inspector: RouteInspector,
        *,
        lifetime_seconds: int = 30,
    ) -> None:
        if len(observers) < 2:
            raise AttestationError(
                "ATTESTATION_ENDPOINTS_INSUFFICIENT",
                "at least two independent source observers are required",
            )
        if not 1 <= lifetime_seconds <= 60:
            raise AttestationError(
                "ATTESTATION_LIFETIME_INVALID", "attestation lifetime must be 1–60 seconds"
            )
        self._observers = observers
        self._route_inspector = route_inspector
        self._lifetime_seconds = lifetime_seconds

    def measure(
        self,
        *,
        assessment_id: str,
        policy_hash: str,
        now: datetime | None = None,
    ) -> dict[str, object]:
        measured_at = now or datetime.now(UTC)
        try:
            route = self._route_inspector.inspect()
        except Exception as exc:
            raise AttestationError(
                "ATTESTATION_ROUTE_FAILED", "route identity inspection failed"
            ) from exc
        if (
            not route.route_profile_id.strip()
            or route.resolver_mode not in {"tunnel_resolver", "approved_resolver"}
            or not route.resolver_id.strip()
        ):
            raise AttestationError("ATTESTATION_ROUTE_INVALID", "route snapshot is invalid")
        try:
            observations = tuple(observer.observe() for observer in self._observers)
        except Exception as exc:
            raise AttestationError(
                "ATTESTATION_OBSERVATION_FAILED", "source identity observation failed"
            ) from exc
        endpoint_ids = [item.endpoint_id.strip() for item in observations]
        if any(not endpoint_id for endpoint_id in endpoint_ids) or len(set(endpoint_ids)) != len(
            endpoint_ids
        ):
            raise AttestationError(
                "ATTESTATION_ENDPOINTS_INVALID", "source observers must have unique identities"
            )
        normalized = [self._normalize(item) for item in observations]
        identities = {(item.source_ipv4, item.source_ipv6) for item in normalized}
        if len(identities) != 1:
            raise AttestationError(
                "ATTESTATION_DISAGREEMENT", "source observers reported different identities"
            )
        source_ipv4, source_ipv6 = identities.pop()
        if source_ipv4 is None and source_ipv6 is None:
            raise AttestationError("ATTESTATION_EMPTY", "source identity was not observed")
        document: dict[str, object] = {
            "schema_version": "1.0.0",
            "attestation_id": str(uuid4()),
            "assessment_id": assessment_id,
            "policy_hash": policy_hash,
            "route_profile_id": route.route_profile_id,
            "resolver_mode": route.resolver_mode,
            "resolver_id": route.resolver_id,
            "observations": endpoint_ids,
            "observed_at": measured_at.isoformat().replace("+00:00", "Z"),
            "expires_at": (measured_at + timedelta(seconds=self._lifetime_seconds))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        if source_ipv4 is not None:
            document["source_ipv4"] = source_ipv4
        if source_ipv6 is not None:
            document["source_ipv6"] = source_ipv6
        return document

    @staticmethod
    def _normalize(observation: SourceObservation) -> SourceObservation:
        try:
            ipv4 = (
                canonicalize_ip(observation.source_ipv4)["value"]
                if observation.source_ipv4 is not None
                else None
            )
            ipv6 = (
                canonicalize_ip(observation.source_ipv6)["value"]
                if observation.source_ipv6 is not None
                else None
            )
        except CanonicalizationError as exc:
            raise AttestationError(
                "ATTESTATION_ADDRESS_INVALID", "source observer returned an invalid address"
            ) from exc
        if ipv4 is not None and ":" in ipv4:
            raise AttestationError("ATTESTATION_ADDRESS_INVALID", "IPv4 observation is not IPv4")
        if ipv6 is not None and ":" not in ipv6:
            raise AttestationError("ATTESTATION_ADDRESS_INVALID", "IPv6 observation is not IPv6")
        return SourceObservation(observation.endpoint_id.strip(), ipv4, ipv6)
