from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from pentai_policy import CanonicalizationError, canonicalize_domain, canonicalize_ip


class ControlledDnsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RawDnsAnswer:
    addresses: tuple[str, ...]
    cname_chain: tuple[str, ...] = ()


@dataclass(frozen=True)
class ControlledDnsAnswer:
    hostname: str
    addresses: tuple[str, ...]
    cname_chain: tuple[str, ...]
    resolver_id: str


class ResolverBackend(Protocol):
    def resolve(self, hostname: str, port: int) -> RawDnsAnswer: ...


class ControlledResolver:
    def __init__(
        self,
        backend: ResolverBackend,
        *,
        resolver_mode: str,
        resolver_id: str,
        maximum_answers: int = 16,
        maximum_cnames: int = 8,
    ) -> None:
        if resolver_mode not in {"tunnel_resolver", "approved_resolver"}:
            raise ControlledDnsError("DNS_RESOLVER_INVALID", "resolver mode is invalid")
        if not resolver_id.strip():
            raise ControlledDnsError("DNS_RESOLVER_INVALID", "resolver identity is required")
        self._backend = backend
        self.resolver_mode = resolver_mode
        self.resolver_id = resolver_id.strip()
        self.maximum_answers = maximum_answers
        self.maximum_cnames = maximum_cnames

    def resolve(
        self, hostname: str, port: int, *, attestation: dict[str, object]
    ) -> ControlledDnsAnswer:
        if (
            attestation.get("resolver_mode") != self.resolver_mode
            or attestation.get("resolver_id") != self.resolver_id
        ):
            raise ControlledDnsError(
                "DNS_ATTESTATION_MISMATCH", "resolver does not match network attestation"
            )
        try:
            canonical_hostname = canonicalize_domain(hostname)
        except CanonicalizationError as exc:
            raise ControlledDnsError("DNS_NAME_INVALID", "DNS name is invalid") from exc
        if not 1 <= port <= 65535:
            raise ControlledDnsError("DNS_PORT_INVALID", "destination port is invalid")
        answer = self._backend.resolve(canonical_hostname, port)
        if not answer.addresses or len(answer.addresses) > self.maximum_answers:
            raise ControlledDnsError("DNS_ANSWER_INVALID", "DNS answer count is invalid")
        if len(answer.cname_chain) > self.maximum_cnames:
            raise ControlledDnsError("DNS_CNAME_LIMIT", "DNS CNAME chain is too long")
        try:
            addresses = tuple(
                sorted({canonicalize_ip(value)["value"] for value in answer.addresses})
            )
            cnames = tuple(canonicalize_domain(value) for value in answer.cname_chain)
        except CanonicalizationError as exc:
            raise ControlledDnsError("DNS_ANSWER_INVALID", "DNS answer is malformed") from exc
        if len(addresses) != len(answer.addresses) or len(set(cnames)) != len(cnames):
            raise ControlledDnsError("DNS_ANSWER_INVALID", "DNS answer contains duplicates")
        return ControlledDnsAnswer(
            hostname=canonical_hostname,
            addresses=addresses,
            cname_chain=cnames,
            resolver_id=self.resolver_id,
        )
