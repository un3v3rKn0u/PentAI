from __future__ import annotations

import ipaddress
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from pentai_policy import (
    CanonicalizationError,
    canonicalize_domain,
    canonicalize_ip,
    canonicalize_url,
)
from pentai_policy.document import parse_time
from pentai_policy.evaluator import evaluate

_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _destination_address(value: str, *, fixture_resolver: bool) -> str:
    canonical = canonicalize_ip(value)["value"]
    address = ipaddress.ip_address(canonical)
    if fixture_resolver and any(address in network for network in _DOCUMENTATION_NETWORKS):
        return canonical
    if not address.is_global:
        raise ValueError("DNS_SPECIAL_ADDRESS")
    return canonical


def _canonical_host(value: str) -> str:
    try:
        return canonicalize_ip(value)["value"]
    except CanonicalizationError:
        return canonicalize_domain(value)


def validate_attestation(
    attestation: dict[str, Any], policy: dict[str, Any], *, now: datetime | None = None
) -> None:
    instant = now or datetime.now(UTC)
    network = policy["network_constraints"]
    if attestation["policy_hash"] != policy["content_hash"]:
        raise ValueError("ATTESTATION_INVALID")
    if attestation["route_profile_id"] != network["route_profile_id"]:
        raise ValueError("ROUTE_MISMATCH")
    if attestation["resolver_mode"] != network["dns_mode"]:
        raise ValueError("DNS_INVALID")
    if len(set(attestation["observations"])) < 2:
        raise ValueError("ATTESTATION_INVALID")
    if (
        parse_time(attestation["observed_at"]) > instant
        or parse_time(attestation["expires_at"]) <= instant
    ):
        raise ValueError("ATTESTATION_INVALID")
    ipv4 = attestation.get("source_ipv4")
    ipv6 = attestation.get("source_ipv6")
    if ipv4 is None and ipv6 is None:
        raise ValueError("SOURCE_IP_MISMATCH")
    if ipv4 is not None and ipv4 not in network["registered_source_ipv4"]:
        raise ValueError("SOURCE_IP_MISMATCH")
    if network["ipv6_mode"] == "disabled" and ipv6 is not None:
        raise ValueError("SOURCE_IP_MISMATCH")
    if (
        network["ipv6_mode"] == "approved_only"
        and ipv6 is not None
        and ipv6 not in network["registered_source_ipv6"]
    ):
        raise ValueError("SOURCE_IP_MISMATCH")


def authorize_destination(
    *,
    grant: dict[str, Any],
    intent: dict[str, Any],
    policy: dict[str, Any],
    attestation: dict[str, Any],
    candidate_url: str,
    addresses: list[str],
    cname_chain: list[str],
    sni_host: str,
    host_header: str,
    redirect_count: int,
    previously_pinned_addresses: list[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    created = now or datetime.now(UTC)
    authorization_id = str(uuid4())
    reasons: list[str] = []
    pinned: list[str] = []
    try:
        validate_attestation(attestation, policy, now=created)
        candidate = canonicalize_url(candidate_url)
        original = intent["target"]
        if candidate["scheme"] not in {"http", "https"}:
            reasons.append("PROTOCOL_DENIED")
        if candidate["scheme"] != original["scheme"]:
            reasons.append("PROTOCOL_DENIED")
        if candidate["port"] != original["port"]:
            reasons.append("PORT_DENIED")
        is_redirect = candidate["canonical_url"] != original["canonical_url"]
        if is_redirect and (
            not grant["constraints"]["follow_redirects"]
            or redirect_count < 1
            or redirect_count > grant["constraints"]["maximum_redirects"]
        ):
            reasons.append("REDIRECT_DENIED")
        host = cast(dict[str, Any], candidate["host"])
        expected_host = str(host["value"])
        if (
            _canonical_host(sni_host) != expected_host
            or _canonical_host(host_header) != expected_host
        ):
            reasons.append("SNI_HOST_MISMATCH")
        if not addresses or len(addresses) != len(set(addresses)):
            reasons.append("DNS_INVALID")
        fixture = str(attestation["resolver_id"]).startswith("fixture:")
        families: set[int] = set()
        for value in addresses:
            pinned.append(_destination_address(value, fixture_resolver=fixture))
            families.add(ipaddress.ip_address(pinned[-1]).version)
        if previously_pinned_addresses is not None and set(pinned) != set(
            previously_pinned_addresses
        ):
            reasons.append("DNS_REBINDING")
        if 6 in families and policy["network_constraints"]["ipv6_mode"] == "disabled":
            reasons.append("IPV6_DENIED")
        for cname in cname_chain:
            cname_target = deepcopy(intent)
            cname_target["target"] = canonicalize_url(
                f"{candidate['scheme']}://{canonicalize_domain(cname)}:{candidate['port']}{candidate['path']}"
            )
            if evaluate(cname_target, policy, active=True, now=created)["outcome"] != "allow":
                reasons.append("CNAME_OUT_OF_SCOPE")
        candidate_intent = deepcopy(intent)
        candidate_intent["target"] = candidate
        if evaluate(candidate_intent, policy, active=True, now=created)["outcome"] != "allow":
            reasons.append("REDIRECT_DENIED" if is_redirect else "GRANT_INVALID")
    except (CanonicalizationError, KeyError, TypeError):
        candidate = {}
        reasons.append("DNS_INVALID")
    except ValueError as exc:
        candidate = locals().get("candidate", {})
        reasons.append(str(exc) if str(exc) else "ATTESTATION_INVALID")
    unique_reasons = list(dict.fromkeys(reasons))
    return {
        "schema_version": "1.0.0",
        "authorization_id": authorization_id,
        "grant_id": grant.get("grant_id", "00000000-0000-0000-0000-000000000000"),
        "attestation_id": attestation.get(
            "attestation_id", "00000000-0000-0000-0000-000000000000"
        ),
        "outcome": "deny" if unique_reasons else "allow",
        "reason_codes": unique_reasons or ["DESTINATION_AUTHORIZED"],
        "candidate": candidate,
        "pinned_addresses": sorted(set(pinned)) if not unique_reasons else [],
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "execution_enabled": False,
    }
