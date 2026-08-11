"""Construct the complete supervised authority chain for the owned TEST-NET fixture."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from pentai_core.authorization import AuthorizationService
from pentai_core.controlled_dns import ControlledResolver, RawDnsAnswer
from pentai_core.network_attestation import NetworkAttestor, RouteSnapshot, SourceObservation
from pentai_core.policy_signing import PolicySigner
from pentai_core.source_store import EncryptedSourceStore
from pentai_policy import canonicalize_url


def _timestamp(offset: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) + offset).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class OwnedFixtureObserver:
    endpoint_id: str

    def observe(self) -> SourceObservation:
        return SourceObservation(self.endpoint_id, "192.0.2.10")


class OwnedFixtureRouteInspector:
    def inspect(self) -> RouteSnapshot:
        return RouteSnapshot(
            "owned-fixture-route", "tunnel_resolver", "fixture:controlled-dns"
        )


class OwnedFixtureDnsBackend:
    def resolve(self, hostname: str, port: int) -> RawDnsAnswer:
        if hostname != "example.test" or port != 8080:
            return RawDnsAnswer(())
        return RawDnsAnswer(("192.0.2.20",))


@dataclass(frozen=True)
class OwnedFixtureResolverProvider:
    resolver: ControlledResolver

    def for_assessment(self, assessment_id: str) -> ControlledResolver:
        if not assessment_id:
            raise ValueError("assessment identity is required")
        return self.resolver


def prepare_owned_fixture_session(
    *, database_path: Path, source_store_path: Path, maximum_response_bytes: int = 32
) -> tuple[AuthorizationService, dict[str, Any]]:
    """Create one approved, budgeted, still non-executing owned-fixture session."""
    if not 1 <= maximum_response_bytes <= 1_048_576:
        raise ValueError("owned fixture response bound is invalid")
    service = AuthorizationService(
        database_path,
        source_store=EncryptedSourceStore(source_store_path, secrets.token_bytes(32)),
        policy_signer=PolicySigner(secrets.token_bytes(32)),
    )
    program = service.create_program("Owned TEST-NET fixture")
    engagement = service.create_engagement(
        program["id"],
        effective_from=_timestamp(timedelta(minutes=-5)),
        expires_at=_timestamp(timedelta(hours=1)),
        timezone="UTC",
    )
    source = service.import_source(
        program["id"],
        authority="contract",
        reference="synthetic://owned-test-net-fixture",
        content="Owned synthetic fixture: HTTP GET example.test:8080/fixture only.",
    )
    manifest = _manifest(
        engagement=engagement,
        source=source,
        maximum_response_bytes=maximum_response_bytes,
    )
    version = service.save_manifest(engagement["id"], manifest)
    if not version["valid"]:
        raise ValueError("owned fixture manifest is invalid")
    bundle = service.compile_policy(version["id"])
    service.approve_policy(bundle["id"], approver_id="owned-fixture-human")
    service.activate_policy(bundle["id"], actor_id="owned-fixture-human")
    intent_id = str(uuid4())
    intent = {
        "schema_version": "1.0.0",
        "intent_id": intent_id,
        "assessment_id": engagement["id"],
        "policy_hash": bundle["content_hash"],
        "actor": {"actor_type": "human", "actor_id": "owned-fixture-human"},
        "capability": "network.http.get",
        "target": canonicalize_url("http://example.test:8080/fixture"),
        "http": {
            "method": "GET",
            "headers_digest": "0" * 64,
            "body_digest": None,
            "follow_redirects": False,
        },
        "parameters_digest": "1" * 64,
        "impact": "benign",
        "created_at": _timestamp(),
        "expires_at": _timestamp(timedelta(minutes=5)),
        "idempotency_key": f"owned-fixture-{intent_id}",
    }
    decision = service.evaluate_intent(engagement["id"], intent)
    grant = service.mint_action_grant(
        decision["decision_id"], audience="pentai-egress-gateway"
    )
    attestation = service.attest_network(
        engagement["id"],
        attestor=NetworkAttestor(
            (
                OwnedFixtureObserver("fixture:egress-a"),
                OwnedFixtureObserver("fixture:egress-b"),
            ),
            OwnedFixtureRouteInspector(),
            lifetime_seconds=60,
        ),
        attestor_id="owned-fixture-attestor",
    )
    resolver = ControlledResolver(
        OwnedFixtureDnsBackend(),
        resolver_mode="tunnel_resolver",
        resolver_id="fixture:controlled-dns",
    )
    destination = service.resolve_and_authorize_network_destination(
        grant_id=grant["grant_id"],
        attestation_id=attestation["attestation_id"],
        candidate_url=intent["target"]["canonical_url"],
        resolver_source=OwnedFixtureResolverProvider(resolver),
        sni_host="example.test",
        host_header="example.test",
    )
    session = service.prepare_gateway_session(
        grant_id=grant["grant_id"],
        destination_authorization_id=destination["authorization_id"],
    )
    return service, session


def _manifest(
    *,
    engagement: dict[str, Any],
    source: dict[str, Any],
    maximum_response_bytes: int,
) -> dict[str, Any]:
    if not 1 <= maximum_response_bytes <= 1_048_576:
        raise ValueError("owned fixture response bound is invalid")
    provenance = [{"source_id": source["id"], "content_hash": source["content_hash"]}]
    return {
        "schema_version": "2.0.0",
        "engagement": {
            "id": engagement["id"],
            "organization": "Owned Synthetic Fixture",
            "program_name": "Owned TEST-NET fixture",
            "program_type": "pentest",
            "status": "draft",
            "effective_from": engagement["effective_from"],
            "expires_at": engagement["expires_at"],
            "timezone": "UTC",
        },
        "sources": [
            {
                "source_id": source["id"],
                "reference": source["reference"],
                "authority": source["authority"],
                "retrieved_at": source["retrieved_at"],
                "content_hash": source["content_hash"],
            }
        ],
        "field_provenance": {
            field: provenance
            for field in (
                "/scope",
                "/techniques",
                "/operational_limits",
                "/network",
                "/data_handling",
                "/reporting",
                "/agent_controls",
            )
        },
        "scope": {
            "assets": [
                {
                    "asset_id": str(uuid4()),
                    "effect": "allow",
                    "type": "domain",
                    "canonical_value": "example.test",
                    "allowed_paths": ["/fixture"],
                    "denied_paths": [],
                    "allowed_ports": [8080],
                    "ownership_verified": True,
                    "source_reference": source["id"],
                }
            ],
            "discovered_assets_default": "deny",
            "redirects_outside_scope": "stop",
            "third_party_services": "deny",
        },
        "techniques": {
            "allowed_capabilities": ["network.http.get"],
            "denied_capabilities": [],
            "conditional_capabilities": [],
            "allowed_http_methods": ["GET"],
        },
        "operational_limits": {
            "requests_per_second": 1,
            "per_host_requests_per_second": 1,
            "burst_limit": 1,
            "concurrent_connections": 1,
            "maximum_runtime_minutes": 30,
            "maximum_total_requests": 1,
            "maximum_request_body_bytes": 0,
            "maximum_response_bytes": maximum_response_bytes,
            "stop_conditions": ["authorization changes"],
        },
        "network": {
            "route_mode": "local_gateway",
            "route_profile_id": "owned-fixture-route",
            "registered_source_ipv4": ["192.0.2.10"],
            "registered_source_ipv6": [],
            "ipv6_mode": "disabled",
            "dns_mode": "tunnel_resolver",
            "pause_on_identity_change": True,
        },
        "data_handling": {
            "real_user_data": "avoid_and_stop",
            "retention_days": 1,
            "approved_storage": "local_encrypted",
            "remote_ai_max_classification": "none",
        },
        "reporting": {
            "submission_channel": "manual",
            "submission_requires_human_approval": True,
            "automatic_submission": False,
        },
        "agent_controls": {
            "autonomy": "supervised_testing",
            "maximum_test_depth": 1,
            "maximum_runtime_minutes": 30,
            "human_approval_required_for": ["policy_activation"],
        },
        "approvals": {
            "scope_reviewer": "owned-fixture-human",
            "rules_reviewer": "owned-fixture-human",
            "technical_controls_reviewer": "owned-fixture-human",
            "status": "pending",
        },
        "unresolved_questions": [],
    }
