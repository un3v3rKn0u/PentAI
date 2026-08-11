from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch
from uuid import uuid4

from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.controlled_dns import ControlledResolver, RawDnsAnswer
from pentai_core.database import transaction
from pentai_core.gateway_response import GatewayResponseMeasurement
from pentai_core.migrate import migrate
from pentai_core.network_attestation import NetworkAttestor, RouteSnapshot, SourceObservation
from pentai_core.policy_signing import PolicySigner
from pentai_core.source_store import EncryptedSourceStore
from pentai_policy import canonicalize_url, content_hash, evaluate
from pentai_policy.document import contract_issues, parse_time


def timestamp(offset: timedelta) -> str:
    return (datetime.now(UTC) + offset).isoformat().replace("+00:00", "Z")


def fixture_resolver(
    addresses: tuple[str, ...], cname_chain: tuple[str, ...] = ()
) -> ControlledResolver:
    backend = Mock()
    backend.resolve.return_value = RawDnsAnswer(addresses, cname_chain)
    return ControlledResolver(
        backend,
        resolver_mode="tunnel_resolver",
        resolver_id="fixture:controlled-dns",
    )


class FixtureResolverSource:
    def __init__(self, resolver: ControlledResolver) -> None:
        self.resolver = resolver
        self.assessment_ids: list[str] = []

    def for_assessment(self, assessment_id: str) -> ControlledResolver:
        self.assessment_ids.append(assessment_id)
        return self.resolver


def manifest_for(engagement: dict[str, object], source: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "2.0.0",
        "engagement": {
            "id": engagement["id"],
            "organization": "Example Research",
            "program_name": "Synthetic Authorization Program",
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
            field: [{"source_id": source["id"], "content_hash": source["content_hash"]}]
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
                    "canonical_value": "EXAMPLE.test.",
                    "allowed_paths": ["/api"],
                    "denied_paths": ["/api/admin"],
                    "allowed_ports": [443],
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
            "maximum_total_requests": 50,
            "maximum_request_body_bytes": 0,
            "maximum_response_bytes": 100000,
            "stop_conditions": ["authorization changes"],
        },
        "network": {
            "route_mode": "local_gateway",
            "route_profile_id": "synthetic-route",
            "registered_source_ipv4": [],
            "registered_source_ipv6": [],
            "ipv6_mode": "disabled",
            "dns_mode": "tunnel_resolver",
            "pause_on_identity_change": True,
        },
        "data_handling": {
            "real_user_data": "avoid_and_stop",
            "retention_days": 7,
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
            "scope_reviewer": "reviewer",
            "rules_reviewer": "reviewer",
            "technical_controls_reviewer": "reviewer",
            "status": "pending",
        },
        "unresolved_questions": [],
    }


def intent_for(
    engagement_id: str, policy_hash: str, url: str = "https://example.test/api/items"
) -> dict[str, object]:
    created = timestamp(timedelta())
    intent_id = str(uuid4())
    return {
        "schema_version": "1.0.0",
        "intent_id": intent_id,
        "assessment_id": engagement_id,
        "policy_hash": policy_hash,
        "actor": {"actor_type": "human", "actor_id": "researcher"},
        "capability": "network.http.get",
        "target": canonicalize_url(url),
        "http": {
            "method": "GET",
            "headers_digest": "0" * 64,
            "body_digest": None,
            "follow_redirects": False,
        },
        "parameters_digest": "1" * 64,
        "impact": "benign",
        "created_at": created,
        "expires_at": timestamp(timedelta(minutes=5)),
        "idempotency_key": f"synthetic-intent-{intent_id}",
    }


class AuthorizationSliceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        migrate(self.database)
        self.service = AuthorizationService(
            self.database,
            source_store=EncryptedSourceStore(Path(self.temporary.name) / "sources", b"k" * 32),
            policy_signer=PolicySigner(b"s" * 32),
        )
        self.program = self.service.create_program("Synthetic program")
        self.engagement = self.service.create_engagement(
            self.program["id"],
            effective_from=timestamp(timedelta(hours=-1)),
            expires_at=timestamp(timedelta(hours=2)),
            timezone="UTC",
        )
        self.source = self.service.import_source(
            self.program["id"],
            authority="contract",
            reference="synthetic://authorization",
            content="Synthetic authorization: example.test /api GET only.",
        )
        self.manifest = manifest_for(self.engagement, self.source)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def activate(self) -> tuple[dict[str, object], dict[str, object]]:
        version = self.service.save_manifest(self.engagement["id"], self.manifest)
        self.assertTrue(version["valid"], version["issues"])
        bundle = self.service.compile_policy(version["id"])
        self.assertEqual(bundle["policy"]["compiler"]["version"], "1.1.0")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            stored_version = connection.execute(
                "SELECT compiler_version FROM policy_bundles WHERE id = ?", (bundle["id"],)
            ).fetchone()[0]
        self.assertEqual(stored_version, "1.1.0")
        self.service.approve_policy(bundle["id"], approver_id="human-reviewer")
        self.service.activate_policy(bundle["id"], actor_id="human-reviewer")
        return version, bundle

    def network_authority(
        self, *, follow_redirects: bool = False, maximum_redirects: int = 0
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        self.manifest["network"]["registered_source_ipv4"] = ["192.0.2.10"]
        _, bundle = self.activate()
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        intent["http"]["follow_redirects"] = follow_redirects  # type: ignore[index]
        intent["http"]["maximum_redirects"] = maximum_redirects  # type: ignore[index]
        decision = self.service.evaluate_intent(self.engagement["id"], intent)
        grant = self.service.mint_action_grant(
            decision["decision_id"], audience="pentai-egress-gateway"
        )
        observers = []
        for endpoint_id in ("fixture:egress-a", "fixture:egress-b"):
            observer = Mock()
            observer.observe.return_value = SourceObservation(endpoint_id, "192.0.2.10")
            observers.append(observer)
        route_inspector = Mock()
        route_inspector.inspect.return_value = RouteSnapshot(
            "synthetic-route", "tunnel_resolver", "fixture:controlled-dns"
        )
        attestation = self.service.attest_network(
            self.engagement["id"],
            attestor=NetworkAttestor(
                tuple(observers), route_inspector, lifetime_seconds=60
            ),
            attestor_id="fixture-attestor",
        )
        return intent, grant, attestation

    @staticmethod
    def network_attestor(
        *,
        address: str = "192.0.2.10",
        resolver_id: str = "fixture:controlled-dns",
    ) -> NetworkAttestor:
        observers = []
        for endpoint_id in ("fixture:egress-a", "fixture:egress-b"):
            observer = Mock()
            observer.observe.return_value = SourceObservation(endpoint_id, address)
            observers.append(observer)
        route_inspector = Mock()
        route_inspector.inspect.return_value = RouteSnapshot(
            "synthetic-route", "tunnel_resolver", resolver_id
        )
        return NetworkAttestor(tuple(observers), route_inspector, lifetime_seconds=60)

    def test_network_destination_authorization_pins_fixture_dns_without_executing(self) -> None:
        intent, grant, attestation = self.network_authority()

        result = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(
                fixture_resolver(("192.0.2.20",), ("example.test",))
            ),
            sni_host="example.test",
            host_header="example.test",
        )

        self.assertEqual(result["outcome"], "allow")
        self.assertEqual(result["reason_codes"], ["DESTINATION_AUTHORIZED"])
        self.assertEqual(result["pinned_addresses"], ["192.0.2.20"])
        self.assertFalse(result["execution_enabled"])
        with closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT used_at FROM action_grants WHERE grant_id = ?",
                    (grant["grant_id"],),
                ).fetchone()[0]
            )

        rebound = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(
                fixture_resolver(("192.0.2.21",), ("example.test",))
            ),
            sni_host="example.test",
            host_header="example.test",
        )
        self.assertEqual(rebound["outcome"], "deny")
        self.assertIn("DNS_REBINDING", rebound["reason_codes"])

    def test_redirect_lineage_derives_relative_target_and_denies_replay(self) -> None:
        intent, grant, attestation = self.network_authority(
            follow_redirects=True, maximum_redirects=2
        )
        root = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        child = self.service.resolve_and_authorize_network_redirect(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            parent_authorization_id=root["authorization_id"],
            location="../api/next",
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        self.assertEqual(child["outcome"], "allow")
        self.assertEqual(child["candidate"]["canonical_url"], "https://example.test/api/next")
        with closing(sqlite3.connect(self.database)) as connection:
            lineage = connection.execute(
                """
                SELECT parent_authorization_id, redirect_count
                FROM destination_authorizations WHERE authorization_id = ?
                """,
                (child["authorization_id"],),
            ).fetchone()
        self.assertEqual(tuple(lineage), (root["authorization_id"], 1))

        replay_source = FixtureResolverSource(fixture_resolver(("192.0.2.20",)))
        with self.assertRaises(DomainError) as raised:
            self.service.resolve_and_authorize_network_redirect(
                grant_id=grant["grant_id"],
                attestation_id=attestation["attestation_id"],
                parent_authorization_id=root["authorization_id"],
                location="/api/replay",
                resolver_source=replay_source,
                sni_host="example.test",
                host_header="example.test",
            )
        self.assertEqual(raised.exception.code, "REDIRECT_DENIED")
        self.assertEqual(replay_source.assessment_ids, [])

    def test_redirect_reauthorizes_new_host_without_false_rebinding(self) -> None:
        self.manifest["scope"]["assets"].append(  # type: ignore[index]
            {
                "asset_id": str(uuid4()),
                "effect": "allow",
                "type": "domain",
                "canonical_value": "redirect.test",
                "allowed_paths": ["/api"],
                "denied_paths": [],
                "allowed_ports": [443],
                "ownership_verified": True,
                "source_reference": self.source["id"],
            }
        )
        intent, grant, attestation = self.network_authority(
            follow_redirects=True, maximum_redirects=1
        )
        root = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        redirect = self.service.resolve_and_authorize_network_redirect(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            parent_authorization_id=root["authorization_id"],
            location="https://redirect.test/api/next",
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.30",))),
            sni_host="redirect.test",
            host_header="redirect.test",
        )
        self.assertEqual(redirect["outcome"], "allow")
        self.assertNotIn("DNS_REBINDING", redirect["reason_codes"])

    def test_redirect_limit_and_invalid_location_default_deny(self) -> None:
        intent, grant, attestation = self.network_authority(
            follow_redirects=True, maximum_redirects=1
        )
        root = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        first = self.service.resolve_and_authorize_network_redirect(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            parent_authorization_id=root["authorization_id"],
            location="/api/one",
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        limited = self.service.resolve_and_authorize_network_redirect(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            parent_authorization_id=first["authorization_id"],
            location="/api/two",
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        self.assertEqual(limited["outcome"], "deny")
        self.assertIn("REDIRECT_DENIED", limited["reason_codes"])

        invalid_source = FixtureResolverSource(fixture_resolver(("192.0.2.20",)))
        with self.assertRaises(DomainError) as raised:
            self.service.resolve_and_authorize_network_redirect(
                grant_id=grant["grant_id"],
                attestation_id=attestation["attestation_id"],
                parent_authorization_id=limited["authorization_id"],
                location="/api/bad\nheader",
                resolver_source=invalid_source,
                sni_host="example.test",
                host_header="example.test",
            )
        self.assertEqual(raised.exception.code, "REDIRECT_DENIED")
        self.assertEqual(invalid_source.assessment_ids, [])

    def test_network_destination_default_denies_special_ipv6_and_host_mismatch(self) -> None:
        intent, grant, attestation = self.network_authority()
        cases = (
            (["127.0.0.1"], "example.test", "DNS_SPECIAL_ADDRESS"),
            (["2001:db8::20"], "example.test", "IPV6_DENIED"),
            (["192.0.2.20"], "other.test", "SNI_HOST_MISMATCH"),
        )
        for addresses, sni_host, expected in cases:
            with self.subTest(expected=expected):
                result = self.service.resolve_and_authorize_network_destination(
                    grant_id=grant["grant_id"],
                    attestation_id=attestation["attestation_id"],
                    candidate_url=intent["target"]["canonical_url"],
                    resolver_source=FixtureResolverSource(fixture_resolver(tuple(addresses))),
                    sni_host=sni_host,
                    host_header="example.test",
                )
                self.assertEqual(result["outcome"], "deny")
                self.assertIn(expected, result["reason_codes"])
                self.assertEqual(result["pinned_addresses"], [])

    def test_network_attestation_is_invalidated_by_pause(self) -> None:
        intent, grant, attestation = self.network_authority()
        self.service.set_assessment_safety(
            self.engagement["id"], status="paused", reason="operator pause", actor_id="reviewer"
        )
        resolver_source = FixtureResolverSource(fixture_resolver(("192.0.2.20",)))

        with self.assertRaises(DomainError) as raised:
            self.service.resolve_and_authorize_network_destination(
                grant_id=grant["grant_id"],
                attestation_id=attestation["attestation_id"],
                candidate_url=intent["target"]["canonical_url"],
                resolver_source=resolver_source,
                sni_host="example.test",
                host_header="example.test",
            )
        self.assertEqual(raised.exception.code, "NETWORK_AUTHORIZATION_DENIED")
        self.assertEqual(resolver_source.assessment_ids, [])
        with closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM network_attestations WHERE attestation_id = ?",
                    (attestation["attestation_id"],),
                ).fetchone()[0],
                "invalidated",
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "status transition"):
                connection.execute(
                    """
                    UPDATE network_attestations
                    SET status = 'valid', invalidated_at = NULL
                    WHERE attestation_id = ?
                    """,
                    (attestation["attestation_id"],),
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
                connection.execute(
                    "DELETE FROM network_attestations WHERE attestation_id = ?",
                    (attestation["attestation_id"],),
                )

    def test_gateway_dns_preflight_derives_assessment_and_blocks_wrong_grant(self) -> None:
        intent, grant, attestation = self.network_authority()
        resolver_source = FixtureResolverSource(fixture_resolver(("192.0.2.20",)))

        with self.assertRaises(DomainError) as raised:
            self.service.resolve_and_authorize_network_destination(
                grant_id=str(uuid4()),
                attestation_id=attestation["attestation_id"],
                candidate_url=intent["target"]["canonical_url"],
                resolver_source=resolver_source,
                sni_host="example.test",
                host_header="example.test",
            )
        self.assertEqual(raised.exception.code, "NETWORK_AUTHORIZATION_DENIED")
        self.assertEqual(resolver_source.assessment_ids, [])

        result = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=resolver_source,
            sni_host="example.test",
            host_header="example.test",
        )
        self.assertEqual(result["outcome"], "allow")
        self.assertEqual(resolver_source.assessment_ids, [self.engagement["id"]])

    def test_gateway_dns_preserves_profile_binding_denial(self) -> None:
        intent, grant, attestation = self.network_authority()
        resolver_source = Mock()
        resolver_source.for_assessment.side_effect = DomainError(
            "NETWORK_PROFILE_POLICY_MISMATCH",
            "active policy and network profile do not match",
        )

        with self.assertRaises(DomainError) as raised:
            self.service.resolve_and_authorize_network_destination(
                grant_id=grant["grant_id"],
                attestation_id=attestation["attestation_id"],
                candidate_url=intent["target"]["canonical_url"],
                resolver_source=resolver_source,
                sni_host="example.test",
                host_header="example.test",
            )
        self.assertEqual(raised.exception.code, "NETWORK_PROFILE_POLICY_MISMATCH")
        resolver_source.for_assessment.assert_called_once_with(self.engagement["id"])

    def test_network_attestation_denies_route_source_and_resolver_mismatch(self) -> None:
        _, _, attestation = self.network_authority()
        cases = (
            ("route_profile_id", "other-route", "ROUTE_MISMATCH"),
            ("source_ipv4", "192.0.2.99", "SOURCE_IP_MISMATCH"),
            ("resolver_mode", "approved_resolver", "DNS_INVALID"),
        )
        for field, value, expected in cases:
            with self.subTest(expected=expected):
                invalid = copy.deepcopy(attestation)
                invalid.pop("status")
                invalid.pop("execution_enabled")
                invalid["attestation_id"] = str(uuid4())
                invalid[field] = value
                with self.assertRaises(DomainError) as raised:
                    self.service.record_network_attestation(
                        invalid, attestor_id="fixture-attestor"
                    )
                self.assertEqual(raised.exception.code, expected)

    def test_network_health_failure_pauses_assessment_and_revokes_authority(self) -> None:
        intent, grant, attestation = self.network_authority()
        destination = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        session = self.service.prepare_gateway_session(
            grant_id=grant["grant_id"],
            destination_authorization_id=destination["authorization_id"],
        )
        observers = []
        for endpoint_id, address in (
            ("fixture:egress-a", "192.0.2.10"),
            ("fixture:egress-b", "192.0.2.11"),
        ):
            observer = Mock()
            observer.observe.return_value = SourceObservation(endpoint_id, address)
            observers.append(observer)
        route_inspector = Mock()
        route_inspector.inspect.return_value = RouteSnapshot(
            "synthetic-route", "tunnel_resolver", "fixture:controlled-dns"
        )

        with self.assertRaises(DomainError) as raised:
            self.service.attest_network(
                self.engagement["id"],
                attestor=NetworkAttestor(tuple(observers), route_inspector),
                attestor_id="network-monitor",
            )
        self.assertEqual(raised.exception.code, "ATTESTATION_DISAGREEMENT")

        with closing(sqlite3.connect(self.database)) as connection, connection:
            state = connection.execute(
                "SELECT status FROM engagements WHERE id = ?", (self.engagement["id"],)
            ).fetchone()[0]
            grant_revoked = connection.execute(
                "SELECT revoked_at FROM action_grants WHERE grant_id = ?", (grant["grant_id"],)
            ).fetchone()[0]
            attestation_status = connection.execute(
                "SELECT status FROM network_attestations WHERE attestation_id = ?",
                (attestation["attestation_id"],),
            ).fetchone()[0]
            session_status = connection.execute(
                "SELECT status FROM gateway_sessions WHERE session_id = ?",
                (session["session_id"],),
            ).fetchone()[0]
            rate_status = connection.execute(
                "SELECT status FROM gateway_rate_reservations WHERE reservation_id = ?",
                (session["reservation_id"],),
            ).fetchone()[0]
            account = connection.execute(
                """
                SELECT reserved_requests, active_connections FROM budget_accounts
                WHERE engagement_id = ?
                """,
                (self.engagement["id"],),
            ).fetchone()
        self.assertEqual(state, "paused")
        self.assertIsNotNone(grant_revoked)
        self.assertEqual(attestation_status, "invalidated")
        self.assertEqual(session_status, "aborted")
        self.assertEqual(rate_status, "released")
        self.assertEqual(tuple(account), (0, 0))

    def test_network_health_refresh_replaces_the_only_valid_attestation(self) -> None:
        _, _, previous = self.network_authority()
        observers = []
        for endpoint_id in ("fixture:egress-a", "fixture:egress-b"):
            observer = Mock()
            observer.observe.return_value = SourceObservation(endpoint_id, "192.0.2.10")
            observers.append(observer)
        route_inspector = Mock()
        route_inspector.inspect.return_value = RouteSnapshot(
            "synthetic-route", "tunnel_resolver", "fixture:controlled-dns"
        )

        current = self.service.attest_network(
            self.engagement["id"],
            attestor=NetworkAttestor(tuple(observers), route_inspector),
            attestor_id="network-monitor",
        )

        with closing(sqlite3.connect(self.database)) as connection, connection:
            rows = connection.execute(
                """
                SELECT attestation_id, status FROM network_attestations
                WHERE engagement_id = ? ORDER BY observed_at, attestation_id
                """,
                (self.engagement["id"],),
            ).fetchall()
        self.assertEqual(
            {row[0]: row[1] for row in rows},
            {
                previous["attestation_id"]: "invalidated",
                current["attestation_id"]: "valid",
            },
        )

    def test_network_identity_check_is_audited_without_rotating_authority(self) -> None:
        _, _, attestation = self.network_authority()

        result = self.service.verify_network_identity(
            self.engagement["id"],
            attestor=self.network_attestor(),
            attestor_id="network-safety-supervisor",
        )

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["attestation_id"], attestation["attestation_id"])
        self.assertFalse(result["execution_enabled"])
        events = [
            event
            for event in self.service.audit_events()
            if event["action"] == "network.identity_checked"
        ]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["subject_id"], attestation["attestation_id"])
        self.assertNotIn("source_ipv4", events[0]["data"])
        with closing(sqlite3.connect(self.database)) as connection:
            valid = connection.execute(
                "SELECT COUNT(*) FROM network_attestations WHERE status = 'valid'"
            ).fetchone()[0]
        self.assertEqual(valid, 1)

    def test_network_identity_change_aborts_prepared_session_and_pauses(self) -> None:
        intent, grant, attestation = self.network_authority()
        destination = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        session = self.service.prepare_gateway_session(
            grant_id=grant["grant_id"],
            destination_authorization_id=destination["authorization_id"],
        )

        with self.assertRaises(DomainError) as raised:
            self.service.verify_network_identity(
                self.engagement["id"],
                attestor=self.network_attestor(resolver_id="fixture:changed-resolver"),
                attestor_id="network-safety-supervisor",
            )
        self.assertEqual(raised.exception.code, "NETWORK_IDENTITY_CHANGED")

        with closing(sqlite3.connect(self.database)) as connection:
            engagement_status = connection.execute(
                "SELECT status FROM engagements WHERE id = ?", (self.engagement["id"],)
            ).fetchone()[0]
            attestation_status = connection.execute(
                "SELECT status FROM network_attestations WHERE attestation_id = ?",
                (attestation["attestation_id"],),
            ).fetchone()[0]
            session_status = connection.execute(
                "SELECT status FROM gateway_sessions WHERE session_id = ?",
                (session["session_id"],),
            ).fetchone()[0]
        self.assertEqual(engagement_status, "paused")
        self.assertEqual(attestation_status, "invalidated")
        self.assertEqual(session_status, "aborted")

    def test_expired_network_identity_denies_and_pauses_before_measurement(self) -> None:
        _, _, attestation = self.network_authority()
        expired = datetime.fromisoformat(
            str(attestation["expires_at"]).replace("Z", "+00:00")
        )
        attestor = self.network_attestor()

        with self.assertRaises(DomainError) as raised:
            self.service.verify_network_identity(
                self.engagement["id"],
                attestor=attestor,
                attestor_id="network-safety-supervisor",
                now=expired,
            )
        self.assertEqual(raised.exception.code, "ATTESTATION_INVALID")
        with closing(sqlite3.connect(self.database)) as connection:
            status = connection.execute(
                "SELECT status FROM engagements WHERE id = ?", (self.engagement["id"],)
            ).fetchone()[0]
        self.assertEqual(status, "paused")

    def test_gateway_session_reserves_and_releases_budget_without_execution(self) -> None:
        intent, grant, attestation = self.network_authority()
        destination = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )

        session = self.service.prepare_gateway_session(
            grant_id=grant["grant_id"],
            destination_authorization_id=destination["authorization_id"],
        )
        self.assertEqual(contract_issues(session, "gateway-session-v1.schema.json"), ())
        self.assertEqual(session["status"], "prepared")
        self.assertFalse(session["execution_enabled"])
        with self.assertRaises(DomainError) as raised:
            self.service.prepare_gateway_session(
                grant_id=grant["grant_id"],
                destination_authorization_id=destination["authorization_id"],
            )
        self.assertEqual(raised.exception.code, "GATEWAY_SESSION_REPLAYED")

        result = self.service.abort_gateway_session(
            session["session_id"], reason="synthetic cancellation"
        )
        self.assertEqual(result["status"], "aborted")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            account = connection.execute(
                """
                SELECT reserved_requests, committed_requests, active_connections
                FROM budget_accounts WHERE engagement_id = ?
                """,
                (self.engagement["id"],),
            ).fetchone()
            rate_status = connection.execute(
                """
                SELECT status FROM gateway_rate_reservations WHERE reservation_id = ?
                """,
                (session["reservation_id"],),
            ).fetchone()[0]
            rate_tokens = connection.execute(
                """
                SELECT tokens FROM gateway_rate_buckets
                WHERE engagement_id = ? AND bucket_key = 'global'
                """,
                (self.engagement["id"],),
            ).fetchone()[0]
            with self.assertRaisesRegex(sqlite3.IntegrityError, "status transition"):
                connection.execute(
                    """
                    UPDATE gateway_sessions SET status = 'prepared', finalized_at = NULL
                    WHERE session_id = ?
                    """,
                    (session["session_id"],),
                )
        self.assertEqual(tuple(account), (0, 0, 0))
        self.assertEqual(rate_status, "released")
        self.assertEqual(rate_tokens, 1)

    def test_gateway_request_start_atomically_consumes_and_commits_without_execution(
        self,
    ) -> None:
        intent, grant, attestation = self.network_authority()
        destination = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        session = self.service.prepare_gateway_session(
            grant_id=grant["grant_id"],
            destination_authorization_id=destination["authorization_id"],
        )

        started = self.service.commit_gateway_request_start(session["session_id"])

        self.assertEqual(
            contract_issues(started, "gateway-request-start-v1.schema.json"), ()
        )
        self.assertEqual(started["status"], "committed")
        self.assertFalse(started["execution_enabled"])
        self.assertLessEqual(
            parse_time(started["deadline_at"]), parse_time(grant["expires_at"])
        )
        with closing(sqlite3.connect(self.database)) as connection:
            account = connection.execute(
                """
                SELECT reserved_requests, committed_requests, active_connections
                FROM budget_accounts WHERE engagement_id = ?
                """,
                (self.engagement["id"],),
            ).fetchone()
            statuses = connection.execute(
                """
                SELECT br.status, grr.status, ag.used_at
                FROM budget_reservations br
                JOIN gateway_rate_reservations grr USING (reservation_id)
                JOIN action_grants ag ON ag.grant_id = br.grant_id
                WHERE br.reservation_id = ?
                """,
                (session["reservation_id"],),
            ).fetchone()
        self.assertEqual(tuple(account), (0, 1, 1))
        self.assertEqual(statuses[0:2], ("committed", "committed"))
        self.assertIsNotNone(statuses[2])
        with self.assertRaises(DomainError) as replayed:
            self.service.commit_gateway_request_start(session["session_id"])
        self.assertEqual(replayed.exception.code, "GATEWAY_REQUEST_REPLAYED")
        with self.assertRaises(DomainError) as abort:
            self.service.abort_gateway_session(
                session["session_id"], reason="must not refund committed capacity"
            )
        self.assertEqual(abort.exception.code, "GATEWAY_REQUEST_COMMITTED")

    def test_gateway_request_start_denies_expired_attestation_without_consumption(
        self,
    ) -> None:
        intent, grant, attestation = self.network_authority()
        destination = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        session = self.service.prepare_gateway_session(
            grant_id=grant["grant_id"],
            destination_authorization_id=destination["authorization_id"],
        )

        with self.assertRaises(DomainError) as denied:
            self.service.commit_gateway_request_start(
                session["session_id"], now=parse_time(attestation["expires_at"])
            )
        self.assertEqual(denied.exception.code, "GATEWAY_REQUEST_DENIED")
        with closing(sqlite3.connect(self.database)) as connection:
            grant_state = connection.execute(
                "SELECT used_at FROM action_grants WHERE grant_id = ?", (grant["grant_id"],)
            ).fetchone()[0]
            reservation = connection.execute(
                "SELECT status FROM budget_reservations WHERE reservation_id = ?",
                (session["reservation_id"],),
            ).fetchone()[0]
        self.assertIsNone(grant_state)
        self.assertEqual(reservation, "reserved")

    def test_gateway_request_start_concurrency_and_recovery_are_fail_closed(self) -> None:
        intent, grant, attestation = self.network_authority()
        destination = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        session = self.service.prepare_gateway_session(
            grant_id=grant["grant_id"],
            destination_authorization_id=destination["authorization_id"],
        )

        def commit() -> str:
            try:
                return str(
                    self.service.commit_gateway_request_start(session["session_id"])[
                        "status"
                    ]
                )
            except DomainError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: commit(), range(2)))
        self.assertEqual(sorted(outcomes), ["GATEWAY_REQUEST_REPLAYED", "committed"])

        recovered = self.service.recover_startup()
        self.assertEqual(recovered["aborted_gateway_sessions"], 1)
        with closing(sqlite3.connect(self.database)) as connection:
            account = connection.execute(
                """
                SELECT reserved_requests, committed_requests, active_connections
                FROM budget_accounts WHERE engagement_id = ?
                """,
                (self.engagement["id"],),
            ).fetchone()
            states = connection.execute(
                """
                SELECT grs.status, gs.status, br.status, grr.status
                FROM gateway_request_starts grs
                JOIN gateway_sessions gs USING (session_id)
                JOIN budget_reservations br USING (reservation_id)
                JOIN gateway_rate_reservations grr USING (reservation_id)
                WHERE grs.session_id = ?
                """,
                (session["session_id"],),
            ).fetchone()
        self.assertEqual(tuple(account), (0, 1, 0))
        self.assertEqual(tuple(states), ("cancelled", "aborted", "committed", "committed"))

    def test_gateway_request_finalization_closes_connection_and_preserves_commit(self) -> None:
        intent, grant, attestation = self.network_authority()
        destination = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        session = self.service.prepare_gateway_session(
            grant_id=grant["grant_id"],
            destination_authorization_id=destination["authorization_id"],
        )
        started = self.service.commit_gateway_request_start(session["session_id"])
        completed_at = parse_time(started["committed_at"]) + timedelta(milliseconds=1)

        result = self.service.finalize_gateway_request(
            started["start_id"],
            GatewayResponseMeasurement("completed", 5, 5, completed_at),
        )

        self.assertEqual(contract_issues(result, "gateway-request-result-v1.schema.json"), ())
        self.assertEqual(result["outcome"], "completed")
        self.assertFalse(result["execution_enabled"])
        with closing(sqlite3.connect(self.database)) as connection:
            account = connection.execute(
                """
                SELECT reserved_requests, committed_requests, active_connections
                FROM budget_accounts WHERE engagement_id = ?
                """,
                (self.engagement["id"],),
            ).fetchone()
            states = connection.execute(
                """
                SELECT gs.status, br.status, grr.status
                FROM gateway_sessions gs
                JOIN budget_reservations br USING (reservation_id)
                JOIN gateway_rate_reservations grr USING (reservation_id)
                WHERE gs.session_id = ?
                """,
                (session["session_id"],),
            ).fetchone()
        self.assertEqual(tuple(account), (0, 1, 0))
        self.assertEqual(tuple(states), ("closed", "committed", "committed"))
        with self.assertRaises(DomainError) as replayed:
            self.service.finalize_gateway_request(
                started["start_id"],
                GatewayResponseMeasurement("completed", 5, 5, completed_at),
            )
        self.assertEqual(replayed.exception.code, "GATEWAY_RESULT_REPLAYED")

    def test_gateway_request_finalization_derives_and_enforces_hard_limits(self) -> None:
        intent, grant, attestation = self.network_authority()
        destination = self.service.resolve_and_authorize_network_destination(
            grant_id=grant["grant_id"],
            attestation_id=attestation["attestation_id"],
            candidate_url=intent["target"]["canonical_url"],
            resolver_source=FixtureResolverSource(fixture_resolver(("192.0.2.20",))),
            sni_host="example.test",
            host_header="example.test",
        )
        session = self.service.prepare_gateway_session(
            grant_id=grant["grant_id"],
            destination_authorization_id=destination["authorization_id"],
        )
        started = self.service.commit_gateway_request_start(session["session_id"])
        before_deadline = parse_time(started["committed_at"]) + timedelta(milliseconds=1)

        with self.assertRaises(DomainError) as invalid:
            self.service.finalize_gateway_request(
                started["start_id"],
                GatewayResponseMeasurement("completed", 100001, 100000, before_deadline),
            )
        self.assertEqual(invalid.exception.code, "GATEWAY_ACCOUNTING_INVALID")
        with self.assertRaises(DomainError) as before_start:
            self.service.finalize_gateway_request(
                started["start_id"],
                GatewayResponseMeasurement(
                    "transport_error",
                    0,
                    0,
                    parse_time(started["committed_at"]) - timedelta(milliseconds=1),
                ),
            )
        self.assertEqual(before_start.exception.code, "GATEWAY_ACCOUNTING_INVALID")
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM gateway_sessions WHERE session_id = ?",
                    (session["session_id"],),
                ).fetchone()[0],
                "prepared",
            )

        result = self.service.finalize_gateway_request(
            started["start_id"],
            GatewayResponseMeasurement(
                "deadline_exceeded", 0, 0, parse_time(started["deadline_at"])
            ),
        )
        self.assertEqual(result["outcome"], "deadline_exceeded")

    def test_gateway_rate_tokens_are_atomic_durable_and_refill(self) -> None:
        self.manifest["operational_limits"]["concurrent_connections"] = 2  # type: ignore[index]
        first_intent, first_grant, attestation = self.network_authority()
        with closing(sqlite3.connect(self.database)) as connection:
            policy_hash = connection.execute(
                """
                SELECT content_hash FROM policy_bundles
                WHERE id = (SELECT active_policy_id FROM engagements WHERE id = ?)
                """,
                (self.engagement["id"],),
            ).fetchone()[0]
        second_intent = intent_for(self.engagement["id"], policy_hash)
        second_decision = self.service.evaluate_intent(self.engagement["id"], second_intent)
        second_grant = self.service.mint_action_grant(
            second_decision["decision_id"], audience="pentai-egress-gateway"
        )
        pairs = []
        for intent, grant, address in (
            (first_intent, first_grant, "192.0.2.20"),
            (second_intent, second_grant, "192.0.2.21"),
        ):
            destination = self.service.resolve_and_authorize_network_destination(
                grant_id=grant["grant_id"],
                attestation_id=attestation["attestation_id"],
                candidate_url=intent["target"]["canonical_url"],
                resolver_source=FixtureResolverSource(fixture_resolver((address,))),
                sni_host="example.test",
                host_header="example.test",
            )
            pairs.append((grant["grant_id"], destination["authorization_id"]))

        instant = datetime.now(UTC)
        def reserve(pair: tuple[str, str]) -> tuple[tuple[str, str], str, dict[str, object] | None]:
            try:
                session = self.service.prepare_gateway_session(
                    grant_id=pair[0], destination_authorization_id=pair[1]
                )
            except DomainError as exc:
                return pair, exc.code, None
            return pair, "prepared", session

        with (
            patch("pentai_core.authorization._now", return_value=instant),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            outcomes = list(executor.map(reserve, pairs))
        self.assertEqual(sorted(item[1] for item in outcomes), ["RATE_LIMITED", "prepared"])
        prepared = next(item[2] for item in outcomes if item[1] == "prepared")
        denied_pair = next(item[0] for item in outcomes if item[1] == "RATE_LIMITED")
        assert prepared is not None

        with patch(
            "pentai_core.authorization._now", return_value=instant + timedelta(seconds=1)
        ):
            second = self.service.prepare_gateway_session(
                grant_id=denied_pair[0],
                destination_authorization_id=denied_pair[1],
            )
        with closing(sqlite3.connect(self.database)) as connection:
            buckets = connection.execute(
                """
                SELECT bucket_key, tokens FROM gateway_rate_buckets
                WHERE engagement_id = ? ORDER BY bucket_key
                """,
                (self.engagement["id"],),
            ).fetchall()
            reservations = connection.execute(
                """
                SELECT reservation_id, status FROM gateway_rate_reservations
                ORDER BY reserved_at, reservation_id
                """
            ).fetchall()
        self.assertEqual([row[0] for row in buckets], ["global", "host:example.test"])
        self.assertTrue(all(abs(row[1]) < 1e-9 for row in buckets))
        self.assertEqual(
            {row[0]: row[1] for row in reservations},
            {prepared["reservation_id"]: "reserved", second["reservation_id"]: "reserved"},
        )
        with transaction(self.database) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE gateway_rate_buckets SET updated_at = ?
                WHERE engagement_id = ? AND bucket_key = 'global'
                """,
                (timestamp(timedelta(seconds=2)), self.engagement["id"]),
            )
            with self.assertRaises(DomainError) as raised:
                self.service._reserve_rate_bucket(
                    connection,
                    engagement_id=self.engagement["id"],
                    policy_bundle_id=connection.execute(
                        """
                        SELECT active_policy_id FROM engagements WHERE id = ?
                        """,
                        (self.engagement["id"],),
                    ).fetchone()[0],
                    bucket_key="global",
                    refill_rate=1,
                    capacity=1,
                    reserved_at=instant,
                )
        self.assertEqual(raised.exception.code, "CLOCK_UNTRUSTED")

    def test_concurrent_gateway_reservations_cannot_exceed_connection_budget(self) -> None:
        self.manifest["operational_limits"]["burst_limit"] = 2  # type: ignore[index]
        first_intent, first_grant, attestation = self.network_authority()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            policy_hash = connection.execute(
                """
                SELECT content_hash FROM policy_bundles
                WHERE id = (SELECT active_policy_id FROM engagements WHERE id = ?)
                """,
                (self.engagement["id"],),
            ).fetchone()[0]
        second_intent = intent_for(self.engagement["id"], policy_hash)
        second_decision = self.service.evaluate_intent(self.engagement["id"], second_intent)
        second_grant = self.service.mint_action_grant(
            second_decision["decision_id"], audience="pentai-egress-gateway"
        )
        pairs = []
        for intent, grant, address in (
            (first_intent, first_grant, "192.0.2.20"),
            (second_intent, second_grant, "192.0.2.21"),
        ):
            destination = self.service.resolve_and_authorize_network_destination(
                grant_id=grant["grant_id"],
                attestation_id=attestation["attestation_id"],
                candidate_url=intent["target"]["canonical_url"],
                resolver_source=FixtureResolverSource(fixture_resolver((address,))),
                sni_host="example.test",
                host_header="example.test",
            )
            pairs.append((grant["grant_id"], destination["authorization_id"]))

        def reserve(pair: tuple[str, str]) -> str:
            try:
                self.service.prepare_gateway_session(
                    grant_id=pair[0], destination_authorization_id=pair[1]
                )
            except DomainError as exc:
                return exc.code
            return "prepared"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = sorted(executor.map(reserve, pairs))
        self.assertEqual(outcomes, ["BUDGET_EXHAUSTED", "prepared"])

    def test_exact_request_is_allowed_and_deterministic(self) -> None:
        _, bundle = self.activate()
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        first = self.service.evaluate_intent(self.engagement["id"], intent)
        second = self.service.evaluate_intent(self.engagement["id"], intent)
        self.assertEqual(first, second)
        self.assertEqual(first["outcome"], "allow")
        self.assertEqual(first["reason_codes"], ["EXPLICIT_ALLOW"])

    def test_allow_decision_mints_and_atomically_consumes_single_use_grant(self) -> None:
        _, bundle = self.activate()
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        decision = self.service.evaluate_intent(self.engagement["id"], intent)
        grant = self.service.mint_action_grant(decision["decision_id"])
        self.assertEqual(contract_issues(grant, "action-grant-v1.schema.json"), ())
        self.assertEqual(grant["intent_id"], intent["intent_id"])
        self.assertEqual(grant["decision_id"], decision["decision_id"])
        self.assertTrue(grant["single_use"])
        self.assertEqual(self.service.mint_action_grant(decision["decision_id"]), grant)

        consumed = self.service.consume_action_grant(
            grant, intent, audience="pentai-execution-broker"
        )
        self.assertEqual(consumed["status"], "consumed")
        grant_events = [
            event
            for event in self.service.audit_events()
            if event["action"].startswith("action_grant")
        ]
        self.assertEqual(
            [event["action"] for event in grant_events],
            ["action_grant.issued", "action_grant.consumed"],
        )
        self.assertTrue(
            all(event["data"]["intent_id"] == intent["intent_id"] for event in grant_events)
        )
        with self.assertRaises(DomainError) as raised:
            self.service.consume_action_grant(
                grant, intent, audience="pentai-execution-broker"
            )
        self.assertEqual(raised.exception.code, "GRANT_REPLAYED")

    def test_grant_rejects_wrong_audience_mutation_expiry_and_wrong_key(self) -> None:
        _, bundle = self.activate()
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        decision = self.service.evaluate_intent(self.engagement["id"], intent)
        grant = self.service.mint_action_grant(decision["decision_id"])

        with self.assertRaises(DomainError) as raised:
            self.service.consume_action_grant(grant, intent, audience="pentai-egress-gateway")
        self.assertEqual(raised.exception.code, "GRANT_BINDING_MISMATCH")

        mutated = copy.deepcopy(intent)
        mutated["parameters_digest"] = "2" * 64
        with self.assertRaises(DomainError) as raised:
            self.service.consume_action_grant(
                grant, mutated, audience="pentai-execution-broker"
            )
        self.assertEqual(raised.exception.code, "GRANT_BINDING_MISMATCH")

        with self.assertRaises(DomainError) as raised:
            self.service.consume_action_grant(
                grant,
                intent,
                audience="pentai-execution-broker",
                now=datetime.now(UTC) + timedelta(minutes=1),
            )
        self.assertEqual(raised.exception.code, "GRANT_EXPIRED")

        wrong_key_service = AuthorizationService(
            self.database,
            source_store=self.service.source_store,
            policy_signer=PolicySigner(b"w" * 32),
        )
        with self.assertRaises(DomainError) as raised:
            wrong_key_service.consume_action_grant(
                grant, intent, audience="pentai-execution-broker"
            )
        self.assertEqual(raised.exception.code, "GRANT_SIGNATURE_INVALID")

    def test_concurrent_grant_consumption_allows_exactly_one_winner(self) -> None:
        _, bundle = self.activate()
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        decision = self.service.evaluate_intent(self.engagement["id"], intent)
        grant = self.service.mint_action_grant(decision["decision_id"])

        def consume() -> str:
            try:
                self.service.consume_action_grant(
                    grant, intent, audience="pentai-execution-broker"
                )
            except DomainError as exc:
                return exc.code
            return "consumed"

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = sorted(executor.map(lambda _: consume(), range(2)))
        self.assertEqual(outcomes, ["GRANT_REPLAYED", "consumed"])

    def test_deny_decision_and_revocation_cannot_produce_usable_grant(self) -> None:
        _, bundle = self.activate()
        denied_intent = intent_for(
            self.engagement["id"], bundle["content_hash"], "https://outside.test/api"
        )
        denied = self.service.evaluate_intent(self.engagement["id"], denied_intent)
        with self.assertRaises(DomainError) as raised:
            self.service.mint_action_grant(denied["decision_id"])
        self.assertEqual(raised.exception.code, "GRANT_AUTHORITY_INVALID")

        allowed_intent = intent_for(self.engagement["id"], bundle["content_hash"])
        allowed_intent["idempotency_key"] = "synthetic-intent-allowed-2"
        allowed = self.service.evaluate_intent(self.engagement["id"], allowed_intent)
        grant = self.service.mint_action_grant(allowed["decision_id"])
        self.service.revoke_policy(
            bundle["id"], actor_id="human-reviewer", reason="synthetic emergency stop"
        )
        with self.assertRaises(DomainError) as raised:
            self.service.consume_action_grant(
                grant, allowed_intent, audience="pentai-execution-broker"
            )
        self.assertEqual(raised.exception.code, "GRANT_REVOKED")

    def test_intent_idempotency_and_authorization_records_are_immutable(self) -> None:
        _, bundle = self.activate()
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        decision = self.service.evaluate_intent(self.engagement["id"], intent)
        conflicting = copy.deepcopy(intent)
        conflicting["intent_id"] = str(uuid4())
        with self.assertRaises(DomainError) as raised:
            self.service.evaluate_intent(self.engagement["id"], conflicting)
        self.assertEqual(raised.exception.code, "IDEMPOTENCY_CONFLICT")

        grant = self.service.mint_action_grant(decision["decision_id"])
        with closing(sqlite3.connect(self.database)) as connection, connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE action_intents SET intent_json = '{}' WHERE intent_id = ?",
                    (intent["intent_id"],),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    UPDATE action_grants SET audience = 'pentai-egress-gateway'
                    WHERE grant_id = ?
                    """,
                    (grant["grant_id"],),
                )

    def test_startup_recovery_revokes_grants_and_requires_explicit_resume(self) -> None:
        _, bundle = self.activate()
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        decision = self.service.evaluate_intent(self.engagement["id"], intent)
        grant = self.service.mint_action_grant(decision["decision_id"])

        recovered = self.service.recover_startup()
        self.assertEqual(recovered["status"], "paused")
        self.assertEqual(recovered["revoked_grants"], 1)
        self.assertEqual(self.service.safety_state()["status"], "paused")
        with self.assertRaises(DomainError) as raised:
            self.service.consume_action_grant(
                grant, intent, audience="pentai-execution-broker"
            )
        self.assertEqual(raised.exception.code, "GRANT_REVOKED")
        with self.assertRaises(DomainError) as raised:
            self.service.set_assessment_safety(
                self.engagement["id"],
                status="active",
                reason="synthetic resume",
                actor_id="human-reviewer",
            )
        self.assertEqual(raised.exception.code, "SAFETY_RESUME_DENIED")

        self.service.set_global_safety(
            status="active", reason="human recovery review complete", actor_id="human-reviewer"
        )
        resumed = self.service.set_assessment_safety(
            self.engagement["id"],
            status="active",
            reason="human recovery review complete",
            actor_id="human-reviewer",
        )
        self.assertEqual(resumed["status"], "active")

        recovered_again = self.service.recover_startup()
        self.assertEqual(recovered_again["revoked_grants"], 0)
        self.service.set_global_safety(
            status="active", reason="review revoked policy path", actor_id="human-reviewer"
        )
        self.service.revoke_policy(
            bundle["id"], actor_id="human-reviewer", reason="synthetic revocation"
        )
        with self.assertRaises(DomainError) as raised:
            self.service.set_assessment_safety(
                self.engagement["id"],
                status="active",
                reason="must not resume revoked policy",
                actor_id="human-reviewer",
            )
        self.assertEqual(raised.exception.code, "SAFETY_RESUME_DENIED")

    def test_emergency_stop_is_durable_and_invalidates_all_epochs(self) -> None:
        _, bundle = self.activate()
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        decision = self.service.evaluate_intent(self.engagement["id"], intent)
        before = self.service.mint_action_grant(decision["decision_id"])
        stopped = self.service.set_global_safety(
            status="stopped", reason="synthetic emergency", actor_id="human-reviewer"
        )
        self.assertEqual(stopped["status"], "stopped")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            epoch = connection.execute(
                "SELECT revocation_epoch FROM engagements WHERE id = ?",
                (self.engagement["id"],),
            ).fetchone()[0]
        self.assertGreater(epoch, before["revocation_epoch"])
        with self.assertRaises(DomainError) as raised:
            self.service.evaluate_intent(self.engagement["id"], intent)
        self.assertEqual(raised.exception.code, "ASSESSMENT_PAUSED")
        self.assertTrue(self.service.verify_audit_chain()["valid"])

    def test_safety_controls_reject_invalid_state_and_missing_reason(self) -> None:
        with self.assertRaises(DomainError) as raised:
            self.service.set_global_safety(
                status="running", reason="invalid state", actor_id="human-reviewer"
            )
        self.assertEqual(raised.exception.code, "SAFETY_STATE_INVALID")

        with self.assertRaises(DomainError) as raised:
            self.service.set_global_safety(
                status="paused", reason="   ", actor_id="human-reviewer"
            )
        self.assertEqual(raised.exception.code, "SAFETY_REASON_REQUIRED")

        with self.assertRaises(DomainError) as raised:
            self.service.set_assessment_safety(
                self.engagement["id"],
                status="stopped",
                reason="unsupported assessment state",
                actor_id="human-reviewer",
            )
        self.assertEqual(raised.exception.code, "ASSESSMENT_STATE_INVALID")

    def test_ambiguous_altered_expired_and_out_of_scope_deny(self) -> None:
        _, bundle = self.activate()
        policy = bundle["policy"]

        ambiguous = intent_for(self.engagement["id"], bundle["content_hash"])
        ambiguous["target"] = {
            **ambiguous["target"],
            "canonical_url": "https://example.test/api/%2e%2e/admin",
        }
        self.assertEqual(
            evaluate(ambiguous, policy, active=True)["reason_codes"],
            ["TARGET_AMBIGUOUS"],
        )

        altered = intent_for(self.engagement["id"], "f" * 64)
        self.assertEqual(
            evaluate(altered, policy, active=True)["reason_codes"],
            ["POLICY_HASH_MISMATCH"],
        )

        expired = copy.deepcopy(policy)
        expired["validity"]["not_after"] = timestamp(timedelta(minutes=-1))
        expired["content_hash"] = content_hash(
            {
                "policy": {
                    key: value
                    for key, value in expired.items()
                    if key not in {"content_hash", "signature"}
                },
                "signer_key_id": expired["signature"]["key_id"],
            }
        )
        expired_intent = intent_for(self.engagement["id"], expired["content_hash"])
        self.assertEqual(
            evaluate(expired_intent, expired, active=True)["reason_codes"],
            ["POLICY_EXPIRED"],
        )

        outside = intent_for(
            self.engagement["id"], bundle["content_hash"], "https://outside.test/api"
        )
        self.assertEqual(
            self.service.evaluate_intent(self.engagement["id"], outside)["reason_codes"],
            ["TARGET_OUT_OF_SCOPE"],
        )

    def test_invalid_expired_cross_assessment_and_method_mismatch_intents_deny(self) -> None:
        _, bundle = self.activate()

        expired = intent_for(self.engagement["id"], bundle["content_hash"])
        expired["created_at"] = timestamp(timedelta(minutes=-10))
        expired["expires_at"] = timestamp(timedelta(minutes=-5))
        self.assertEqual(
            self.service.evaluate_intent(self.engagement["id"], expired)["reason_codes"],
            ["TESTING_WINDOW_CLOSED"],
        )

        cross_assessment = intent_for(str(uuid4()), bundle["content_hash"])
        self.assertEqual(
            self.service.evaluate_intent(self.engagement["id"], cross_assessment)["reason_codes"],
            ["DEFAULT_DENY"],
        )

        wrong_method = intent_for(self.engagement["id"], bundle["content_hash"])
        wrong_method["http"]["method"] = "HEAD"
        self.assertEqual(
            self.service.evaluate_intent(self.engagement["id"], wrong_method)["reason_codes"],
            ["METHOD_DENIED"],
        )

        malformed = intent_for(self.engagement["id"], bundle["content_hash"])
        malformed["unexpected"] = True
        self.assertEqual(
            self.service.evaluate_intent(self.engagement["id"], malformed)["reason_codes"],
            ["DEFAULT_DENY"],
        )

    def test_deny_precedence_and_path_boundaries(self) -> None:
        _, bundle = self.activate()
        denied = intent_for(
            self.engagement["id"],
            bundle["content_hash"],
            "https://example.test/api/admin/users",
        )
        lookalike = intent_for(
            self.engagement["id"],
            bundle["content_hash"],
            "https://example.test/apiv2",
        )
        self.assertEqual(
            self.service.evaluate_intent(self.engagement["id"], denied)["reason_codes"],
            ["EXPLICIT_DENY"],
        )
        self.assertEqual(
            self.service.evaluate_intent(self.engagement["id"], lookalike)["reason_codes"],
            ["PATH_DENIED"],
        )

    def test_activation_requires_exact_human_approval(self) -> None:
        version = self.service.save_manifest(self.engagement["id"], self.manifest)
        bundle = self.service.compile_policy(version["id"])
        with self.assertRaisesRegex(DomainError, "exact human policy approval"):
            self.service.activate_policy(bundle["id"], actor_id="researcher")

    def test_expired_offset_approval_cannot_activate(self) -> None:
        version = self.service.save_manifest(self.engagement["id"], self.manifest)
        bundle = self.service.compile_policy(version["id"])
        approval_time = datetime.now(UTC)
        expiry = (approval_time + timedelta(minutes=1)).astimezone(timezone(timedelta(hours=10)))
        with patch("pentai_core.authorization._now", return_value=approval_time):
            approval = self.service.approve_policy(
                bundle["id"],
                approver_id="human-reviewer",
                expires_at=expiry.isoformat(),
            )
        self.assertTrue(approval["expires_at"].endswith("Z"))
        with (
            patch(
                "pentai_core.authorization._now",
                return_value=approval_time + timedelta(minutes=2),
            ),
            self.assertRaises(DomainError) as raised,
        ):
            self.service.activate_policy(bundle["id"], actor_id="human-reviewer")
        self.assertEqual(raised.exception.code, "APPROVAL_MISSING")

    def test_approval_uses_truthful_transaction_attestation(self) -> None:
        version = self.service.save_manifest(self.engagement["id"], self.manifest)
        bundle = self.service.compile_policy(version["id"])
        approval = self.service.approve_policy(bundle["id"], approver_id="human-reviewer")
        self.assertEqual(approval["schema_version"], "1.2.0")
        self.assertEqual(approval["signature"]["algorithm"], "Ed25519")
        self.assertEqual(contract_issues(approval, "approval-v1.schema.json"), ())

    def test_policy_and_approval_signatures_are_verified_before_activation(self) -> None:
        version = self.service.save_manifest(self.engagement["id"], self.manifest)
        bundle = self.service.compile_policy(version["id"])
        self.assertEqual(bundle["policy"]["signature"]["algorithm"], "Ed25519")
        approval = self.service.approve_policy(bundle["id"], approver_id="human-reviewer")
        self.assertEqual(approval["signature"]["algorithm"], "Ed25519")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE policy_bundles SET signature = ? WHERE id = ?",
                ("invalid", bundle["id"]),
            )
        with self.assertRaises(DomainError) as raised:
            self.service.activate_policy(bundle["id"], actor_id="human-reviewer")
        self.assertEqual(raised.exception.code, "POLICY_HASH_MISMATCH")

    def test_missing_signer_fails_closed_before_policy_persistence(self) -> None:
        unsigned_service = AuthorizationService(
            self.database, source_store=self.service.source_store
        )
        version = unsigned_service.save_manifest(self.engagement["id"], self.manifest)
        with self.assertRaises(DomainError) as raised:
            unsigned_service.compile_policy(version["id"])
        self.assertEqual(raised.exception.code, "POLICY_SIGNER_UNAVAILABLE")

    def test_key_rotation_fails_closed_for_existing_policy_authority(self) -> None:
        version = self.service.save_manifest(self.engagement["id"], self.manifest)
        bundle = self.service.compile_policy(version["id"])
        self.service.approve_policy(bundle["id"], approver_id="human-reviewer")
        rotated_service = AuthorizationService(
            self.database,
            source_store=self.service.source_store,
            policy_signer=PolicySigner(b"r" * 32),
        )
        with self.assertRaises(DomainError) as raised:
            rotated_service.activate_policy(bundle["id"], actor_id="human-reviewer")
        self.assertEqual(raised.exception.code, "POLICY_HASH_MISMATCH")

        self.service.activate_policy(bundle["id"], actor_id="human-reviewer")
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        with self.assertRaises(DomainError) as raised:
            rotated_service.evaluate_intent(self.engagement["id"], intent)
        self.assertEqual(raised.exception.code, "POLICY_SIGNATURE_INVALID")

    def test_policy_history_and_reasoned_revocation_are_durable(self) -> None:
        _, bundle = self.activate()
        history = self.service.list_policies(self.engagement["id"])
        self.assertEqual(history[0]["status"], "active")
        with self.assertRaises(DomainError) as raised:
            self.service.revoke_policy(bundle["id"], actor_id="human-reviewer", reason=" ")
        self.assertEqual(raised.exception.code, "REVOCATION_REASON_REQUIRED")
        self.service.revoke_policy(
            bundle["id"], actor_id="human-reviewer", reason="synthetic review withdrawal"
        )
        self.assertEqual(self.service.list_policies(self.engagement["id"])[0]["status"], "revoked")

    def test_edit_creates_version_and_does_not_inherit_approval(self) -> None:
        first = self.service.save_manifest(self.engagement["id"], self.manifest)
        first_bundle = self.service.compile_policy(first["id"])
        self.service.approve_policy(first_bundle["id"], approver_id="human-reviewer")

        edited = copy.deepcopy(self.manifest)
        edited["operational_limits"]["maximum_total_requests"] = 25
        second = self.service.save_manifest(self.engagement["id"], edited)
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(second["supersedes_id"], first["id"])
        second_bundle = self.service.compile_policy(second["id"])
        with self.assertRaises(DomainError) as raised:
            self.service.activate_policy(second_bundle["id"], actor_id="human-reviewer")
        self.assertEqual(raised.exception.code, "APPROVAL_MISSING")

    def test_manifest_history_is_versioned_idempotent_and_diffed(self) -> None:
        first = self.service.save_manifest(self.engagement["id"], self.manifest)
        duplicate = self.service.save_manifest(self.engagement["id"], copy.deepcopy(self.manifest))
        self.assertEqual(duplicate["id"], first["id"])
        self.assertEqual(duplicate["version_number"], 1)

        edited = copy.deepcopy(self.manifest)
        edited["reporting"]["submission_channel"] = "manual-portal"
        second = self.service.save_manifest(self.engagement["id"], edited)
        self.assertEqual(second["version_number"], 2)
        self.assertEqual(second["supersedes_id"], first["id"])
        self.assertEqual(
            [item["version_number"] for item in self.service.list_manifests(self.engagement["id"])],
            [2, 1],
        )
        difference = self.service.manifest_diff(self.engagement["id"], first["id"], second["id"])
        self.assertEqual(difference["changed_sections"], ["reporting"])
        self.assertEqual(
            difference, self.service.manifest_diff(self.engagement["id"], first["id"], second["id"])
        )

    def test_field_provenance_missing_unknown_or_stale_is_default_denied(self) -> None:
        for mutation, expected in (
            (lambda item: item.pop("field_provenance"), "CONTRACT_INVALID"),
            (
                lambda item: item["field_provenance"]["/scope"][0].update(
                    {"source_id": str(uuid4())}
                ),
                "PROVENANCE_MISSING",
            ),
            (
                lambda item: item["field_provenance"]["/scope"][0].update(
                    {"content_hash": "f" * 64}
                ),
                "PROVENANCE_HASH_MISMATCH",
            ),
        ):
            candidate = copy.deepcopy(self.manifest)
            mutation(candidate)
            version = self.service.save_manifest(self.engagement["id"], candidate)
            self.assertFalse(version["valid"])
            self.assertIn(expected, {issue["code"] for issue in version["issues"]})
            with self.assertRaises(DomainError):
                self.service.compile_policy(version["id"])

    def test_manifest_diff_cannot_cross_engagement_boundary(self) -> None:
        first = self.service.save_manifest(self.engagement["id"], self.manifest)
        other = self.service.create_engagement(
            self.program["id"],
            effective_from=timestamp(timedelta(hours=-1)),
            expires_at=timestamp(timedelta(hours=2)),
            timezone="UTC",
        )
        other_manifest = copy.deepcopy(self.manifest)
        other_manifest["engagement"].update(
            {key: other[key] for key in ("id", "effective_from", "expires_at", "timezone")}
        )
        second = self.service.save_manifest(other["id"], other_manifest)
        with self.assertRaises(DomainError) as raised:
            self.service.manifest_diff(self.engagement["id"], first["id"], second["id"])
        self.assertEqual(raised.exception.code, "MANIFEST_NOT_FOUND")

    def test_unresolved_manifest_is_rejected_and_audited(self) -> None:
        self.manifest["unresolved_questions"] = ["Does wildcard include the apex?"]
        version = self.service.save_manifest(self.engagement["id"], self.manifest)
        self.assertFalse(version["valid"])
        self.assertIn("AUTHORIZATION_AMBIGUOUS", {item["code"] for item in version["issues"]})
        with self.assertRaises(DomainError):
            self.service.compile_policy(version["id"])
        self.assertIn("policy.rejected", [event["action"] for event in self.service.audit_events()])

    def test_manifest_contract_and_engagement_binding_are_enforced(self) -> None:
        malformed = copy.deepcopy(self.manifest)
        malformed["scope"]["assets"][0]["effect"] = "unexpected"
        version = self.service.save_manifest(self.engagement["id"], malformed)
        self.assertFalse(version["valid"])
        self.assertIn("CONTRACT_INVALID", {item["code"] for item in version["issues"]})

        mismatched = copy.deepcopy(self.manifest)
        mismatched["engagement"]["id"] = str(uuid4())
        with self.assertRaises(DomainError) as raised:
            self.service.save_manifest(self.engagement["id"], mismatched)
        self.assertEqual(raised.exception.code, "ENGAGEMENT_MISMATCH")

    def test_approved_replacement_policy_atomically_retires_the_active_policy(self) -> None:
        _, first_bundle = self.activate()
        edited = copy.deepcopy(self.manifest)
        edited["operational_limits"]["maximum_total_requests"] = 25
        version = self.service.save_manifest(self.engagement["id"], edited)
        second_bundle = self.service.compile_policy(version["id"])
        self.service.approve_policy(second_bundle["id"], approver_id="human-reviewer")

        self.service.activate_policy(second_bundle["id"], actor_id="human-reviewer")

        with closing(sqlite3.connect(self.database)) as connection, connection:
            first = connection.execute(
                "SELECT revoked_at FROM policy_bundles WHERE id = ?",
                (first_bundle["id"],),
            ).fetchone()
            active = connection.execute(
                "SELECT active_policy_id, revocation_epoch FROM engagements WHERE id = ?",
                (self.engagement["id"],),
            ).fetchone()
        self.assertIsNotNone(first[0])
        self.assertEqual(active[0], second_bundle["id"])
        self.assertEqual(active[1], 1)

        with self.assertRaises(DomainError) as raised:
            self.service.activate_policy(first_bundle["id"], actor_id="human-reviewer")
        self.assertEqual(raised.exception.code, "POLICY_REVOKED")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            after = connection.execute(
                "SELECT active_policy_id FROM engagements WHERE id = ?",
                (self.engagement["id"],),
            ).fetchone()
            replacement = connection.execute(
                "SELECT revoked_at FROM policy_bundles WHERE id = ?",
                (second_bundle["id"],),
            ).fetchone()
        self.assertEqual(after[0], second_bundle["id"])
        self.assertIsNone(replacement[0])

    def test_duplicate_conditional_capability_is_rejected_without_crashing(self) -> None:
        duplicate = copy.deepcopy(self.manifest)
        duplicate["techniques"]["conditional_capabilities"] = [
            {
                "capability": "network.http.head",
                "approval_type": "conditional_action",
                "conditions": ["first"],
            },
            {
                "capability": "network.http.head",
                "approval_type": "conditional_action",
                "conditions": ["second"],
            },
        ]
        version = self.service.save_manifest(self.engagement["id"], duplicate)
        self.assertFalse(version["valid"])
        self.assertIn("CONTRADICTORY_RULES", {item["code"] for item in version["issues"]})
        with self.assertRaises(DomainError) as raised:
            self.service.compile_policy(version["id"])
        self.assertEqual(raised.exception.code, "CONTRADICTORY_RULES")

    def test_ambiguous_asset_authority_and_duplicate_matchers_fail_closed(self) -> None:
        cases: list[tuple[dict[str, object], str]] = []

        no_ports = copy.deepcopy(self.manifest)
        no_ports["scope"]["assets"][0]["allowed_ports"] = []
        cases.append((no_ports, "PORT_AUTHORITY_MISSING"))

        no_ownership = copy.deepcopy(self.manifest)
        no_ownership["scope"]["assets"][0]["ownership_verified"] = False
        cases.append((no_ownership, "OWNERSHIP_UNVERIFIED"))

        wildcard = copy.deepcopy(self.manifest)
        wildcard["scope"]["assets"][0].update(
            {"type": "wildcard_domain", "canonical_value": "*.example.test"}
        )
        cases.append((wildcard, "ASSET_AMBIGUOUS"))

        duplicate = copy.deepcopy(self.manifest)
        repeated = copy.deepcopy(duplicate["scope"]["assets"][0])
        repeated["asset_id"] = str(uuid4())
        duplicate["scope"]["assets"].append(repeated)
        cases.append((duplicate, "CONTRADICTORY_RULES"))

        for candidate, expected in cases:
            version = self.service.save_manifest(self.engagement["id"], candidate)
            self.assertFalse(version["valid"])
            self.assertIn(expected, {issue["code"] for issue in version["issues"]})
            with self.assertRaises(DomainError):
                self.service.compile_policy(version["id"])

    def test_url_port_and_path_cannot_broaden_canonical_authority(self) -> None:
        candidate = copy.deepcopy(self.manifest)
        candidate["scope"]["assets"][0].update(
            {
                "type": "url",
                "canonical_value": "https://example.test/api",
                "allowed_ports": [8443],
                "allowed_paths": ["/"],
            }
        )
        version = self.service.save_manifest(self.engagement["id"], candidate)
        codes = {issue["code"] for issue in version["issues"]}
        self.assertFalse(version["valid"])
        self.assertEqual(codes & {"CONTRADICTORY_RULES", "SCOPE_AMBIGUOUS"}, codes)
        self.assertEqual(codes, {"CONTRADICTORY_RULES", "SCOPE_AMBIGUOUS"})

    def test_limit_and_network_relationships_are_complete_and_consistent(self) -> None:
        candidate = copy.deepcopy(self.manifest)
        candidate["operational_limits"]["per_host_requests_per_second"] = 2
        candidate["agent_controls"]["maximum_runtime_minutes"] = 31
        candidate["network"].update(
            {
                "dns_mode": "approved_resolver",
                "registered_source_ipv6": ["2001:db8::1"],
            }
        )
        version = self.service.save_manifest(self.engagement["id"], candidate)
        self.assertFalse(version["valid"])
        codes = [issue["code"] for issue in version["issues"]]
        self.assertEqual(codes.count("LIMITS_INVALID"), 2)
        self.assertIn("CONTRADICTORY_RULES", codes)
        self.assertIn("NETWORK_CONSTRAINTS_INCOMPLETE", codes)

    def test_manifest_requires_an_explicitly_allowed_capability(self) -> None:
        candidate = copy.deepcopy(self.manifest)
        candidate["techniques"]["allowed_capabilities"] = []
        candidate["techniques"]["allowed_http_methods"] = []
        version = self.service.save_manifest(self.engagement["id"], candidate)
        self.assertFalse(version["valid"])
        self.assertIn("TECHNIQUES_INCOMPLETE", {item["code"] for item in version["issues"]})

    def test_typed_matcher_specificity_is_deterministic(self) -> None:
        candidate = copy.deepcopy(self.manifest)
        source_id = self.source["id"]
        candidate["scope"]["assets"] = [
            {
                "asset_id": str(uuid4()),
                "effect": "deny",
                "type": "cidr",
                "canonical_value": "192.0.2.0/24",
                "allowed_ports": [443],
                "source_reference": source_id,
            },
            {
                "asset_id": str(uuid4()),
                "effect": "allow",
                "type": "ipv4",
                "canonical_value": "192.0.2.10",
                "allowed_ports": [443],
                "allowed_paths": ["/api"],
                "ownership_verified": True,
                "source_reference": source_id,
            },
        ]
        version = self.service.save_manifest(self.engagement["id"], candidate)
        self.assertTrue(version["valid"], version["issues"])
        bundle = self.service.compile_policy(version["id"])
        self.service.approve_policy(bundle["id"], approver_id="human-reviewer")
        self.service.activate_policy(bundle["id"], actor_id="human-reviewer")
        exact = intent_for(self.engagement["id"], bundle["content_hash"], "https://192.0.2.10/api")
        other = intent_for(self.engagement["id"], bundle["content_hash"], "https://192.0.2.11/api")
        self.assertEqual(
            self.service.evaluate_intent(self.engagement["id"], exact)["reason_codes"],
            ["EXPLICIT_ALLOW"],
        )
        self.assertEqual(
            self.service.evaluate_intent(self.engagement["id"], other)["reason_codes"],
            ["EXPLICIT_DENY"],
        )

    def test_audit_chain_covers_lifecycle_and_detects_tampering(self) -> None:
        _, bundle = self.activate()
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        self.service.evaluate_intent(self.engagement["id"], intent)
        rejected_version = self.service.save_manifest(self.engagement["id"], self.manifest)
        rejected_bundle = self.service.compile_policy(rejected_version["id"])
        self.service.approve_policy(
            rejected_bundle["id"],
            approver_id="human-reviewer",
            decision="rejected",
            reason="review declined",
        )
        self.service.revoke_policy(
            bundle["id"], actor_id="human-reviewer", reason="synthetic test complete"
        )
        actions = {event["action"] for event in self.service.audit_events()}
        self.assertTrue(
            {
                "policy.approval",
                "policy.activation",
                "policy.rejection",
                "policy.revocation",
                "policy.evaluation",
            }
            <= actions
        )
        self.assertTrue(self.service.verify_audit_chain()["valid"])
        with closing(sqlite3.connect(self.database)) as connection, connection:
            event = connection.execute(
                "SELECT event_id FROM audit_events ORDER BY sequence LIMIT 1"
            ).fetchone()
            connection.execute(
                "UPDATE audit_events SET data_json = ? WHERE event_id = ?",
                (json.dumps({"tampered": True}), event[0]),
            )
        verification = self.service.verify_audit_chain()
        self.assertFalse(verification["valid"])
        self.assertEqual(verification["failed_sequence"], 1)

    def test_activated_policy_and_approved_manifest_are_database_immutable(self) -> None:
        version, bundle = self.activate()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE policy_bundles SET content_hash = ? WHERE id = ?",
                    ("f" * 64, bundle["id"]),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE manifest_versions SET content_hash = ? WHERE id = ?",
                    ("e" * 64, version["id"]),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE manifest_versions SET supersedes_id = NULL WHERE id = ?",
                    (version["id"],),
                )
            approval = connection.execute(
                "SELECT id FROM approvals WHERE policy_bundle_id = ?",
                (bundle["id"],),
            ).fetchone()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE approvals SET document_json = '{}' WHERE id = ?",
                    (approval[0],),
                )


if __name__ == "__main__":
    unittest.main()
