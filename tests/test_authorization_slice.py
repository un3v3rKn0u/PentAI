from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.migrate import migrate
from pentai_core.source_store import EncryptedSourceStore
from pentai_policy import canonicalize_url, content_hash, evaluate
from pentai_policy.document import contract_issues


def timestamp(offset: timedelta) -> str:
    return (datetime.now(UTC) + offset).isoformat().replace("+00:00", "Z")


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
    return {
        "schema_version": "1.0.0",
        "intent_id": str(uuid4()),
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
        "idempotency_key": "synthetic-intent-0001",
    }


class AuthorizationSliceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        migrate(self.database)
        self.service = AuthorizationService(
            self.database,
            source_store=EncryptedSourceStore(Path(self.temporary.name) / "sources", b"k" * 32),
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
        self.service.approve_policy(bundle["id"], approver_id="human-reviewer")
        self.service.activate_policy(bundle["id"], actor_id="human-reviewer")
        return version, bundle

    def test_exact_request_is_allowed_and_deterministic(self) -> None:
        _, bundle = self.activate()
        intent = intent_for(self.engagement["id"], bundle["content_hash"])
        first = self.service.evaluate_intent(self.engagement["id"], intent)
        second = self.service.evaluate_intent(self.engagement["id"], intent)
        self.assertEqual(first, second)
        self.assertEqual(first["outcome"], "allow")
        self.assertEqual(first["reason_codes"], ["EXPLICIT_ALLOW"])

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
            {key: value for key, value in expired.items() if key != "content_hash"}
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
        self.assertEqual(approval["schema_version"], "1.1.0")
        self.assertEqual(approval["signature"]["algorithm"], "local-transaction-sha256")
        self.assertEqual(contract_issues(approval, "approval-v1.schema.json"), ())

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

        with sqlite3.connect(self.database) as connection:
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
        with sqlite3.connect(self.database) as connection:
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
        with sqlite3.connect(self.database) as connection:
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
        with sqlite3.connect(self.database) as connection:
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
