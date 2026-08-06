from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
import uuid
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from pentai_core.authorization import AuthorizationError, AuthorizationService
from pentai_policy import compile_manifest, source_content_hash, validate_manifest

NOW = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)


def valid_manifest(source_id: str, source_hash: str, engagement_id: str) -> dict[str, object]:
    return {
        "schema_version": "2.0.0",
        "engagement": {
            "id": engagement_id,
            "organization": "Example Research Program",
            "program_name": "Synthetic Web Scope",
            "program_type": "vdp",
            "status": "draft",
            "effective_from": "2026-08-01T00:00:00Z",
            "expires_at": "2027-08-01T00:00:00Z",
            "timezone": "UTC",
        },
        "sources": [
            {
                "source_id": source_id,
                "reference": "synthetic authorization.txt",
                "authority": "contract",
                "retrieved_at": "2026-08-01T00:00:00Z",
                "content_hash": source_hash,
            }
        ],
        "scope": {
            "assets": [
                {
                    "asset_id": str(uuid.uuid4()),
                    "effect": "allow",
                    "type": "url",
                    "canonical_value": "https://api.example.test/api",
                    "allowed_paths": ["/api"],
                    "denied_paths": ["/api/admin"],
                    "allowed_ports": [443],
                    "source_reference": source_id,
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
            "requests_per_second": 2,
            "per_host_requests_per_second": 1,
            "burst_limit": 2,
            "concurrent_connections": 1,
            "maximum_runtime_minutes": 30,
            "maximum_total_requests": 100,
            "maximum_response_bytes": 1048576,
            "stop_conditions": ["authorization changes"],
        },
        "network": {
            "route_mode": "local_gateway",
            "route_profile_id": "simulation-only",
            "registered_source_ipv4": [],
            "registered_source_ipv6": [],
            "ipv6_mode": "disabled",
            "dns_mode": "approved_resolver",
            "pause_on_identity_change": True,
        },
        "data_handling": {
            "real_user_data": "avoid_and_stop",
            "retention_days": 30,
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
            "maximum_test_depth": 0,
            "maximum_runtime_minutes": 30,
            "human_approval_required_for": [],
        },
        "approvals": {
            "scope_reviewer": "reviewer",
            "rules_reviewer": "reviewer",
            "technical_controls_reviewer": "reviewer",
            "status": "pending",
        },
        "unresolved_questions": [],
    }


def intent(policy_hash: str, url: str = "https://api.example.test/api/items") -> dict[str, object]:
    from pentai_policy.canonicalize import canonicalize_url

    target = canonicalize_url(url)
    return {
        "schema_version": "1.0.0",
        "intent_id": str(uuid.uuid4()),
        "assessment_id": str(uuid.uuid4()),
        "policy_hash": policy_hash,
        "actor": {"actor_type": "human", "actor_id": "local-reviewer"},
        "capability": "network.http.get",
        "target": target,
        "http": {
            "method": "GET",
            "headers_digest": "0" * 64,
            "body_digest": None,
            "follow_redirects": False,
        },
        "parameters_digest": "1" * 64,
        "impact": "benign",
        "created_at": "2026-08-06T12:00:00Z",
        "expires_at": "2026-08-06T12:05:00Z",
        "idempotency_key": str(uuid.uuid4()),
    }


class AuthorizationSliceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "pentai.db"
        self.service = AuthorizationService(self.database)
        self.program = self.service.create_program("Synthetic program")
        content = "Synthetic authorization for example.test only."
        self.source = self.service.import_source(
            self.program["id"], reference="authorization.txt", authority="contract", content=content
        )
        self.manifest = valid_manifest(
            self.source["id"], source_content_hash(content), str(uuid.uuid4())
        )
        self.version = self.service.create_engagement(self.program["id"], self.manifest)
        self.policy = self.service.compile(self.version["id"])

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def activate(self) -> None:
        self.service.approve(
            self.policy["policy_id"],
            approver_id="human-reviewer",
            expires_at="2027-01-01T00:00:00Z",
        )
        self.service.activate(self.policy["policy_id"], actor_id="human-reviewer")

    def test_exact_approved_active_request_is_allowed_and_repeatable(self) -> None:
        self.activate()
        request = intent(self.policy["content_hash"])
        first = self.service.evaluate_intent(self.policy["policy_id"], request, now=NOW)
        second = self.service.evaluate_intent(self.policy["policy_id"], request, now=NOW)
        self.assertEqual(first, second)
        self.assertEqual(first["outcome"], "allow")
        self.assertEqual(first["reason_codes"], ["EXPLICIT_ALLOW"])

    def test_ambiguous_altered_expired_and_out_of_scope_requests_deny(self) -> None:
        self.activate()
        ambiguous = intent(self.policy["content_hash"])
        ambiguous["target"]["path"] = "/different"
        self.assertEqual(
            self.service.evaluate_intent(self.policy["policy_id"], ambiguous, now=NOW)[
                "reason_codes"
            ],
            ["TARGET_AMBIGUOUS"],
        )
        altered = intent("f" * 64)
        self.assertEqual(
            self.service.evaluate_intent(self.policy["policy_id"], altered, now=NOW)[
                "reason_codes"
            ],
            ["POLICY_HASH_MISMATCH"],
        )
        expired = self.service.evaluate_intent(
            self.policy["policy_id"],
            intent(self.policy["content_hash"]),
            now=datetime(2028, 1, 1, tzinfo=UTC),
        )
        self.assertEqual(expired["reason_codes"], ["POLICY_EXPIRED"])
        outside = self.service.evaluate_intent(
            self.policy["policy_id"],
            intent(self.policy["content_hash"], "https://outside.example.test/api"),
            now=NOW,
        )
        self.assertEqual(outside["reason_codes"], ["TARGET_OUT_OF_SCOPE"])

    def test_explicit_deny_and_path_boundaries(self) -> None:
        self.activate()
        denied = self.service.evaluate_intent(
            self.policy["policy_id"],
            intent(self.policy["content_hash"], "https://api.example.test/api/admin/users"),
            now=NOW,
        )
        self.assertEqual(denied["reason_codes"], ["EXPLICIT_DENY"])
        lookalike = self.service.evaluate_intent(
            self.policy["policy_id"],
            intent(self.policy["content_hash"], "https://api.example.test/apiv2"),
            now=NOW,
        )
        self.assertEqual(lookalike["reason_codes"], ["TARGET_OUT_OF_SCOPE"])

    def test_activation_requires_exact_current_human_approval(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "approval"):
            self.service.activate(self.policy["policy_id"], actor_id="human-reviewer")
        with self.assertRaisesRegex(AuthorizationError, "future"):
            self.service.approve(
                self.policy["policy_id"],
                approver_id="human-reviewer",
                expires_at="2020-01-01T00:00:00Z",
            )

    def test_editing_creates_new_version_without_inheriting_approval(self) -> None:
        self.service.approve(
            self.policy["policy_id"],
            approver_id="human-reviewer",
            expires_at="2027-01-01T00:00:00Z",
        )
        edited = deepcopy(self.manifest)
        edited["scope"]["assets"][0]["allowed_paths"] = ["/api/v2"]
        version = self.service.save_manifest(self.manifest["engagement"]["id"], edited)
        policy = self.service.compile(version["id"])
        self.assertNotEqual(policy["manifest_hash"], self.policy["manifest_hash"])
        with self.assertRaisesRegex(AuthorizationError, "approval"):
            self.service.activate(policy["policy_id"], actor_id="human-reviewer")

    def test_audit_chain_covers_events_and_detects_tampering(self) -> None:
        self.activate()
        self.service.evaluate_intent(
            self.policy["policy_id"], intent(self.policy["content_hash"]), now=NOW
        )
        self.service.revoke(self.policy["policy_id"], actor_id="human-reviewer")
        actions = [event["action"] for event in self.service.audit_events()]
        self.assertTrue(
            {"approval", "activation", "policy_evaluation", "revocation"} <= set(actions)
        )
        self.assertTrue(self.service.verify_audit_chain()["valid"])
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE audit_events SET data_json = ? WHERE sequence = 1", ('{"tampered":true}',)
            )
        self.assertFalse(self.service.verify_audit_chain()["valid"])

    def test_rejection_is_audited(self) -> None:
        self.service.approve(
            self.policy["policy_id"],
            approver_id="human-reviewer",
            expires_at="2027-01-01T00:00:00Z",
            decision="rejected",
        )
        self.assertEqual(self.service.audit_events()[-1]["action"], "rejection")

    def test_manifest_validation_and_compilation_are_deterministic(self) -> None:
        first = validate_manifest(self.manifest)
        reordered = json.loads(json.dumps(self.manifest))
        reordered["techniques"]["allowed_capabilities"] = list(
            reversed(reordered["techniques"]["allowed_capabilities"])
        )
        second = validate_manifest(reordered)
        self.assertEqual(first["content_hash"], second["content_hash"])
        self.assertEqual(compile_manifest(self.manifest), compile_manifest(reordered))
        unresolved = deepcopy(self.manifest)
        unresolved["unresolved_questions"] = ["Does the wildcard include the apex?"]
        self.assertFalse(validate_manifest(unresolved)["valid"])
        unknown = deepcopy(self.manifest)
        unknown["assumptions"] = ["Never infer authorization"]
        result = validate_manifest(unknown)
        self.assertFalse(result["valid"])
        self.assertIn("UNKNOWN_FIELD", [issue["code"] for issue in result["issues"]])

    def test_recompilation_is_idempotent_and_new_manifest_supersedes_old_approval(self) -> None:
        self.assertEqual(self.service.compile(self.version["id"]), self.policy)
        self.service.approve(
            self.policy["policy_id"],
            approver_id="human-reviewer",
            expires_at="2027-01-01T00:00:00Z",
        )
        edited = deepcopy(self.manifest)
        edited["scope"]["assets"][0]["allowed_paths"] = ["/api/v2"]
        self.service.save_manifest(self.manifest["engagement"]["id"], edited)
        with self.assertRaisesRegex(AuthorizationError, "approval"):
            self.service.activate(self.policy["policy_id"], actor_id="human-reviewer")
