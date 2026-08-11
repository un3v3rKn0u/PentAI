from __future__ import annotations

import json
import sqlite3
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pentai_core.authorization import AuthorizationService, DomainError
from pentai_core.migrate import migrate
from pentai_core.network_attestation_adapters import HostRouteSnapshot
from pentai_core.network_profile_setup import NetworkProfileSetupService
from pentai_policy.document import contract_issues

NOW = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)


class Probe:
    def inspect(self) -> HostRouteSnapshot:
        return HostRouteSnapshot("fixture0", "192.0.2.1", ("192.0.2.53",))


def setup_service(database: Path) -> tuple[AuthorizationService, dict[str, object]]:
    migrate(database)
    service = AuthorizationService(database)
    proposal = NetworkProfileSetupService(Probe(), clock=lambda: NOW).discover()
    with patch("pentai_core.authorization._now", return_value=NOW):
        service.save_network_profile_proposal(proposal)
    return service, proposal


def activate(
    service: AuthorizationService,
    proposal: dict[str, object],
    **changes: object,
) -> dict[str, Any]:
    values: dict[str, Any] = {
        "confirm_route": True,
        "resolver_mode": "tunnel_resolver",
        "registered_source_ipv4": ["8.8.8.8"],
        "registered_source_ipv6": [],
        "ipv6_mode": "disabled",
        "actor_id": "local-human",
    }
    values.update(changes)
    with patch("pentai_core.authorization._now", return_value=NOW + timedelta(seconds=1)):
        return service.activate_network_profile(str(proposal["proposal_id"]), **values)


def insert_active_policy(
    database: Path,
    profile: dict[str, Any] | None,
    *,
    engagement_id: str = "assessment-a",
    network_changes: dict[str, Any] | None = None,
) -> None:
    network = {
        "route_profile_id": profile["route_profile_id"] if profile else "route-missing",
        "registered_source_ipv4": profile["registered_source_ipv4"] if profile else ["8.8.8.8"],
        "registered_source_ipv6": profile["registered_source_ipv6"] if profile else [],
        "ipv6_mode": profile["ipv6_mode"] if profile else "disabled",
        "dns_mode": profile["resolver_mode"] if profile else "tunnel_resolver",
        "pause_on_identity_change": True,
    }
    network.update(network_changes or {})
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO programs(id, name, status) VALUES ('program-a', 'fixture', 'active')"
        )
        connection.execute(
            """
            INSERT INTO engagements(
                id, program_id, status, effective_from, expires_at, timezone
            ) VALUES (?, 'program-a', 'active', ?, ?, 'UTC')
            """,
            (engagement_id, NOW.isoformat(), (NOW + timedelta(days=1)).isoformat()),
        )
        connection.execute(
            """
            INSERT INTO manifest_versions(
                id, engagement_id, schema_version, document_json, content_hash,
                validation_status
            ) VALUES ('manifest-a', ?, '2.0.0', '{}', ?, 'valid')
            """,
            (engagement_id, "b" * 64),
        )
        connection.execute(
            """
            INSERT INTO policy_bundles(
                id, engagement_id, manifest_version_id, schema_version,
                compiler_version, policy_json, content_hash, activated_at
            ) VALUES ('policy-a', ?, 'manifest-a', '1.0.0', 'fixture', ?, ?, ?)
            """,
            (
                engagement_id,
                json.dumps({"network_constraints": network}),
                "a" * 64,
                NOW.isoformat(),
            ),
        )
        connection.execute(
            "UPDATE engagements SET active_policy_id = 'policy-a' WHERE id = ?",
            (engagement_id,),
        )


def test_confirmation_persists_one_non_executing_profile_and_audits_without_source_ip(
    tmp_path: Path,
) -> None:
    service, proposal = setup_service(tmp_path / "pentai.db")

    profile = activate(service, proposal)

    assert contract_issues(profile, "network-profile-v1.schema.json") == ()
    assert profile["status"] == "active"
    assert profile["execution_enabled"] is False
    assert service.list_network_profiles() == [profile]
    events = service.audit_events()
    assert events[-1]["action"] == "network_profile.activated"
    assert "8.8.8.8" not in json.dumps(events[-1])
    assert service.verify_audit_chain()["valid"] is True


def test_revocation_is_durable_audited_and_cannot_repeat(tmp_path: Path) -> None:
    service, proposal = setup_service(tmp_path / "pentai.db")
    profile = activate(service, proposal)

    with patch("pentai_core.authorization._now", return_value=NOW + timedelta(seconds=2)):
        revoked = service.revoke_network_profile(
            str(profile["profile_id"]), reason="Operator changed route", actor_id="local-human"
        )

    assert revoked["status"] == "revoked"
    assert revoked["revocation_reason"] == "Operator changed route"
    assert contract_issues(revoked, "network-profile-v1.schema.json") == ()
    assert service.audit_events()[-1]["action"] == "network_profile.revoked"
    with pytest.raises(DomainError) as raised:
        service.revoke_network_profile(
            str(profile["profile_id"]), reason="again", actor_id="local-human"
        )
    assert raised.value.code == "NETWORK_PROFILE_REVOKED"


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"confirm_route": False}, "NETWORK_PROFILE_CONFIRMATION_REQUIRED"),
        ({"resolver_mode": "ambient"}, "NETWORK_PROFILE_RESOLVER_INVALID"),
        ({"registered_source_ipv4": []}, "NETWORK_PROFILE_SOURCE_REQUIRED"),
        ({"registered_source_ipv4": ["127.0.0.1"]}, "NETWORK_PROFILE_SOURCE_INVALID"),
        ({"registered_source_ipv4": ["224.0.0.1"]}, "NETWORK_PROFILE_SOURCE_INVALID"),
        (
            {"registered_source_ipv6": ["2001:4860:4860::8888"]},
            "NETWORK_PROFILE_IPV6_CONFLICT",
        ),
        (
            {"registered_source_ipv4": [], "ipv6_mode": "approved_only"},
            "NETWORK_PROFILE_IPV6_REQUIRED",
        ),
    ],
)
def test_confirmation_defaults_deny_invalid_or_ambiguous_input(
    tmp_path: Path, changes: dict[str, object], code: str
) -> None:
    service, proposal = setup_service(tmp_path / "pentai.db")
    with pytest.raises(DomainError) as raised:
        activate(service, proposal, **changes)
    assert raised.value.code == code
    assert service.list_network_profiles() == []


def test_stale_replayed_and_conflicting_activation_are_denied(tmp_path: Path) -> None:
    service, proposal = setup_service(tmp_path / "pentai.db")
    with patch("pentai_core.authorization._now", return_value=NOW + timedelta(minutes=6)):
        with pytest.raises(DomainError) as stale:
            service.activate_network_profile(
                str(proposal["proposal_id"]),
                confirm_route=True,
                resolver_mode="tunnel_resolver",
                registered_source_ipv4=["8.8.8.8"],
                registered_source_ipv6=[],
                ipv6_mode="disabled",
                actor_id="local-human",
            )
    assert stale.value.code == "NETWORK_PROFILE_PROPOSAL_STALE"

    fresh = NetworkProfileSetupService(
        Probe(), clock=lambda: NOW + timedelta(minutes=1)
    ).discover()
    with patch("pentai_core.authorization._now", return_value=NOW + timedelta(minutes=1)):
        service.save_network_profile_proposal(fresh)
    first = activate(service, fresh)
    with pytest.raises(DomainError) as replay:
        activate(service, fresh)
    assert replay.value.code == "NETWORK_PROFILE_PROPOSAL_USED"

    another = NetworkProfileSetupService(
        Probe(), clock=lambda: NOW + timedelta(minutes=2)
    ).discover()
    with patch("pentai_core.authorization._now", return_value=NOW + timedelta(minutes=2)):
        service.save_network_profile_proposal(another)
    with pytest.raises(DomainError) as conflict:
        activate(service, another)
    assert conflict.value.code == "NETWORK_PROFILE_ACTIVE_CONFLICT"
    assert first["status"] == "active"


def test_database_rejects_mutation_and_deletion_of_profile_history(tmp_path: Path) -> None:
    service, proposal = setup_service(tmp_path / "pentai.db")
    profile = activate(service, proposal)
    connection = sqlite3.connect(tmp_path / "pentai.db")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="identity is immutable"):
            connection.execute(
                "UPDATE network_profiles SET route_interface = 'other' WHERE profile_id = ?",
                (profile["profile_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="history cannot be deleted"):
            connection.execute(
                "DELETE FROM network_profiles WHERE profile_id = ?", (profile["profile_id"],)
            )
    finally:
        connection.close()


def test_proposal_storage_rejects_tampered_identity_and_unbounded_lifetime(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pentai.db"
    migrate(database)
    service = AuthorizationService(database)
    proposal = NetworkProfileSetupService(Probe(), clock=lambda: NOW).discover()
    tampered = deepcopy(proposal)
    tampered["route_interface"] = "attacker-controlled"
    with patch("pentai_core.authorization._now", return_value=NOW):
        with pytest.raises(DomainError) as identity:
            service.save_network_profile_proposal(tampered)
    assert identity.value.code == "NETWORK_PROFILE_PROPOSAL_INVALID"

    unbounded = deepcopy(proposal)
    unbounded["expires_at"] = (NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    with patch("pentai_core.authorization._now", return_value=NOW):
        with pytest.raises(DomainError) as lifetime:
            service.save_network_profile_proposal(unbounded)
    assert lifetime.value.code == "NETWORK_PROFILE_PROPOSAL_STALE"


def test_pending_proposal_capacity_is_bounded(tmp_path: Path) -> None:
    database = tmp_path / "pentai.db"
    migrate(database)
    service = AuthorizationService(database)
    discovery = NetworkProfileSetupService(Probe(), clock=lambda: NOW)
    with patch("pentai_core.authorization._now", return_value=NOW):
        for _ in range(64):
            service.save_network_profile_proposal(discovery.discover())
        with pytest.raises(DomainError) as capacity:
            service.save_network_profile_proposal(discovery.discover())
    assert capacity.value.code == "NETWORK_PROFILE_PROPOSAL_CAPACITY"


def test_active_policy_resolves_only_an_exact_confirmed_profile(tmp_path: Path) -> None:
    database = tmp_path / "pentai.db"
    service, proposal = setup_service(database)
    profile = activate(service, proposal)
    insert_active_policy(database, profile)

    assert service.network_profile_for_assessment("assessment-a") == profile


def test_policy_profile_mismatch_and_missing_binding_default_deny(tmp_path: Path) -> None:
    mismatch_database = tmp_path / "mismatch.db"
    mismatch_service, proposal = setup_service(mismatch_database)
    profile = activate(mismatch_service, proposal)
    insert_active_policy(
        mismatch_database,
        profile,
        network_changes={"route_profile_id": "route-000000000000000000000000"},
    )
    with pytest.raises(DomainError) as mismatch:
        mismatch_service.network_profile_for_assessment("assessment-a")
    assert mismatch.value.code == "NETWORK_PROFILE_POLICY_MISMATCH"

    missing_database = tmp_path / "missing.db"
    migrate(missing_database)
    missing_service = AuthorizationService(missing_database)
    insert_active_policy(missing_database, None)
    with pytest.raises(DomainError) as missing:
        missing_service.network_profile_for_assessment("assessment-a")
    assert missing.value.code == "NETWORK_PROFILE_BINDING_MISSING"
