from __future__ import annotations

import copy
import unittest
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pentai_core.worker_containment import (
    ContainmentError,
    prepare_worker_launch,
    validate_worker_containment_attestation,
)
from pentai_policy.document import contract_issues


def timestamp(offset: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) + offset).isoformat().replace("+00:00", "Z")


def containment_attestation() -> dict[str, object]:
    return {
        "schema_version": "2.0.0",
        "attestation_id": str(uuid4()),
        "runtime": "podman",
        "runtime_instance_id": "fixture:rootless-runtime",
        "network_role": "worker_gateway",
        "rootless": True,
        "read_only_root": True,
        "capabilities_dropped": True,
        "no_new_privileges": True,
        "host_pid_disabled": True,
        "host_ipc_disabled": True,
        "host_network_disabled": True,
        "runtime_socket_mounted": False,
        "resource_limits_supported": True,
        "temporary_mounts_only": True,
        "worker_gateway_network_id": "fixture:internal-worker-gateway-network",
        "direct_egress_disabled": True,
        "external_dns_disabled": True,
        "ipv6_disabled": True,
        "observed_at": timestamp(timedelta(seconds=-1)),
        "expires_at": timestamp(timedelta(seconds=30)),
    }


def prepared_session() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "session_id": str(uuid4()),
        "reservation_id": str(uuid4()),
        "grant_id": str(uuid4()),
        "attestation_id": str(uuid4()),
        "destination_authorization_id": str(uuid4()),
        "status": "prepared",
        "request_count": 1,
        "response_bytes_limit": 100_000,
        "prepared_at": timestamp(timedelta(seconds=-1)),
        "execution_enabled": False,
    }


class WorkerContainmentTests(unittest.TestCase):
    def test_prepares_locked_down_non_executing_launch_spec(self) -> None:
        result = prepare_worker_launch(
            session=prepared_session(),
            containment_attestation=containment_attestation(),
            image_digest="sha256:" + "a" * 64,
            argv=["fixture-tool", "--safe-mode"],
        )
        self.assertEqual(contract_issues(result, "worker-launch-spec-v1.schema.json"), ())
        self.assertEqual(result["network_mode"], "gateway_only")
        self.assertEqual(result["gateway_network_id"], "fixture:internal-worker-gateway-network")
        self.assertEqual(result["drop_capabilities"], "ALL")
        self.assertFalse(result["mount_runtime_socket"])
        self.assertFalse(result["external_dns_enabled"])
        self.assertFalse(result["ipv6_enabled"])
        self.assertFalse(result["execution_enabled"])

    def test_fixture_or_ambiguous_network_role_cannot_plan_worker_launch(self) -> None:
        historical = containment_attestation()
        historical["schema_version"] = "1.0.0"
        historical["gateway_network_id"] = historical.pop("worker_gateway_network_id")
        historical.pop("network_role")

        wrong_role = containment_attestation()
        wrong_role["network_role"] = "gateway_target_fixture"

        ambiguous = containment_attestation()
        ambiguous["gateway_network_id"] = ambiguous["worker_gateway_network_id"]

        missing_role = containment_attestation()
        missing_role.pop("network_role")

        missing_network = containment_attestation()
        missing_network.pop("worker_gateway_network_id")

        for document in (
            historical,
            wrong_role,
            ambiguous,
            missing_role,
            missing_network,
        ):
            with self.subTest(document=document), self.assertRaises(ContainmentError) as raised:
                prepare_worker_launch(
                    session=prepared_session(),
                    containment_attestation=document,
                    image_digest="sha256:" + "a" * 64,
                    argv=["fixture-tool"],
                )
            self.assertEqual(raised.exception.code, "CONTAINMENT_ATTESTATION_INVALID")

    def test_every_required_containment_property_fails_closed(self) -> None:
        required_true = (
            "rootless",
            "read_only_root",
            "capabilities_dropped",
            "no_new_privileges",
            "host_pid_disabled",
            "host_ipc_disabled",
            "host_network_disabled",
            "resource_limits_supported",
            "temporary_mounts_only",
            "direct_egress_disabled",
            "external_dns_disabled",
            "ipv6_disabled",
        )
        for field in required_true:
            with self.subTest(field=field), self.assertRaises(ContainmentError) as raised:
                document = containment_attestation()
                document[field] = False
                validate_worker_containment_attestation(document)
            self.assertEqual(raised.exception.code, "CONTAINMENT_ATTESTATION_INVALID")

        with self.assertRaises(ContainmentError) as raised:
            document = containment_attestation()
            document["runtime_socket_mounted"] = True
            validate_worker_containment_attestation(document)
        self.assertEqual(raised.exception.code, "CONTAINMENT_ATTESTATION_INVALID")

    def test_stale_attestation_and_finalized_session_deny(self) -> None:
        stale = containment_attestation()
        stale["expires_at"] = timestamp(timedelta(seconds=-1))
        with self.assertRaises(ContainmentError) as raised:
            validate_worker_containment_attestation(stale)
        self.assertEqual(raised.exception.code, "CONTAINMENT_ATTESTATION_STALE")

        session = prepared_session()
        session["status"] = "aborted"
        session["finalized_at"] = timestamp()
        with self.assertRaises(ContainmentError) as raised:
            prepare_worker_launch(
                session=session,
                containment_attestation=containment_attestation(),
                image_digest="sha256:" + "a" * 64,
                argv=["fixture-tool"],
            )
        self.assertEqual(raised.exception.code, "GATEWAY_SESSION_INACTIVE")

    def test_attestation_window_is_short_and_well_ordered(self) -> None:
        cases = (
            (timedelta(seconds=-1), timedelta(minutes=2)),
            (timedelta(seconds=10), timedelta(seconds=20)),
            (timedelta(seconds=-1), timedelta(seconds=-2)),
        )
        for observed_offset, expiry_offset in cases:
            with self.subTest(observed_offset=observed_offset, expiry_offset=expiry_offset):
                document = containment_attestation()
                document["observed_at"] = timestamp(observed_offset)
                document["expires_at"] = timestamp(expiry_offset)
                with self.assertRaises(ContainmentError):
                    validate_worker_containment_attestation(document)

    def test_invalid_image_command_and_resource_limits_deny(self) -> None:
        cases = (
            {"image_digest": "latest", "argv": ["fixture-tool"]},
            {"image_digest": "sha256:" + "a" * 64, "argv": []},
            {
                "image_digest": "sha256:" + "a" * 64,
                "argv": ["fixture-tool"],
                "pid_limit": 0,
            },
            {"image_digest": "sha256:" + "a" * 64, "argv": ["fixture\x00tool"]},
            {"image_digest": "sha256:" + "a" * 64, "argv": ["x" * 4097]},
            {"image_digest": "sha256:" + "a" * 64, "argv": ["x"] * 65},
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), self.assertRaises(ContainmentError):
                prepare_worker_launch(
                    session=copy.deepcopy(prepared_session()),
                    containment_attestation=copy.deepcopy(containment_attestation()),
                    **arguments,
                )


if __name__ == "__main__":
    unittest.main()
