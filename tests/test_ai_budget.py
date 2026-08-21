from __future__ import annotations

import copy
import threading
import unittest
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pentai_core.ai_budget import AIBudgetError, AIBudgetLedger
from pentai_core.ai_provider_config import ProviderPolicy
from pentai_core.ai_provider_registry import build_provider_policy
from pentai_policy.document import contract_issues

NOW = datetime(2026, 8, 21, 9, 0, tzinfo=UTC)


@dataclass
class Clock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value


def provider_policy() -> ProviderPolicy:
    registry: dict[str, object] = {
        "schema_version": "1.0.0",
        "registry_id": str(uuid4()),
        "revision": 3,
        "providers": [
            {
                "provider_id": "remote-approved",
                "provider_type": "approved_remote",
                "models": ["remote-model-v1"],
                "allowed_input_classifications": ["public"],
                "state": "enabled",
            }
        ],
        "budget_ceilings": {
            "max_input_tokens": 100,
            "max_output_tokens": 50,
            "max_requests": 2,
            "max_cost_microusd": 1_000,
            "max_runtime_seconds": 30,
        },
        "remote_providers_enabled": True,
        "configured_at": (NOW - timedelta(days=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=10)).isoformat(),
        "execution_enabled": False,
    }
    return build_provider_policy(registry, now=NOW)


def configuration() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "configuration_id": str(uuid4()),
        "provider_type": "approved_remote",
        "provider_id": "remote-approved",
        "model_id": "remote-model-v1",
        "secret_ref": "secretref://provider/remote-approved/12345678-1234-4234-8234-123456789abc",
        "privacy_classification": "remote_third_party",
        "allowed_input_classifications": ["public"],
        "budgets": {
            "max_input_tokens": 100,
            "max_output_tokens": 50,
            "max_requests": 2,
            "max_cost_microusd": 1_000,
            "max_runtime_seconds": 30,
        },
        "remote_provider_opt_in": True,
        "configured_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(days=7)).isoformat(),
        "execution_enabled": False,
    }


def request(
    provider_configuration: dict[str, object],
    policy: ProviderPolicy,
    *,
    version: int = 0,
    key: str = "budget:test:00000001",
    amounts: dict[str, int] | None = None,
    requested_at: datetime = NOW,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "configuration_id": provider_configuration["configuration_id"],
        "registry_id": policy.registry_id,
        "registry_revision": policy.registry_revision,
        "idempotency_key": key,
        "expected_ledger_version": version,
        "amounts": amounts
        or {
            "input_tokens": 10,
            "output_tokens": 5,
            "requests": 1,
            "cost_microusd": 100,
            "runtime_seconds": 3,
        },
        "requested_at": requested_at.isoformat(),
        "expires_at": (expires_at or requested_at + timedelta(minutes=2)).isoformat(),
        "execution_enabled": False,
    }


def ledger_fixture(
    *, clock: Clock | None = None
) -> tuple[AIBudgetLedger, dict[str, object], ProviderPolicy]:
    provider_configuration = configuration()
    policy = provider_policy()
    return (
        AIBudgetLedger(
            configuration=provider_configuration,
            policy=policy,
            clock=clock or Clock(),
        ),
        provider_configuration,
        policy,
    )


class AIBudgetLedgerTests(unittest.TestCase):
    def test_exact_ceiling_reserves_without_enabling_execution(self) -> None:
        ledger, provider_configuration, policy = ledger_fixture()
        amounts = {
            "input_tokens": 100,
            "output_tokens": 50,
            "requests": 2,
            "cost_microusd": 1_000,
            "runtime_seconds": 30,
        }
        record = ledger.reserve(request(provider_configuration, policy, amounts=amounts))
        self.assertEqual(contract_issues(record, "ai-budget-reservation-v1.schema.json"), ())
        self.assertEqual(record["state"], "reserved")
        self.assertFalse(record["execution_enabled"])
        self.assertEqual(ledger.version, 1)
        another = request(
            provider_configuration,
            policy,
            version=1,
            key="budget:test:00000002",
        )
        with self.assertRaises(AIBudgetError) as raised:
            ledger.reserve(another)
        self.assertEqual(raised.exception.code, "AI_BUDGET_EXCEEDED")

    def test_malformed_empty_stale_and_invalid_lifetime_requests_deny(self) -> None:
        ledger, provider_configuration, policy = ledger_fixture()
        malformed = request(provider_configuration, policy)
        malformed["input_tokens"] = 1
        empty = request(
            provider_configuration,
            policy,
            amounts={
                field: 0
                for field in (
                    "input_tokens",
                    "output_tokens",
                    "requests",
                    "cost_microusd",
                    "runtime_seconds",
                )
            },
        )
        stale = request(
            provider_configuration,
            policy,
            requested_at=NOW - timedelta(minutes=2),
        )
        overlong = request(
            provider_configuration,
            policy,
            expires_at=NOW + timedelta(minutes=6),
        )
        cases = (
            (malformed, "AI_BUDGET_REQUEST_MALFORMED"),
            (empty, "AI_BUDGET_AMOUNT_INVALID"),
            (stale, "AI_BUDGET_REQUEST_STALE"),
            (overlong, "AI_BUDGET_REQUEST_STALE"),
        )
        for document, code in cases:
            with self.subTest(code=code), self.assertRaises(AIBudgetError) as raised:
                ledger.reserve(document)
            self.assertEqual(raised.exception.code, code)

    def test_exact_replay_is_idempotent_and_conflicting_replay_denies(self) -> None:
        ledger, provider_configuration, policy = ledger_fixture()
        original = request(provider_configuration, policy)
        first = ledger.reserve(original)
        replay = copy.deepcopy(original)
        replay["expected_ledger_version"] = 999
        self.assertEqual(ledger.reserve(replay), first)
        conflict = copy.deepcopy(replay)
        amounts = conflict["amounts"]
        assert isinstance(amounts, dict)
        amounts["input_tokens"] = 11
        with self.assertRaises(AIBudgetError) as raised:
            ledger.reserve(conflict)
        self.assertEqual(raised.exception.code, "AI_BUDGET_IDEMPOTENCY_CONFLICT")

    def test_version_and_authority_fencing_deny_stale_or_tampered_requests(self) -> None:
        ledger, provider_configuration, policy = ledger_fixture()
        stale = request(provider_configuration, policy, version=1)
        wrong_configuration = request(provider_configuration, policy)
        wrong_configuration["configuration_id"] = str(uuid4())
        wrong_registry = request(provider_configuration, policy)
        wrong_registry["registry_revision"] = policy.registry_revision + 1
        cases = (
            (stale, "AI_BUDGET_VERSION_STALE"),
            (wrong_configuration, "AI_BUDGET_AUTHORITY_MISMATCH"),
            (wrong_registry, "AI_BUDGET_AUTHORITY_MISMATCH"),
        )
        for document, code in cases:
            with self.subTest(code=code), self.assertRaises(AIBudgetError) as raised:
                ledger.reserve(document)
            self.assertEqual(raised.exception.code, code)

    def test_commit_release_and_invalid_transitions_are_fenced(self) -> None:
        ledger, provider_configuration, policy = ledger_fixture()
        first = ledger.reserve(request(provider_configuration, policy))
        committed = ledger.commit(first["reservation_id"], expected_version=1)
        self.assertEqual(committed["state"], "committed")
        self.assertEqual(ledger.commit(first["reservation_id"], expected_version=0), committed)
        with self.assertRaises(AIBudgetError) as raised:
            ledger.release(first["reservation_id"], expected_version=2)
        self.assertEqual(raised.exception.code, "AI_BUDGET_STATE_CONFLICT")

        second_request = request(
            provider_configuration,
            policy,
            version=2,
            key="budget:test:00000002",
        )
        second = ledger.reserve(second_request)
        released = ledger.release(second["reservation_id"], expected_version=3)
        self.assertEqual(released["state"], "released")
        self.assertEqual(ledger.release(second["reservation_id"], expected_version=0), released)

    def test_expired_reservation_cannot_commit_but_can_release_safely(self) -> None:
        clock = Clock()
        ledger, provider_configuration, policy = ledger_fixture(clock=clock)
        record = ledger.reserve(
            request(
                provider_configuration,
                policy,
                expires_at=NOW + timedelta(seconds=1),
            )
        )
        clock.value = NOW + timedelta(seconds=2)
        with self.assertRaises(AIBudgetError) as raised:
            ledger.commit(record["reservation_id"], expected_version=1)
        self.assertEqual(raised.exception.code, "AI_BUDGET_RESERVATION_EXPIRED")
        released = ledger.release(record["reservation_id"], expected_version=1)
        self.assertEqual(released["state"], "released")

    def test_concurrent_reservations_cannot_oversubscribe_or_bypass_version(self) -> None:
        ledger, provider_configuration, policy = ledger_fixture()
        barrier = threading.Barrier(3)
        results: list[str] = []
        lock = threading.Lock()

        def contender(index: int) -> None:
            candidate = request(
                provider_configuration,
                policy,
                key=f"budget:thread:{index:08d}",
                amounts={
                    "input_tokens": 60,
                    "output_tokens": 30,
                    "requests": 1,
                    "cost_microusd": 600,
                    "runtime_seconds": 20,
                },
            )
            barrier.wait()
            try:
                ledger.reserve(candidate)
                outcome = "reserved"
            except AIBudgetError as exc:
                outcome = exc.code
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=contender, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count("reserved"), 1)
        self.assertEqual(results.count("AI_BUDGET_VERSION_STALE"), 1)

    def test_recovery_releases_expired_reservations_and_preserves_committed_spend(self) -> None:
        clock = Clock()
        ledger, provider_configuration, policy = ledger_fixture(clock=clock)
        committed_source = request(provider_configuration, policy)
        committed = ledger.reserve(committed_source)
        ledger.commit(committed["reservation_id"], expected_version=1)
        expiring_source = request(
            provider_configuration,
            policy,
            version=2,
            key="budget:test:00000002",
            expires_at=NOW + timedelta(seconds=1),
        )
        expiring = ledger.reserve(expiring_source)
        snapshot = ledger.snapshot()
        clock.value = NOW + timedelta(seconds=2)
        recovered = AIBudgetLedger.recover(
            snapshot,
            configuration=provider_configuration,
            policy=policy,
            clock=clock,
        )
        states = {record["reservation_id"]: record["state"] for record in recovered.snapshot()}
        self.assertEqual(states[committed["reservation_id"]], "committed")
        self.assertEqual(states[expiring["reservation_id"]], "released")
        replay = copy.deepcopy(expiring_source)
        replay["expected_ledger_version"] = 0
        self.assertEqual(recovered.reserve(replay)["state"], "released")

    def test_recovery_denies_ambiguous_tampered_or_oversubscribed_state(self) -> None:
        ledger, provider_configuration, policy = ledger_fixture()
        record = ledger.reserve(request(provider_configuration, policy))
        duplicate = (record, copy.deepcopy(record))
        tampered = copy.deepcopy(record)
        tampered["configuration_id"] = str(uuid4())
        oversized = copy.deepcopy(record)
        amounts = oversized["amounts"]
        assert isinstance(amounts, dict)
        amounts["input_tokens"] = 101
        cases = (
            (duplicate, "AI_BUDGET_RECOVERY_AMBIGUOUS"),
            ((tampered,), "AI_BUDGET_RECOVERY_MISMATCH"),
            ((oversized,), "AI_BUDGET_RECOVERY_EXCEEDED"),
        )
        for records, code in cases:
            with self.subTest(code=code), self.assertRaises(AIBudgetError) as raised:
                AIBudgetLedger.recover(
                    records,
                    configuration=provider_configuration,
                    policy=policy,
                    clock=Clock(),
                )
            self.assertEqual(raised.exception.code, code)


if __name__ == "__main__":
    unittest.main()
