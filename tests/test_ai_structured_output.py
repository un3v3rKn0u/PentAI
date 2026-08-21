from __future__ import annotations

import copy
import json
import threading
import unittest
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pentai_core.ai_structured_output import (
    MAX_OUTPUT_BYTES,
    StructuredOutputError,
    StructuredOutputParser,
)
from pentai_policy.document import contract_issues

NOW = datetime(2026, 8, 21, 10, 0, tzinfo=UTC)


@dataclass
class Clock:
    value: datetime = NOW

    def __call__(self) -> datetime:
        return self.value


def candidate(*, summary: str = "Synthetic observation") -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "response_type": "candidate_observation",
        "summary": summary,
        "observations": [
            {
                "category": "synthetic",
                "detail": "No external effect",
                "confidence_millis": 750,
            }
        ],
        "execution_enabled": False,
    }


def encoded(document: object) -> bytes:
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode()


class StructuredOutputParserTests(unittest.TestCase):
    def test_direct_candidate_is_accepted_without_authority(self) -> None:
        result = StructuredOutputParser(clock=Clock()).parse_direct(encoded(candidate()))

        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["parse_path"], "direct")
        self.assertEqual(result["attempt_count"], 1)
        self.assertFalse(result["execution_enabled"])
        self.assertEqual(contract_issues(result, "ai-structured-output-result-v1.schema.json"), ())

    def test_exact_byte_limit_passes_and_one_byte_over_denies(self) -> None:
        raw = encoded(candidate())
        boundary = raw + (b" " * (MAX_OUTPUT_BYTES - len(raw)))
        parser = StructuredOutputParser(clock=Clock())

        self.assertEqual(parser.parse_direct(boundary)["outcome"], "accepted")
        denied = parser.parse_direct(boundary + b" ")
        self.assertEqual(denied["failure_code"], "AI_OUTPUT_TOO_LARGE")

    def test_invalid_encoding_empty_and_non_bytes_deny(self) -> None:
        parser = StructuredOutputParser(clock=Clock())
        cases = (
            (b"", "AI_OUTPUT_EMPTY"),
            (b"\xff", "AI_OUTPUT_INVALID_ENCODING"),
            ("{}", "AI_OUTPUT_INPUT_TYPE_INVALID"),
        )
        for raw, code in cases:
            with self.subTest(code=code):
                result = parser.parse_direct(raw)
                self.assertEqual(result["outcome"], "denied")
                self.assertEqual(result["failure_code"], code)

    def test_duplicate_trailing_malformed_and_non_finite_json_deny(self) -> None:
        parser = StructuredOutputParser(clock=Clock())
        cases = (
            (b'{"schema_version":"1.0.0","schema_version":"1.0.0"}', "AI_OUTPUT_DUPLICATE_KEY"),
            (encoded(candidate()) + b" trailing", "AI_OUTPUT_MALFORMED"),
            (b"{", "AI_OUTPUT_MALFORMED"),
            (b'{"value":' + (b"9" * 5000) + b"}", "AI_OUTPUT_MALFORMED"),
            (b'{"value":NaN}', "AI_OUTPUT_NON_FINITE_NUMBER"),
        )
        for raw, code in cases:
            with self.subTest(code=code):
                self.assertEqual(parser.parse_direct(raw)["failure_code"], code)

    def test_unsupported_version_type_and_operation_deny(self) -> None:
        version = candidate()
        version["schema_version"] = "2.0.0"
        response_type = candidate()
        response_type["response_type"] = "action_grant"
        operation = candidate()
        operation["operation"] = "execute"
        parser = StructuredOutputParser(clock=Clock())
        cases = (
            (version, "AI_OUTPUT_VERSION_UNSUPPORTED"),
            (response_type, "AI_OUTPUT_TYPE_UNSUPPORTED"),
            (operation, "AI_OUTPUT_OPERATION_UNSUPPORTED"),
        )
        for document, code in cases:
            with self.subTest(code=code):
                self.assertEqual(parser.parse_direct(encoded(document))["failure_code"], code)

    def test_unknown_missing_coerced_and_excess_collection_deny(self) -> None:
        unknown = candidate()
        unknown["unexpected_field"] = "synthetic"
        missing = candidate()
        missing.pop("summary")
        coerced = candidate()
        observations = coerced["observations"]
        assert isinstance(observations, list)
        observations[0]["confidence_millis"] = "750"
        excess = candidate()
        excess["observations"] = [copy.deepcopy(observations[0]) for _ in range(33)]
        parser = StructuredOutputParser(clock=Clock())

        for document in (unknown, missing, coerced, excess):
            with self.subTest(document=document):
                result = parser.parse_direct(encoded(document))
                self.assertEqual(result["failure_code"], "AI_OUTPUT_SCHEMA_INVALID")

    def test_excessive_nesting_denies_before_unknown_field_validation(self) -> None:
        document = candidate()
        document["extra"] = [[[[[[]]]]]]

        result = StructuredOutputParser(clock=Clock()).parse_direct(encoded(document))

        self.assertEqual(result["failure_code"], "AI_OUTPUT_DEPTH_EXCEEDED")

    def test_one_bound_repair_is_accepted_and_replay_denies(self) -> None:
        parser = StructuredOutputParser(clock=Clock())
        initial = b"{"
        request = parser.build_repair_request(initial)

        repaired = parser.parse_repair(
            initial_raw=initial,
            repair_request=request,
            repaired_raw=encoded(candidate()),
        )
        replay = parser.parse_repair(
            initial_raw=initial,
            repair_request=request,
            repaired_raw=encoded(candidate()),
        )

        self.assertEqual((repaired["outcome"], repaired["parse_path"]), ("accepted", "repaired"))
        self.assertEqual(repaired["attempt_count"], 2)
        self.assertEqual(replay["failure_code"], "AI_OUTPUT_REPAIR_REPLAYED")

    def test_repair_tampering_binding_and_expiry_deny(self) -> None:
        clock = Clock()
        parser = StructuredOutputParser(clock=clock)
        initial = b"{"
        malformed_request = parser.build_repair_request(initial)
        malformed_request["max_output_bytes"] = MAX_OUTPUT_BYTES + 1
        mismatch_request = parser.build_repair_request(initial)
        clock.value += timedelta(minutes=2)
        stale_request = parser.build_repair_request(b'{"summary":}')
        clock.value += timedelta(minutes=2)
        cases = (
            (initial, malformed_request, "AI_OUTPUT_REPAIR_REQUEST_INVALID"),
            (b'{"different":', mismatch_request, "AI_OUTPUT_REPAIR_BINDING_MISMATCH"),
            (b'{"summary":}', stale_request, "AI_OUTPUT_REPAIR_STALE"),
        )
        for source, request, code in cases:
            with self.subTest(code=code):
                result = parser.parse_repair(
                    initial_raw=source,
                    repair_request=request,
                    repaired_raw=encoded(candidate()),
                )
                self.assertEqual(result["failure_code"], code)

    def test_repair_is_forbidden_for_valid_or_terminal_output_and_exhausts_once(self) -> None:
        parser = StructuredOutputParser(clock=Clock())
        terminal = b"x" * (MAX_OUTPUT_BYTES + 1)
        for raw in (encoded(candidate()), terminal):
            with self.subTest(length=len(raw)), self.assertRaises(StructuredOutputError) as raised:
                parser.build_repair_request(raw)
            self.assertEqual(raised.exception.code, "AI_OUTPUT_REPAIR_FORBIDDEN")

        initial = b"{"
        request = parser.build_repair_request(initial)
        exhausted = parser.parse_repair(
            initial_raw=initial,
            repair_request=request,
            repaired_raw=b"{",
        )
        self.assertEqual(exhausted["failure_code"], "AI_OUTPUT_REPAIR_EXHAUSTED")

    def test_concurrent_repair_consumption_allows_exactly_one_attempt(self) -> None:
        parser = StructuredOutputParser(clock=Clock())
        initial = b"{"
        request = parser.build_repair_request(initial)
        barrier = threading.Barrier(3)
        results: list[str] = []

        def attempt() -> None:
            barrier.wait()
            result = parser.parse_repair(
                initial_raw=initial,
                repair_request=request,
                repaired_raw=encoded(candidate()),
            )
            results.append(str(result["failure_code"] or result["outcome"]))

        threads = [threading.Thread(target=attempt) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        self.assertCountEqual(results, ["accepted", "AI_OUTPUT_REPAIR_REPLAYED"])


if __name__ == "__main__":
    unittest.main()
