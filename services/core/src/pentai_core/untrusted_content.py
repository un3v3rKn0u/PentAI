from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any
from uuid import uuid4

from pentai_policy.document import contract_issues, parse_time

MAX_CONTENT_BYTES = 16_384
MAX_ENVELOPE_LIFETIME = timedelta(hours=24)
_ORIGIN_PROVENANCE = {
    "program_page": "source",
    "retrieved_document": "retrieval",
    "target_content": "target",
    "tool_output": "tool",
    "evidence_derivative": "evidence-derivative",
    "plugin_message": "plugin",
    "model_output": "model",
}
_INDICATORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "direct",
        re.compile(r"\b(ignore|disregard) (all |the )?(previous|prior) instructions\b", re.I),
    ),
    ("indirect", re.compile(r"\b(when an ai reads|assistant should follow)\b", re.I)),
    ("encoded", re.compile(r"\b(base64|decode this|decode the following)\b", re.I)),
    ("obfuscated", re.compile(r"\bi\s+g\s+n\s+o\s+r\s+e\b", re.I)),
    ("delimiter_breaking", re.compile(r"(<\/?system>|```\s*system|\[/?system\])", re.I)),
    ("role_confusion", re.compile(r"\b(you are now|act as) (the )?(system|administrator)", re.I)),
    ("authority_claim", re.compile(r"\b(admin override|authorized by the operator)\b", re.I)),
    ("secret_exfiltration", re.compile(r"\b(reveal credentials|exfiltrate secrets?)\b", re.I)),
    ("tool_call", re.compile(r"\b(call tool|invoke function|execute tool)\b", re.I)),
    ("policy_mutation", re.compile(r"\b(modify policy|approve action|mint grant)\b", re.I)),
    ("data_poisoning", re.compile(r"\b(overwrite memory|store as fact)\b", re.I)),
)


class UntrustedContentError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def build_untrusted_content_envelope(
    *,
    assessment_id: str,
    origin: str,
    classification: str,
    provenance_ref: str,
    content: str,
    acquired_at: datetime,
    expires_at: datetime,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    categories = detect_instruction_categories(content) if isinstance(content, str) else ()
    envelope = {
        "schema_version": "1.0.0",
        "envelope_id": str(uuid4()),
        "assessment_id": assessment_id,
        "origin": origin,
        "classification": classification,
        "provenance_ref": provenance_ref,
        "content": content,
        "content_sha256": _content_digest(content) if isinstance(content, str) else "",
        "acquired_at": _timestamp(acquired_at),
        "expires_at": _timestamp(expires_at),
        "instruction_metadata": {
            "suspected": bool(categories),
            "categories": list(categories),
        },
        "authority": "none",
        "execution_enabled": False,
    }
    validate_untrusted_content_envelope(
        envelope,
        expected_assessment_id=assessment_id,
        clock=clock,
    )
    return envelope


def validate_untrusted_content_envelope(
    document: dict[str, Any],
    *,
    expected_assessment_id: str,
    clock: Callable[[], datetime] | None = None,
) -> None:
    if contract_issues(document, "untrusted-content-envelope-v1.schema.json"):
        raise UntrustedContentError(
            "UNTRUSTED_CONTENT_MALFORMED", "untrusted content envelope is malformed"
        )
    if document["assessment_id"] != expected_assessment_id:
        raise UntrustedContentError(
            "UNTRUSTED_CONTENT_SCOPE_MISMATCH", "assessment scope does not match"
        )
    expected_prefix = _ORIGIN_PROVENANCE[document["origin"]]
    if not document["provenance_ref"].startswith(f"provenance://{expected_prefix}/"):
        raise UntrustedContentError(
            "UNTRUSTED_CONTENT_PROVENANCE_MISMATCH", "origin and provenance do not match"
        )
    encoded = document["content"].encode("utf-8")
    if len(encoded) > MAX_CONTENT_BYTES:
        raise UntrustedContentError(
            "UNTRUSTED_CONTENT_TOO_LARGE", "untrusted content exceeds the byte limit"
        )
    if document["content_sha256"] != _content_digest(document["content"]):
        raise UntrustedContentError(
            "UNTRUSTED_CONTENT_DIGEST_MISMATCH", "untrusted content digest does not match"
        )
    expected_categories = detect_instruction_categories(document["content"])
    metadata = document["instruction_metadata"]
    if metadata["categories"] != list(expected_categories) or metadata["suspected"] is not bool(
        expected_categories
    ):
        raise UntrustedContentError(
            "UNTRUSTED_CONTENT_METADATA_MISMATCH", "instruction metadata does not match"
        )
    instant = _now(clock)
    acquired_at = parse_time(document["acquired_at"])
    expires_at = parse_time(document["expires_at"])
    if acquired_at > instant:
        raise UntrustedContentError(
            "UNTRUSTED_CONTENT_FUTURE", "untrusted content acquisition is in the future"
        )
    if (
        expires_at <= instant
        or expires_at <= acquired_at
        or expires_at - acquired_at > MAX_ENVELOPE_LIFETIME
    ):
        raise UntrustedContentError(
            "UNTRUSTED_CONTENT_STALE", "untrusted content validity is stale"
        )


def detect_instruction_categories(content: str) -> tuple[str, ...]:
    return tuple(category for category, pattern in _INDICATORS if pattern.search(content))


class UntrustedContentRegistry:
    """Process-local replay fencing for validated, non-executing envelopes."""

    def __init__(
        self,
        *,
        assessment_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._assessment_id = assessment_id
        self._clock = clock
        self._records: dict[str, dict[str, Any]] = {}
        self._fingerprints: dict[str, str] = {}
        self._provenance: set[str] = set()
        self._lock = RLock()

    def register(self, document: dict[str, Any]) -> dict[str, Any]:
        validate_untrusted_content_envelope(
            document,
            expected_assessment_id=self._assessment_id,
            clock=self._clock,
        )
        fingerprint = _fingerprint(document)
        with self._lock:
            envelope_id = document["envelope_id"]
            if envelope_id in self._records:
                code = (
                    "UNTRUSTED_CONTENT_REPLAYED"
                    if self._fingerprints[envelope_id] == fingerprint
                    else "UNTRUSTED_CONTENT_IDENTITY_CONFLICT"
                )
                raise UntrustedContentError(code, "untrusted content identity was reused")
            if document["provenance_ref"] in self._provenance:
                raise UntrustedContentError(
                    "UNTRUSTED_CONTENT_PROVENANCE_REUSED", "provenance reference was reused"
                )
            stored = copy.deepcopy(document)
            self._records[envelope_id] = stored
            self._fingerprints[envelope_id] = fingerprint
            self._provenance.add(document["provenance_ref"])
            return copy.deepcopy(stored)

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(
                copy.deepcopy(self._records[envelope_id]) for envelope_id in sorted(self._records)
            )


def _content_digest(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def _fingerprint(document: dict[str, Any]) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _now(clock: Callable[[], datetime] | None) -> datetime:
    value = clock() if clock is not None else datetime.now(UTC)
    if value.tzinfo is None:
        raise UntrustedContentError("UNTRUSTED_CONTENT_CLOCK_INVALID", "clock is invalid")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise UntrustedContentError("UNTRUSTED_CONTENT_TIME_INVALID", "time is invalid")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
