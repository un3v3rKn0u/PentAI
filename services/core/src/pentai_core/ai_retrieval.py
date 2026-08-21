from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from types import MappingProxyType
from typing import Any

from pentai_policy.document import contract_issues, parse_time

from pentai_core.untrusted_content import validate_untrusted_content_envelope

MAX_POLICY_LIFETIME = timedelta(days=30)
MAX_REQUEST_AGE = timedelta(minutes=1)
MAX_REQUEST_LIFETIME = timedelta(minutes=5)


class AIRetrievalError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RetrievalPermission:
    purposes: frozenset[str]
    allowed_origins: frozenset[str]
    allowed_classifications: frozenset[str]
    max_results: int


@dataclass(frozen=True)
class RetrievalPolicy:
    policy_id: str
    policy_version: int
    assessment_id: str
    permissions: Mapping[str, RetrievalPermission]
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "permissions", MappingProxyType(dict(self.permissions)))


def compile_retrieval_policy(
    document: dict[str, Any], *, clock: Callable[[], datetime] | None = None
) -> RetrievalPolicy:
    if contract_issues(document, "ai-retrieval-policy-v1.schema.json"):
        raise AIRetrievalError("AI_RETRIEVAL_POLICY_MALFORMED", "retrieval policy is malformed")
    instant = _now(clock)
    issued_at = parse_time(document["issued_at"])
    expires_at = parse_time(document["expires_at"])
    if (
        issued_at > instant
        or expires_at <= instant
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_POLICY_LIFETIME
    ):
        raise AIRetrievalError("AI_RETRIEVAL_POLICY_STALE", "retrieval policy is stale")
    permissions: dict[str, RetrievalPermission] = {}
    for source in document["permissions"]:
        subject_id = source["subject_id"]
        if subject_id in permissions:
            raise AIRetrievalError(
                "AI_RETRIEVAL_POLICY_AMBIGUOUS", "retrieval subject is duplicated"
            )
        permissions[subject_id] = RetrievalPermission(
            purposes=frozenset(source["purposes"]),
            allowed_origins=frozenset(source["allowed_origins"]),
            allowed_classifications=frozenset(source["allowed_classifications"]),
            max_results=source["max_results"],
        )
    return RetrievalPolicy(
        policy_id=document["policy_id"],
        policy_version=document["policy_version"],
        assessment_id=document["assessment_id"],
        permissions=permissions,
        issued_at=issued_at,
        expires_at=expires_at,
    )


class AssessmentRetrievalCatalog:
    """Deterministic metadata-only ACL filtering for one assessment."""

    def __init__(
        self,
        *,
        assessment_id: str,
        policy_document: dict[str, Any],
        envelopes: Sequence[dict[str, Any]],
        catalog_version: int = 1,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if catalog_version < 1:
            raise AIRetrievalError(
                "AI_RETRIEVAL_CATALOG_VERSION_INVALID", "catalog version is invalid"
            )
        self._clock = clock
        self._policy_document = copy.deepcopy(policy_document)
        self._policy = compile_retrieval_policy(self._policy_document, clock=clock)
        if self._policy.assessment_id != assessment_id:
            raise AIRetrievalError(
                "AI_RETRIEVAL_POLICY_SCOPE_MISMATCH", "retrieval policy scope does not match"
            )
        self._assessment_id = assessment_id
        self._catalog_version = catalog_version
        self._envelopes = tuple(copy.deepcopy(envelope) for envelope in envelopes)
        self._requests: dict[str, str] = {}
        self._lock = RLock()
        self._validate_catalog()

    @property
    def version(self) -> int:
        return self._catalog_version

    def retrieve(self, request: dict[str, Any]) -> dict[str, Any]:
        if contract_issues(request, "ai-retrieval-request-v1.schema.json"):
            raise AIRetrievalError(
                "AI_RETRIEVAL_REQUEST_MALFORMED", "retrieval request is malformed"
            )
        fingerprint = _fingerprint(request)
        with self._lock:
            previous = self._requests.get(request["request_id"])
            if previous is not None:
                code = (
                    "AI_RETRIEVAL_REQUEST_REPLAYED"
                    if previous == fingerprint
                    else "AI_RETRIEVAL_REQUEST_IDENTITY_CONFLICT"
                )
                raise AIRetrievalError(code, "retrieval request identity was reused")
            instant = _now(self._clock)
            self._policy = compile_retrieval_policy(self._policy_document, clock=self._clock)
            self._validate_request(request, instant=instant)
            self._validate_catalog()
            permission = self._policy.permissions[request["subject_id"]]
            origins = frozenset(request["allowed_origins"])
            classifications = frozenset(request["allowed_classifications"])
            selected = [
                envelope
                for envelope in self._envelopes
                if envelope["origin"] in origins and envelope["classification"] in classifications
            ]
            selected.sort(
                key=lambda item: (
                    item["origin"],
                    item["classification"],
                    item["provenance_ref"],
                    item["envelope_id"],
                )
            )
            selected = selected[: min(request["result_limit"], permission.max_results)]
            items = [_metadata(envelope) for envelope in selected]
            result = {
                "schema_version": "1.0.0",
                "request_id": request["request_id"],
                "assessment_id": request["assessment_id"],
                "subject_id": request["subject_id"],
                "purpose": request["purpose"],
                "policy_id": request["policy_id"],
                "policy_version": request["policy_version"],
                "catalog_version": self._catalog_version,
                "query_sha256": request["query_sha256"],
                "result_count": len(items),
                "items": items,
                "authority": "none",
                "execution_enabled": False,
            }
            if contract_issues(result, "ai-retrieval-result-v1.schema.json"):
                raise AIRetrievalError("AI_RETRIEVAL_RESULT_INVALID", "retrieval result is invalid")
            self._requests[request["request_id"]] = fingerprint
            return copy.deepcopy(result)

    def _validate_request(self, request: dict[str, Any], *, instant: datetime) -> None:
        if request["assessment_id"] != self._assessment_id:
            raise AIRetrievalError(
                "AI_RETRIEVAL_REQUEST_SCOPE_MISMATCH", "retrieval request scope does not match"
            )
        if (
            request["policy_id"] != self._policy.policy_id
            or request["policy_version"] != self._policy.policy_version
        ):
            raise AIRetrievalError(
                "AI_RETRIEVAL_POLICY_MISMATCH", "retrieval policy identity does not match"
            )
        if request["expected_catalog_version"] != self._catalog_version:
            raise AIRetrievalError(
                "AI_RETRIEVAL_CATALOG_VERSION_STALE", "retrieval catalog version is stale"
            )
        requested_at = parse_time(request["requested_at"])
        expires_at = parse_time(request["expires_at"])
        if (
            requested_at > instant
            or instant - requested_at > MAX_REQUEST_AGE
            or expires_at <= instant
            or expires_at <= requested_at
            or expires_at - requested_at > MAX_REQUEST_LIFETIME
            or expires_at > self._policy.expires_at
        ):
            raise AIRetrievalError("AI_RETRIEVAL_REQUEST_STALE", "retrieval request is stale")
        permission = self._policy.permissions.get(request["subject_id"])
        if permission is None:
            raise AIRetrievalError("AI_RETRIEVAL_SUBJECT_DENIED", "retrieval subject is denied")
        if request["purpose"] not in permission.purposes:
            raise AIRetrievalError("AI_RETRIEVAL_PURPOSE_DENIED", "retrieval purpose is denied")
        if not frozenset(request["allowed_origins"]).issubset(
            permission.allowed_origins
        ) or not frozenset(request["allowed_classifications"]).issubset(
            permission.allowed_classifications
        ):
            raise AIRetrievalError(
                "AI_RETRIEVAL_PRIVILEGE_EXPANSION", "retrieval request expands permission"
            )
        if request["result_limit"] > permission.max_results:
            raise AIRetrievalError(
                "AI_RETRIEVAL_LIMIT_EXCEEDED", "retrieval result limit exceeds permission"
            )

    def _validate_catalog(self) -> None:
        envelope_ids: set[str] = set()
        provenance_refs: set[str] = set()
        for envelope in self._envelopes:
            validate_untrusted_content_envelope(
                envelope,
                expected_assessment_id=self._assessment_id,
                clock=self._clock,
            )
            if (
                envelope["envelope_id"] in envelope_ids
                or envelope["provenance_ref"] in provenance_refs
            ):
                raise AIRetrievalError(
                    "AI_RETRIEVAL_CATALOG_AMBIGUOUS", "retrieval catalog is ambiguous"
                )
            envelope_ids.add(envelope["envelope_id"])
            provenance_refs.add(envelope["provenance_ref"])


def _metadata(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "envelope_id": envelope["envelope_id"],
        "origin": envelope["origin"],
        "classification": envelope["classification"],
        "provenance_ref": envelope["provenance_ref"],
        "content_sha256": envelope["content_sha256"],
        "acquired_at": envelope["acquired_at"],
        "expires_at": envelope["expires_at"],
        "instruction_metadata": copy.deepcopy(envelope["instruction_metadata"]),
        "authority": "none",
        "execution_enabled": False,
    }


def _fingerprint(document: dict[str, Any]) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _now(clock: Callable[[], datetime] | None) -> datetime:
    value = clock() if clock is not None else datetime.now(UTC)
    if value.tzinfo is None:
        raise AIRetrievalError("AI_RETRIEVAL_CLOCK_INVALID", "clock is invalid")
    return value.astimezone(UTC)
