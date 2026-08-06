from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, cast

from pentai_policy.canonicalize import (
    CanonicalizationError,
    canonicalize_cidr,
    canonicalize_domain,
    canonicalize_ip,
    canonicalize_url,
)

JsonObject = dict[str, Any]
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "engagement",
        "sources",
        "scope",
        "techniques",
        "operational_limits",
        "network",
        "data_handling",
        "reporting",
        "agent_controls",
        "approvals",
        "known_issues",
        "unresolved_questions",
        "normalization_warnings",
    }
)
_REQUIRED_TOP_LEVEL_FIELDS = _TOP_LEVEL_FIELDS - {"known_issues", "normalization_warnings"}
_HASH = re.compile(r"^[a-f0-9]{64}$")


class ManifestValidationError(ValueError):
    """Raised when a manifest cannot safely become authorization."""


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    path: str
    message: str
    blocking: bool = True


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def content_hash(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def source_content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def _time(value: object, path: str, issues: list[ValidationIssue]) -> datetime | None:
    if not isinstance(value, str):
        issues.append(ValidationIssue("INVALID_DATETIME", path, "RFC 3339 date-time required"))
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        issues.append(ValidationIssue("INVALID_DATETIME", path, "RFC 3339 date-time required"))
        return None
    if result.tzinfo is None:
        issues.append(ValidationIssue("INVALID_DATETIME", path, "timezone required"))
        return None
    return result.astimezone(UTC)


def _asset(asset: JsonObject, index: int, issues: list[ValidationIssue]) -> JsonObject:
    result = deepcopy(asset)
    base = f"scope.assets[{index}]"
    kind, raw = result.get("type"), result.get("canonical_value")
    raw_text = cast(str, raw)
    try:
        if kind == "domain":
            result["canonical_value"] = canonicalize_domain(raw_text)
        elif kind == "wildcard_domain":
            value = raw_text[2:] if raw_text.startswith("*.") else raw_text
            result["canonical_value"] = canonicalize_domain(value)
            if "include_apex" not in result:
                issues.append(
                    ValidationIssue(
                        "AMBIGUOUS_WILDCARD_APEX",
                        f"{base}.include_apex",
                        "wildcard scope must explicitly state apex behavior",
                    )
                )
        elif kind == "url":
            result["canonical_value"] = canonicalize_url(raw_text)["canonical_url"]
        elif kind in {"ipv4", "ipv6"}:
            address = canonicalize_ip(raw_text)
            if address["family"] != kind:
                raise CanonicalizationError("address family does not match asset type")
            result["canonical_value"] = address["value"]
        elif kind == "cidr":
            result["canonical_value"] = canonicalize_cidr(raw_text)["canonical"]
        else:
            issues.append(ValidationIssue("UNSUPPORTED_ASSET_TYPE", f"{base}.type", "unsupported"))
    except (CanonicalizationError, TypeError) as exc:
        issues.append(ValidationIssue("INVALID_SCOPE_VALUE", f"{base}.canonical_value", str(exc)))
    for key in ("allowed_paths", "denied_paths"):
        values = result.get(key, [])
        if not isinstance(values, list):
            issues.append(ValidationIssue("INVALID_PATH_LIMIT", f"{base}.{key}", "list required"))
            continue
        normalized: list[str] = []
        for value in values:
            try:
                normalized.append(
                    cast(str, canonicalize_url(f"https://scope.invalid{value}")["path"])
                )
            except (CanonicalizationError, TypeError):
                issues.append(
                    ValidationIssue(
                        "INVALID_PATH_LIMIT", f"{base}.{key}", "absolute paths required"
                    )
                )
        result[key] = sorted(set(normalized))
    ports = result.get("allowed_ports", [])
    if not isinstance(ports, list) or any(
        isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
        for port in ports
    ):
        issues.append(
            ValidationIssue("INVALID_PORT_LIMIT", f"{base}.allowed_ports", "ports must be 1..65535")
        )
    else:
        result["allowed_ports"] = sorted(set(ports))
    return result


def canonicalize_manifest(document: JsonObject) -> tuple[JsonObject, list[ValidationIssue]]:
    if not isinstance(document, dict):
        return {}, [ValidationIssue("INVALID_MANIFEST", "$", "manifest must be an object")]
    manifest = deepcopy(document)
    issues: list[ValidationIssue] = []
    for field in sorted(_REQUIRED_TOP_LEVEL_FIELDS - manifest.keys()):
        issues.append(ValidationIssue("MISSING_REQUIRED_FIELD", field, "field is required"))
    for field in sorted(manifest.keys() - _TOP_LEVEL_FIELDS):
        issues.append(ValidationIssue("UNKNOWN_FIELD", field, "Manifest v2 rejects unknown fields"))
    if manifest.get("schema_version") != "2.0.0":
        issues.append(
            ValidationIssue("UNSUPPORTED_MANIFEST_VERSION", "schema_version", "expected 2.0.0")
        )
    scope = manifest.get("scope")
    if (
        not isinstance(scope, dict)
        or not isinstance(scope.get("assets"), list)
        or not scope["assets"]
    ):
        issues.append(
            ValidationIssue("MISSING_SCOPE", "scope.assets", "at least one asset is required")
        )
    else:
        canonical_assets: list[JsonObject] = []
        for index, asset in enumerate(scope["assets"]):
            if not isinstance(asset, dict):
                issues.append(
                    ValidationIssue("INVALID_ASSET", f"scope.assets[{index}]", "object required")
                )
                continue
            for field in ("asset_id", "effect", "type", "canonical_value", "source_reference"):
                if field not in asset:
                    issues.append(
                        ValidationIssue(
                            "MISSING_REQUIRED_FIELD",
                            f"scope.assets[{index}].{field}",
                            "field is required",
                        )
                    )
            canonical_assets.append(_asset(asset, index, issues))
        scope["assets"] = sorted(
            canonical_assets,
            key=lambda item: (
                str(item.get("effect")),
                str(item.get("type")),
                str(item.get("canonical_value")),
            ),
        )
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        issues.append(ValidationIssue("MISSING_PROVENANCE", "sources", "a source is required"))
    else:
        for index, source in enumerate(sources):
            digest = source.get("content_hash") if isinstance(source, dict) else None
            if not isinstance(digest, str) or not _HASH.fullmatch(digest):
                issues.append(
                    ValidationIssue(
                        "MISSING_PROVENANCE", f"sources[{index}].content_hash", "SHA-256 required"
                    )
                )
        manifest["sources"] = sorted(sources, key=lambda item: str(item.get("source_id")))
        source_ids = {source.get("source_id") for source in sources if isinstance(source, dict)}
        for index, asset in enumerate(scope.get("assets", []) if isinstance(scope, dict) else []):
            if asset.get("source_reference") not in source_ids:
                issues.append(
                    ValidationIssue(
                        "MISSING_FIELD_PROVENANCE",
                        f"scope.assets[{index}].source_reference",
                        "asset must reference a manifest source",
                    )
                )
    unresolved = manifest.get("unresolved_questions")
    if not isinstance(unresolved, list):
        issues.append(
            ValidationIssue("INVALID_UNRESOLVED_QUESTIONS", "unresolved_questions", "list required")
        )
    elif unresolved:
        issues.append(
            ValidationIssue(
                "UNRESOLVED_AUTHORIZATION", "unresolved_questions", "all questions must be resolved"
            )
        )
    engagement = manifest.get("engagement")
    if not isinstance(engagement, dict):
        issues.append(ValidationIssue("MISSING_ENGAGEMENT", "engagement", "engagement is required"))
    else:
        start = _time(engagement.get("effective_from"), "engagement.effective_from", issues)
        end = _time(engagement.get("expires_at"), "engagement.expires_at", issues)
        if start and end and start >= end:
            issues.append(
                ValidationIssue(
                    "INVALID_VALIDITY_WINDOW", "engagement.expires_at", "must follow effective_from"
                )
            )
    techniques = manifest.get("techniques")
    if not isinstance(techniques, dict):
        issues.append(
            ValidationIssue("MISSING_TECHNIQUES", "techniques", "techniques are required")
        )
    else:
        allowed = set(techniques.get("allowed_capabilities", []))
        denied = set(techniques.get("denied_capabilities", []))
        if allowed & denied:
            issues.append(
                ValidationIssue(
                    "CONTRADICTORY_CAPABILITY_RULES", "techniques", "allow and deny overlap"
                )
            )
        for key in ("allowed_capabilities", "denied_capabilities", "allowed_http_methods"):
            if isinstance(techniques.get(key), list):
                techniques[key] = sorted(set(techniques[key]))
            else:
                issues.append(
                    ValidationIssue("INVALID_TECHNIQUE_RULES", f"techniques.{key}", "list required")
                )
        if techniques.get("conditional_capabilities"):
            issues.append(
                ValidationIssue(
                    "UNSUPPORTED_CONDITIONAL_CAPABILITY",
                    "techniques.conditional_capabilities",
                    "conditional capabilities are not representable in this milestone",
                )
            )
        capability_methods = {
            "network.http.get": "GET",
            "network.http.head": "HEAD",
            "network.http.options": "OPTIONS",
        }
        represented = {capability_methods[item] for item in allowed if item in capability_methods}
        if represented != set(techniques.get("allowed_http_methods", [])):
            issues.append(
                ValidationIssue(
                    "CONTRADICTORY_METHOD_RULES",
                    "techniques.allowed_http_methods",
                    "HTTP methods must correspond exactly to allowed HTTP capabilities",
                )
            )
    limits = manifest.get("operational_limits")
    required_limits = {
        "requests_per_second",
        "per_host_requests_per_second",
        "burst_limit",
        "concurrent_connections",
        "maximum_runtime_minutes",
        "maximum_total_requests",
        "maximum_response_bytes",
        "stop_conditions",
    }
    if not isinstance(limits, dict):
        issues.append(
            ValidationIssue("MISSING_LIMITS", "operational_limits", "limits are required")
        )
    else:
        for field in sorted(required_limits - limits.keys()):
            issues.append(
                ValidationIssue(
                    "MALFORMED_LIMIT", f"operational_limits.{field}", "field is required"
                )
            )
        for field in required_limits - {"stop_conditions"}:
            value = limits.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                issues.append(
                    ValidationIssue(
                        "MALFORMED_LIMIT", f"operational_limits.{field}", "positive number required"
                    )
                )
        if not isinstance(limits.get("stop_conditions"), list) or not limits.get("stop_conditions"):
            issues.append(
                ValidationIssue(
                    "MALFORMED_LIMIT",
                    "operational_limits.stop_conditions",
                    "non-empty list required",
                )
            )
    return manifest, issues


def validate_manifest(document: JsonObject) -> dict[str, object]:
    canonical, issues = canonicalize_manifest(document)
    return {
        "valid": not issues,
        "issues": [asdict(issue) for issue in issues],
        "canonical_document": canonical,
        "content_hash": content_hash(canonical),
    }
