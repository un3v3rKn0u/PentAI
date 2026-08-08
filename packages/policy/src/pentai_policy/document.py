from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from pentai_policy.canonicalize import (
    CanonicalizationError,
    canonicalize_cidr,
    canonicalize_domain,
    canonicalize_ip,
    canonicalize_path,
    canonicalize_url,
    canonicalize_wildcard_domain,
)


def canonical_json(value: object) -> str:
    """RFC-8785-shaped deterministic JSON for the repository's JSON value subset."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def content_hash(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    path: str
    message: str
    severity: str = "error"

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "path": self.path,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class ManifestValidation:
    document: dict[str, Any] | None
    issues: tuple[ValidationIssue, ...]

    @property
    def valid(self) -> bool:
        return self.document is not None and not any(
            issue.severity == "error" for issue in self.issues
        )


def _source_schema(schema_name: str) -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "schemas" / "v1" / schema_name
        if candidate.is_file():
            return candidate
    return None


@cache
def _contract_validator(schema_name: str) -> Draft202012Validator:
    try:
        schema_text = (
            resources.files("pentai_policy")
            .joinpath("schemas", schema_name)
            .read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        source_schema = _source_schema(schema_name)
        if source_schema is None:
            raise
        schema_text = source_schema.read_text(encoding="utf-8")
    return Draft202012Validator(json.loads(schema_text), format_checker=FormatChecker())


def contract_issues(document: object, schema_name: str) -> tuple[ValidationIssue, ...]:
    errors = sorted(
        _contract_validator(schema_name).iter_errors(document),
        key=lambda item: str(item.absolute_path),
    )
    return tuple(
        ValidationIssue(
            "CONTRACT_INVALID",
            "/" + "/".join(str(part) for part in error.absolute_path),
            error.message,
        )
        for error in errors
    )


_SUPPORTED_CAPABILITIES = {
    "network.http.get",
    "network.http.head",
    "network.http.options",
}
_CAPABILITY_METHOD = {
    "network.http.get": "GET",
    "network.http.head": "HEAD",
    "network.http.options": "OPTIONS",
}


def validate_and_canonicalize_manifest(
    candidate: dict[str, Any],
    *,
    source_hashes: dict[str, str] | None = None,
    now: datetime | None = None,
) -> ManifestValidation:
    document = deepcopy(candidate)
    issues: list[ValidationIssue] = []
    schema_issues = contract_issues(document, "engagement-manifest-v2.schema.json")
    if schema_issues:
        return ManifestValidation(document, schema_issues)
    required = {
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
        "unresolved_questions",
    }
    missing = sorted(required - document.keys())
    for field in missing:
        issues.append(ValidationIssue("MANIFEST_FIELD_MISSING", f"/{field}", "required field"))
    if missing:
        return ManifestValidation(None, tuple(issues))
    if document.get("schema_version") != "2.0.0":
        issues.append(
            ValidationIssue("UNSUPPORTED_SCHEMA", "/schema_version", "Manifest v2.0.0 is required")
        )

    unresolved = document.get("unresolved_questions")
    if not isinstance(unresolved, list):
        issues.append(
            ValidationIssue(
                "UNRESOLVED_QUESTIONS_INVALID",
                "/unresolved_questions",
                "must be an array",
            )
        )
    elif unresolved:
        issues.append(
            ValidationIssue(
                "AUTHORIZATION_AMBIGUOUS",
                "/unresolved_questions",
                "all authorization questions must be resolved",
            )
        )

    sources = document.get("sources")
    source_ids: set[str] = set()
    if not isinstance(sources, list) or not sources:
        issues.append(ValidationIssue("PROVENANCE_MISSING", "/sources", "at least one source"))
    else:
        for index, source in enumerate(sources):
            if not isinstance(source, dict):
                issues.append(
                    ValidationIssue("PROVENANCE_INVALID", f"/sources/{index}", "must be an object")
                )
                continue
            source_id = source.get("source_id")
            digest = source.get("content_hash")
            if not isinstance(source_id, str) or not isinstance(digest, str):
                issues.append(
                    ValidationIssue(
                        "PROVENANCE_MISSING", f"/sources/{index}", "source id and hash required"
                    )
                )
                continue
            source_ids.add(source_id)
            if source_hashes is not None and source_hashes.get(source_id) != digest:
                issues.append(
                    ValidationIssue(
                        "PROVENANCE_HASH_MISMATCH",
                        f"/sources/{index}/content_hash",
                        "source content no longer matches its recorded hash",
                    )
                )

    scope = document.get("scope")
    assets = scope.get("assets") if isinstance(scope, dict) else None
    if not isinstance(assets, list) or not assets:
        issues.append(
            ValidationIssue("SCOPE_EMPTY", "/scope/assets", "at least one asset required")
        )
    else:
        canonical_assets: list[dict[str, Any]] = []
        seen: dict[tuple[str, str], str] = {}
        for index, asset in enumerate(assets):
            path = f"/scope/assets/{index}"
            if not isinstance(asset, dict):
                issues.append(ValidationIssue("ASSET_INVALID", path, "must be an object"))
                continue
            source_reference = asset.get("source_reference")
            if source_reference not in source_ids:
                issues.append(
                    ValidationIssue(
                        "PROVENANCE_MISSING",
                        f"{path}/source_reference",
                        "must reference an imported source",
                    )
                )
            asset_type = asset.get("type")
            raw = asset.get("canonical_value")
            try:
                if not isinstance(raw, str):
                    raise CanonicalizationError("canonical value must be a string")
                if asset_type == "domain":
                    canonical = canonicalize_domain(raw)
                elif asset_type == "wildcard_domain":
                    canonical = canonicalize_wildcard_domain(raw)
                elif asset_type == "url":
                    canonical = str(canonicalize_url(raw)["canonical_url"])
                elif asset_type in {"ipv4", "ipv6"}:
                    result = canonicalize_ip(raw)
                    if result["family"] != asset_type:
                        raise CanonicalizationError("IP family does not match asset type")
                    canonical = result["value"]
                elif asset_type == "cidr":
                    canonical = str(canonicalize_cidr(raw)["canonical"])
                else:
                    raise CanonicalizationError("unsupported asset type")
                normalized = deepcopy(asset)
                normalized["canonical_value"] = canonical
                normalized["allowed_ports"] = sorted(set(normalized.get("allowed_ports", [])))
                normalized["allowed_paths"] = sorted(
                    {canonicalize_path(item) for item in normalized.get("allowed_paths", [])}
                )
                normalized["denied_paths"] = sorted(
                    {canonicalize_path(item) for item in normalized.get("denied_paths", [])}
                )
                asset_key = (str(asset_type), canonical)
                previous = seen.get(asset_key)
                effect = normalized.get("effect")
                if previous is not None and previous != effect:
                    issues.append(
                        ValidationIssue(
                            "CONTRADICTORY_RULES", path, "same asset is both allowed and denied"
                        )
                    )
                seen[asset_key] = str(effect)
                canonical_assets.append(normalized)
            except (CanonicalizationError, TypeError) as exc:
                issues.append(ValidationIssue("ASSET_INVALID", path, str(exc)))
        if isinstance(scope, dict):
            scope["assets"] = sorted(
                canonical_assets,
                key=lambda item: (
                    item["type"],
                    item["canonical_value"],
                    item["effect"],
                    item["asset_id"],
                ),
            )

    techniques = document.get("techniques")
    if isinstance(techniques, dict):
        allowed = set(techniques.get("allowed_capabilities", []))
        denied = set(techniques.get("denied_capabilities", []))
        conditional = {
            str(item["capability"])
            for item in techniques.get("conditional_capabilities", [])
            if isinstance(item, dict) and "capability" in item
        }
        conditional_items = techniques.get("conditional_capabilities", [])
        conditional_names = [
            str(item["capability"])
            for item in conditional_items
            if isinstance(item, dict) and "capability" in item
        ]
        if len(conditional_names) != len(set(conditional_names)):
            issues.append(
                ValidationIssue(
                    "CONTRADICTORY_RULES",
                    "/techniques/conditional_capabilities",
                    "a capability may have only one conditional rule",
                )
            )
        if (allowed & denied) or (allowed & conditional) or (denied & conditional):
            issues.append(
                ValidationIssue(
                    "CONTRADICTORY_RULES",
                    "/techniques",
                    "a capability may have only one effect",
                )
            )
        unsupported = sorted((allowed | denied | conditional) - _SUPPORTED_CAPABILITIES)
        if unsupported:
            issues.append(
                ValidationIssue(
                    "UNSUPPORTED_CAPABILITY",
                    "/techniques",
                    f"unsupported capabilities: {', '.join(unsupported)}",
                )
            )
        methods = set(techniques.get("allowed_http_methods", []))
        for capability in allowed:
            if _CAPABILITY_METHOD.get(capability) not in methods:
                issues.append(
                    ValidationIssue(
                        "CONTRADICTORY_RULES",
                        "/techniques/allowed_http_methods",
                        f"{capability} requires {_CAPABILITY_METHOD.get(capability)}",
                    )
                )
        for field_name in (
            "allowed_capabilities",
            "denied_capabilities",
            "allowed_http_methods",
        ):
            if isinstance(techniques.get(field_name), list):
                techniques[field_name] = sorted(set(techniques[field_name]))

    limits = document.get("operational_limits")
    if not isinstance(limits, dict):
        issues.append(ValidationIssue("LIMITS_INVALID", "/operational_limits", "object required"))
    else:
        positive = (
            "requests_per_second",
            "per_host_requests_per_second",
            "burst_limit",
            "concurrent_connections",
            "maximum_runtime_minutes",
            "maximum_total_requests",
            "maximum_response_bytes",
        )
        for field_name in positive:
            if not isinstance(limits.get(field_name), (int, float)) or limits[field_name] <= 0:
                issues.append(
                    ValidationIssue(
                        "LIMITS_INVALID",
                        f"/operational_limits/{field_name}",
                        "must be > 0",
                    )
                )

    engagement = document.get("engagement")
    if isinstance(engagement, dict):
        try:
            not_before = parse_time(engagement["effective_from"])
            not_after = parse_time(engagement["expires_at"])
            instant = (now or datetime.now(UTC)).astimezone(UTC)
            if not_after <= not_before:
                issues.append(
                    ValidationIssue(
                        "VALIDITY_INVALID", "/engagement/expires_at", "must follow effective_from"
                    )
                )
            elif instant < not_before:
                issues.append(
                    ValidationIssue(
                        "AUTHORIZATION_NOT_YET_VALID",
                        "/engagement/effective_from",
                        "authorization has not started",
                    )
                )
            elif instant >= not_after:
                issues.append(
                    ValidationIssue(
                        "AUTHORIZATION_EXPIRED",
                        "/engagement/expires_at",
                        "authorization has expired",
                    )
                )
        except (KeyError, TypeError, ValueError):
            issues.append(
                ValidationIssue("VALIDITY_INVALID", "/engagement", "valid RFC3339 window required")
            )

    if issues:
        return ManifestValidation(document, tuple(issues))
    return ManifestValidation(document, ())
