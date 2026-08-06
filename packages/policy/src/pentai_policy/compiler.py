from __future__ import annotations

import uuid
from copy import deepcopy
from typing import Any, cast

from pentai_policy.canonicalize import canonicalize_cidr, canonicalize_ip, canonicalize_url
from pentai_policy.documents import ManifestValidationError, content_hash, validate_manifest

SUPPORTED_CAPABILITIES = frozenset(
    {"network.http.get", "network.http.head", "network.http.options"}
)
_NAMESPACE = uuid.UUID("1e5bc6c2-e017-46e3-8b79-43879f52692f")


def _uuid(*parts: object) -> str:
    return str(uuid.uuid5(_NAMESPACE, "|".join(map(str, parts))))


def _matcher(asset: dict[str, Any]) -> dict[str, object]:
    kind, value = asset["type"], asset["canonical_value"]
    if kind == "domain":
        return {"host": value}
    if kind == "wildcard_domain":
        return {"base_domain": value, "include_apex": asset["include_apex"]}
    if kind == "url":
        url = canonicalize_url(value)
        return {key: url[key] for key in ("scheme", "host", "port", "path")}
    if kind in {"ipv4", "ipv6"}:
        return dict(canonicalize_ip(value))
    if kind == "cidr":
        return canonicalize_cidr(value)
    raise ManifestValidationError(f"unsupported asset type: {kind}")


def compile_manifest(document: dict[str, Any]) -> dict[str, Any]:
    result = validate_manifest(document)
    if not result["valid"]:
        raw_issues = cast(list[dict[str, object]], result["issues"])
        raise ManifestValidationError(
            "manifest is not compilable: " + ", ".join(str(item["code"]) for item in raw_issues)
        )
    manifest = cast(dict[str, Any], result["canonical_document"])
    manifest_hash = cast(str, result["content_hash"])
    techniques = manifest["techniques"]
    capabilities = set(techniques["allowed_capabilities"]) | set(techniques["denied_capabilities"])
    unsupported = sorted(capabilities - SUPPORTED_CAPABILITIES)
    if unsupported:
        raise ManifestValidationError(f"unsupported capabilities: {', '.join(unsupported)}")
    assets = []
    for asset in manifest["scope"]["assets"]:
        rule_id = _uuid(manifest_hash, "asset", content_hash(asset))
        rule: dict[str, Any] = {
            "rule_id": rule_id,
            "effect": asset["effect"],
            "asset_type": asset["type"],
            "matcher": _matcher(asset),
            "specificity": (400 if asset["type"] == "url" else 300)
            + max((len(path) for path in asset.get("allowed_paths", [])), default=0),
            "source_references": [asset["source_reference"]],
        }
        for key in ("allowed_ports", "allowed_paths"):
            if asset.get(key):
                rule[key] = asset[key]
        assets.append(rule)
        for denied_path in asset.get("denied_paths", []):
            denied_matcher = dict(_matcher(asset))
            denied_matcher["path"] = denied_path
            assets.append(
                {
                    "rule_id": _uuid(manifest_hash, "asset-denied-path", rule_id, denied_path),
                    "effect": "deny",
                    "asset_type": asset["type"],
                    "matcher": denied_matcher,
                    "specificity": rule["specificity"] + len(denied_path) + 1,
                    "source_references": [asset["source_reference"]],
                }
            )
    source_ids = [source["source_id"] for source in manifest["sources"]]
    capability_rules = [
        {
            "rule_id": _uuid(manifest_hash, capability, effect),
            "capability": capability,
            "effect": effect,
            "source_references": source_ids,
        }
        for effect, values in (
            ("allow", techniques["allowed_capabilities"]),
            ("deny", techniques["denied_capabilities"]),
        )
        for capability in values
    ]
    limits, network = manifest["operational_limits"], manifest["network"]
    if not network.get("route_profile_id"):
        raise ManifestValidationError("route_profile_id is required by Policy IR v1")
    policy: dict[str, Any] = {
        "schema_version": "1.0.0",
        "policy_id": _uuid(manifest_hash, "policy"),
        "engagement_id": manifest["engagement"]["id"],
        "manifest_hash": manifest_hash,
        "compiler": {
            "name": "pentai-policy-compiler",
            "version": "1.0.0",
            "canonicalization_version": "1.0.0",
        },
        "validity": {
            "not_before": manifest["engagement"]["effective_from"],
            "not_after": manifest["engagement"]["expires_at"],
            "revocation_epoch": 0,
        },
        "asset_rules": sorted(assets, key=lambda item: item["rule_id"]),
        "capability_rules": sorted(capability_rules, key=lambda item: item["rule_id"]),
        "budgets": {
            "global_rps": limits["requests_per_second"],
            "per_host_rps": limits["per_host_requests_per_second"],
            "burst": limits["burst_limit"],
            "concurrent_connections": limits["concurrent_connections"],
            "maximum_total_requests": limits["maximum_total_requests"],
            "maximum_runtime_seconds": limits["maximum_runtime_minutes"] * 60,
            "maximum_response_bytes": limits["maximum_response_bytes"],
        },
        "network_constraints": {
            "route_profile_id": network["route_profile_id"],
            "registered_source_ipv4": sorted(network["registered_source_ipv4"]),
            "registered_source_ipv6": sorted(network["registered_source_ipv6"]),
            "ipv6_mode": network["ipv6_mode"],
            "dns_mode": network["dns_mode"],
            "pause_on_identity_change": True,
        },
        "approval_requirements": [],
        "default_effect": "deny",
    }
    policy["content_hash"] = content_hash(deepcopy(policy))
    return policy
