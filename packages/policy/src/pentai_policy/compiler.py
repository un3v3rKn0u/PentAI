from __future__ import annotations

from copy import deepcopy
from typing import Any
from uuid import UUID, uuid5

from pentai_policy.canonicalize import canonicalize_url
from pentai_policy.document import content_hash

COMPILER_VERSION = "1.1.0"
_NAMESPACE = UUID("825e6af6-8030-43c2-8968-933d894b14b5")


class CompilationError(ValueError):
    pass


def _stable_id(kind: str, value: object) -> str:
    return str(uuid5(_NAMESPACE, f"{kind}:{content_hash(value)}"))


def compile_manifest(manifest: dict[str, Any], manifest_hash: str) -> dict[str, Any]:
    if manifest.get("unresolved_questions"):
        raise CompilationError("AUTHORIZATION_AMBIGUOUS")
    assets = manifest["scope"]["assets"]
    if not any(asset["effect"] == "allow" for asset in assets):
        raise CompilationError("SCOPE_EMPTY")

    asset_rules: list[dict[str, Any]] = []
    for asset in assets:
        matcher: dict[str, Any]
        specificity: int
        if asset["type"] == "url":
            target = canonicalize_url(asset["canonical_value"])
            matcher = {
                "scheme": target["scheme"],
                "host": target["host"],
                "port": target["port"],
                "path": target["path"],
            }
            specificity = 5000 + len(str(target["path"]))
        elif asset["type"] in {"domain", "wildcard_domain"}:
            matcher = {
                "value": asset["canonical_value"],
                "include_apex": bool(asset.get("include_apex", False)),
            }
            specificity = (4000 if asset["type"] == "domain" else 3000) + len(
                asset["canonical_value"].split(".")
            )
        elif asset["type"] == "cidr":
            matcher = {"value": asset["canonical_value"]}
            specificity = 2000 + int(asset["canonical_value"].split("/")[1])
        else:
            matcher = {"value": asset["canonical_value"]}
            specificity = 4000
        rule_seed = {
            "asset_id": asset["asset_id"],
            "effect": asset["effect"],
            "type": asset["type"],
            "matcher": matcher,
        }
        base_rule = {
            "rule_id": _stable_id("asset-rule", rule_seed),
            "effect": asset["effect"],
            "asset_type": asset["type"],
            "matcher": matcher,
            "specificity": specificity,
            "allowed_ports": sorted(set(asset.get("allowed_ports", []))),
            "allowed_paths": sorted(set(asset.get("allowed_paths", []))),
            "source_references": [asset["source_reference"]],
        }
        asset_rules.append(base_rule)
        for denied_path in sorted(set(asset.get("denied_paths", []))):
            deny_matcher = deepcopy(matcher)
            deny_matcher["path_prefix"] = denied_path
            deny_seed = {"parent": rule_seed, "denied_path": denied_path}
            asset_rules.append(
                {
                    "rule_id": _stable_id("asset-path-deny", deny_seed),
                    "effect": "deny",
                    "asset_type": asset["type"],
                    "matcher": deny_matcher,
                    "specificity": specificity + 100 + len(denied_path),
                    "allowed_ports": sorted(set(asset.get("allowed_ports", []))),
                    "allowed_paths": [denied_path],
                    "source_references": [asset["source_reference"]],
                }
            )

    techniques = manifest["techniques"]
    capability_rules: list[dict[str, Any]] = []
    effects: list[tuple[str, str, list[dict[str, Any]]]] = [
        (item, "allow", []) for item in techniques["allowed_capabilities"]
    ]
    effects += [(item, "deny", []) for item in techniques["denied_capabilities"]]
    effects += [
        (
            item["capability"],
            "conditional",
            [
                {"description": condition, "approval_type": item["approval_type"]}
                for condition in item.get("conditions", [])
            ],
        )
        for item in techniques["conditional_capabilities"]
    ]
    for capability, effect, conditions in sorted(
        effects, key=lambda item: (item[0], item[1], content_hash(item[2]))
    ):
        seed = {"capability": capability, "effect": effect, "conditions": conditions}
        capability_rules.append(
            {
                "rule_id": _stable_id("capability-rule", seed),
                "capability": capability,
                "effect": effect,
                "conditions": conditions,
                "source_references": sorted(
                    {source for rule in asset_rules for source in rule["source_references"]}
                ),
            }
        )

    limits = manifest["operational_limits"]
    network = manifest["network"]
    engagement = manifest["engagement"]
    policy: dict[str, Any] = {
        "schema_version": "1.0.0",
        "policy_id": _stable_id("policy", {"manifest_hash": manifest_hash}),
        "engagement_id": engagement["id"],
        "manifest_hash": manifest_hash,
        "compiler": {
            "name": "pentai-policy-compiler",
            "version": COMPILER_VERSION,
            "canonicalization_version": "1.0.0",
        },
        "validity": {
            "not_before": engagement["effective_from"],
            "not_after": engagement["expires_at"],
            "revocation_epoch": 0,
        },
        "asset_rules": sorted(asset_rules, key=lambda item: item["rule_id"]),
        "capability_rules": sorted(capability_rules, key=lambda item: item["rule_id"]),
        "budgets": {
            "global_rps": limits["requests_per_second"],
            "per_host_rps": limits["per_host_requests_per_second"],
            "burst": limits["burst_limit"],
            "concurrent_connections": limits["concurrent_connections"],
            "maximum_total_requests": limits["maximum_total_requests"],
            "maximum_runtime_seconds": limits["maximum_runtime_minutes"] * 60,
            "maximum_request_body_bytes": limits.get("maximum_request_body_bytes", 0),
            "maximum_response_bytes": limits["maximum_response_bytes"],
        },
        "network_constraints": {
            "route_profile_id": network.get("route_profile_id") or network["route_mode"],
            "registered_source_ipv4": sorted(network["registered_source_ipv4"]),
            "registered_source_ipv6": sorted(network["registered_source_ipv6"]),
            "ipv6_mode": network["ipv6_mode"],
            "dns_mode": network["dns_mode"],
            "pause_on_identity_change": True,
        },
        "approval_requirements": [],
        "default_effect": "deny",
    }
    policy["content_hash"] = content_hash(policy)
    return policy
