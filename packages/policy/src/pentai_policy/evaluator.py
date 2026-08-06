from __future__ import annotations

import ipaddress
import uuid
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, cast

from pentai_policy.canonicalize import CanonicalizationError, canonicalize_url
from pentai_policy.documents import content_hash

_NAMESPACE = uuid.UUID("84f739ae-6b6c-4bb8-ac4c-b2ae71b485ed")


def path_matches(prefix: str, path: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _matches(rule: dict[str, Any], target: dict[str, Any]) -> bool:
    matcher, host, kind = rule["matcher"], target["host"], rule["asset_type"]
    if "path" in matcher and not path_matches(matcher["path"], target["path"]):
        return False
    if kind == "domain":
        return bool(host["kind"] == "domain" and host["value"] == matcher["host"])
    if kind == "wildcard_domain":
        return bool(
            host["kind"] == "domain"
            and (
                host["value"].endswith("." + matcher["base_domain"])
                or (matcher["include_apex"] and host["value"] == matcher["base_domain"])
            )
        )
    if kind == "url":
        return all(
            target[key] == matcher[key] for key in ("scheme", "host", "port")
        ) and path_matches(matcher["path"], target["path"])
    if kind in {"ipv4", "ipv6"}:
        return bool(host["kind"] == kind and host["value"] == matcher["value"])
    return (
        kind == "cidr"
        and host["kind"] in {"ipv4", "ipv6"}
        and ipaddress.ip_address(host["value"]) in ipaddress.ip_network(matcher["canonical"])
    )


def _decision(
    intent: dict[str, Any],
    policy_hash: str,
    outcome: str,
    reason: str,
    rules: list[str],
    now: datetime,
) -> dict[str, Any]:
    identity = content_hash(
        [intent.get("intent_id"), policy_hash, outcome, reason, sorted(rules), now.isoformat()]
    )
    return {
        "schema_version": "1.0.0",
        "decision_id": str(uuid.uuid5(_NAMESPACE, identity)),
        "intent_id": intent["intent_id"],
        "assessment_id": intent["assessment_id"],
        "policy_hash": policy_hash,
        "outcome": outcome,
        "reason_codes": [reason],
        "evaluated_rule_ids": sorted(set(rules)),
        "runtime_checks_required": [],
        "decided_at": now.isoformat().replace("+00:00", "Z"),
        "evaluator": {
            "name": "pentai-policy-evaluator",
            "version": "1.0.0",
            "canonicalization_version": "1.0.0",
        },
    }


def evaluate(
    policy: dict[str, Any],
    intent: dict[str, Any],
    *,
    active: bool,
    revoked: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    instant = (now or datetime.now(UTC)).astimezone(UTC)
    material = deepcopy(policy)
    stored_hash = material.pop("content_hash", "")

    def deny(reason: str, rules: list[str] | None = None) -> dict[str, Any]:
        return _decision(intent, str(stored_hash), "deny", reason, rules or [], instant)

    if (
        not stored_hash
        or content_hash(material) != stored_hash
        or intent.get("policy_hash") != stored_hash
    ):
        return deny("POLICY_HASH_MISMATCH")
    if not active:
        return deny("POLICY_INACTIVE")
    if revoked:
        return deny("POLICY_REVOKED")
    try:
        start = datetime.fromisoformat(policy["validity"]["not_before"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(policy["validity"]["not_after"].replace("Z", "+00:00"))
        if instant < start or instant >= end:
            return deny("POLICY_EXPIRED")
    except (KeyError, TypeError, ValueError):
        return deny("POLICY_HASH_MISMATCH")
    try:
        target = canonicalize_url(intent["target"]["canonical_url"])
        supplied = {key: intent["target"].get(key) for key in ("scheme", "host", "port", "path")}
        if supplied != {key: target[key] for key in supplied}:
            return deny("TARGET_AMBIGUOUS")
    except (KeyError, TypeError, CanonicalizationError):
        return deny("TARGET_AMBIGUOUS")
    capability_rules = [
        r for r in policy["capability_rules"] if r["capability"] == intent.get("capability")
    ]
    blocked = [r for r in capability_rules if r["effect"] == "deny"]
    if blocked:
        return deny("CAPABILITY_DENIED", [r["rule_id"] for r in blocked])
    if not any(r["effect"] == "allow" for r in capability_rules):
        return deny("CAPABILITY_DENIED")
    method_capability = {
        "GET": "network.http.get",
        "HEAD": "network.http.head",
        "OPTIONS": "network.http.options",
    }.get(intent.get("http", {}).get("method"))
    if method_capability != intent.get("capability"):
        return deny("METHOD_DENIED")
    matches = [r for r in policy["asset_rules"] if _matches(r, target)]
    if not matches:
        return deny("TARGET_OUT_OF_SCOPE")
    maximum = max(r["specificity"] for r in matches)
    effective = [r for r in matches if r["specificity"] == maximum]
    denied = [r for r in effective if r["effect"] == "deny"]
    if denied:
        return deny("EXPLICIT_DENY", [r["rule_id"] for r in denied])
    allowed = [r for r in effective if r["effect"] == "allow"]
    if not allowed:
        return deny("DEFAULT_DENY")
    if not any(not r.get("allowed_ports") or target["port"] in r["allowed_ports"] for r in allowed):
        return deny("PORT_DENIED", [r["rule_id"] for r in allowed])
    if not any(
        not r.get("allowed_paths")
        or any(path_matches(p, cast(str, target["path"])) for p in r["allowed_paths"])
        for r in allowed
    ):
        return deny("PATH_DENIED", [r["rule_id"] for r in allowed])
    return _decision(
        intent, stored_hash, "allow", "EXPLICIT_ALLOW", [r["rule_id"] for r in allowed], instant
    )
