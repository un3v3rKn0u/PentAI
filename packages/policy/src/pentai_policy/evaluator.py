from __future__ import annotations

from datetime import UTC, datetime, time
from ipaddress import ip_address, ip_network
from typing import Any
from uuid import UUID, uuid5
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pentai_policy.canonicalize import CanonicalizationError, canonicalize_url
from pentai_policy.document import content_hash, contract_issues, parse_time

EVALUATOR_VERSION = "1.0.0"
_NAMESPACE = UUID("9b879065-2de4-4fd7-b03c-5fe2bccdfcca")
_RUNTIME_CHECKS = [
    "policy_status",
    "clock",
    "route_identity",
    "source_ip",
    "dns",
    "destination_ip",
    "sni_host",
    "port",
    "redirect",
    "rate",
    "response_size",
]


def _path_matches(prefix: str, path: str) -> bool:
    prefix = prefix.rstrip("/") or "/"
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


def _asset_matches(rule: dict[str, Any], target: dict[str, Any]) -> bool:
    matcher = rule["matcher"]
    kind = rule["asset_type"]
    host = target["host"]
    path_prefix = matcher.get("path_prefix")
    if path_prefix is not None and not _path_matches(path_prefix, target["path"]):
        return False
    if kind == "url":
        return (
            matcher["scheme"] == target["scheme"]
            and matcher["host"] == host
            and matcher["port"] == target["port"]
            and _path_matches(matcher["path"], target["path"])
        )
    if kind == "domain":
        return bool(host == {"kind": "domain", "value": matcher["value"]})
    if kind == "wildcard_domain":
        if host["kind"] != "domain":
            return False
        value = host["value"]
        base = matcher["value"]
        return bool((matcher.get("include_apex") and value == base) or value.endswith("." + base))
    if kind in {"ipv4", "ipv6"}:
        return bool(host == {"kind": kind, "value": matcher["value"]})
    if kind == "cidr" and host["kind"] in {"ipv4", "ipv6"}:
        return ip_address(host["value"]) in ip_network(matcher["value"])
    return False


def _window_end(window: dict[str, Any], instant: datetime) -> datetime | None:
    zone = ZoneInfo(window["timezone"])
    local = instant.astimezone(zone)
    current_time = local.strftime("%H:%M")
    if (
        local.strftime("%A").lower() not in window["days"]
        or not window["start_time"] <= current_time < window["end_time"]
    ):
        return None
    local_end_time = time.fromisoformat(window["end_time"])
    candidates: list[datetime] = []
    for fold in (0, 1):
        local_end = datetime.combine(local.date(), local_end_time, zone).replace(fold=fold)
        candidate = local_end.astimezone(UTC)
        if candidate.astimezone(zone).replace(tzinfo=None) == local_end.replace(tzinfo=None):
            candidates.append(candidate)
    future_candidates = [candidate for candidate in candidates if candidate > instant]
    return min(future_candidates, default=None)


def testing_schedule_deadline(schedule: dict[str, Any], instant: datetime) -> datetime | None:
    try:
        blackout_starts: list[datetime] = []
        for period in schedule["blackout_periods"]:
            starts_at = parse_time(period["starts_at"])
            if starts_at <= instant < parse_time(period["ends_at"]):
                return None
            if starts_at > instant:
                blackout_starts.append(starts_at)
        window_ends = [
            end
            for window in schedule["allowed_windows"]
            if (end := _window_end(window, instant)) is not None
        ]
        if not window_ends:
            return None
        deadline = max(window_ends)
        if blackout_starts:
            deadline = min(deadline, min(blackout_starts))
        return deadline if deadline > instant else None
    except (KeyError, TypeError, ValueError, ZoneInfoNotFoundError):
        return None


def testing_schedule_allows(schedule: dict[str, Any], instant: datetime) -> bool:
    return testing_schedule_deadline(schedule, instant) is not None


def _decision(
    intent: dict[str, Any],
    policy_hash: str,
    outcome: str,
    reasons: list[str],
    rule_ids: list[str],
) -> dict[str, Any]:
    seed = {
        "intent": intent,
        "policy_hash": policy_hash,
        "outcome": outcome,
        "reason_codes": reasons,
        "evaluated_rule_ids": sorted(set(rule_ids)),
    }
    return {
        "schema_version": "1.0.0",
        "decision_id": str(uuid5(_NAMESPACE, content_hash(seed))),
        "intent_id": intent.get("intent_id", "00000000-0000-0000-0000-000000000000"),
        "assessment_id": intent.get("assessment_id", "00000000-0000-0000-0000-000000000000"),
        "policy_hash": policy_hash,
        "outcome": outcome,
        "reason_codes": reasons,
        "evaluated_rule_ids": sorted(set(rule_ids)),
        "runtime_checks_required": _RUNTIME_CHECKS if outcome == "allow" else [],
        "decided_at": intent.get("created_at", "1970-01-01T00:00:00Z"),
        "evaluator": {
            "name": "pentai-policy-evaluator",
            "version": EVALUATOR_VERSION,
            "canonicalization_version": "1.0.0",
        },
    }


def evaluate(
    intent: dict[str, Any],
    policy: dict[str, Any],
    *,
    active: bool,
    revoked: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    stored_hash = str(policy.get("content_hash", "0" * 64))
    unsigned = {
        key: value for key, value in policy.items() if key not in {"content_hash", "signature"}
    }
    signature = policy.get("signature", {})
    signer_key_id = signature.get("key_id") if isinstance(signature, dict) else None
    signed_hash = content_hash({"policy": unsigned, "signer_key_id": signer_key_id})
    if signed_hash != stored_hash or intent.get("policy_hash") != stored_hash:
        return _decision(intent, stored_hash, "deny", ["POLICY_HASH_MISMATCH"], [])
    if contract_issues(intent, "action-intent-v1.schema.json"):
        return _decision(intent, stored_hash, "deny", ["DEFAULT_DENY"], [])
    if intent["assessment_id"] != policy.get("engagement_id"):
        return _decision(intent, stored_hash, "deny", ["DEFAULT_DENY"], [])
    if revoked:
        return _decision(intent, stored_hash, "deny", ["POLICY_REVOKED"], [])
    if not active:
        return _decision(intent, stored_hash, "deny", ["POLICY_INACTIVE"], [])
    instant = (now or datetime.now(UTC)).astimezone(UTC)
    if instant < parse_time(policy["validity"]["not_before"]):
        return _decision(intent, stored_hash, "deny", ["POLICY_INACTIVE"], [])
    if instant >= parse_time(policy["validity"]["not_after"]):
        return _decision(intent, stored_hash, "deny", ["POLICY_EXPIRED"], [])
    if instant < parse_time(intent["created_at"]) or instant >= parse_time(intent["expires_at"]):
        return _decision(intent, stored_hash, "deny", ["TESTING_WINDOW_CLOSED"], [])
    testing_schedule = policy.get("testing_schedule")
    if isinstance(testing_schedule, dict) and not testing_schedule_allows(
        testing_schedule, instant
    ):
        return _decision(intent, stored_hash, "deny", ["TESTING_WINDOW_CLOSED"], [])
    try:
        canonical = canonicalize_url(intent["target"]["canonical_url"])
    except (CanonicalizationError, KeyError, TypeError):
        return _decision(intent, stored_hash, "deny", ["TARGET_AMBIGUOUS"], [])
    if canonical != intent.get("target"):
        return _decision(intent, stored_hash, "deny", ["TARGET_AMBIGUOUS"], [])

    account_constraints = policy.get("account_constraints")
    if isinstance(account_constraints, dict):
        account_reference = intent.get("account_reference")
        if account_constraints.get("mode") == "unauthenticated_only" and account_reference:
            return _decision(intent, stored_hash, "deny", ["ACCOUNT_DENIED"], [])
        if account_constraints.get("mode") == "approved_test_accounts" and (
            not account_reference
            or account_reference not in account_constraints.get("approved_account_references", [])
        ):
            return _decision(intent, stored_hash, "deny", ["ACCOUNT_DENIED"], [])

    capability_rules = [
        rule
        for rule in policy["capability_rules"]
        if rule["capability"] == intent.get("capability")
    ]
    if not capability_rules or any(rule["effect"] == "deny" for rule in capability_rules):
        return _decision(
            intent,
            stored_hash,
            "deny",
            ["CAPABILITY_DENIED"],
            [rule["rule_id"] for rule in capability_rules],
        )
    if any(rule["effect"] == "conditional" for rule in capability_rules):
        return _decision(
            intent,
            stored_hash,
            "deny",
            ["APPROVAL_MISSING"],
            [rule["rule_id"] for rule in capability_rules],
        )
    expected_method = {
        "network.http.get": "GET",
        "network.http.head": "HEAD",
        "network.http.options": "OPTIONS",
    }.get(intent["capability"])
    if intent.get("http", {}).get("method") != expected_method:
        return _decision(
            intent,
            stored_hash,
            "deny",
            ["METHOD_DENIED"],
            [rule["rule_id"] for rule in capability_rules],
        )

    matches = [rule for rule in policy["asset_rules"] if _asset_matches(rule, canonical)]
    if not matches:
        return _decision(intent, stored_hash, "deny", ["TARGET_OUT_OF_SCOPE"], [])
    max_specificity = max(rule["specificity"] for rule in matches)
    applicable = [rule for rule in matches if rule["specificity"] >= max_specificity]
    rule_ids = [rule["rule_id"] for rule in applicable]
    if any(rule["effect"] == "deny" for rule in applicable):
        return _decision(intent, stored_hash, "deny", ["EXPLICIT_DENY"], rule_ids)
    if any(rule["effect"] != "allow" for rule in applicable):
        return _decision(intent, stored_hash, "deny", ["DEFAULT_DENY"], rule_ids)
    for rule in applicable:
        ports = rule.get("allowed_ports", [])
        if ports and canonical["port"] not in ports:
            return _decision(intent, stored_hash, "deny", ["PORT_DENIED"], rule_ids)
        allowed_paths = rule.get("allowed_paths", [])
        if allowed_paths and not any(
            _path_matches(path, str(canonical["path"])) for path in allowed_paths
        ):
            return _decision(intent, stored_hash, "deny", ["PATH_DENIED"], rule_ids)
    return _decision(intent, stored_hash, "allow", ["EXPLICIT_ALLOW"], rule_ids)
