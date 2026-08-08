# Canonical Target Formats v1

**Contract:** PENTAI-CANON-v1<br>
**Principle:** Parse, validate, canonicalize, then compare. Failure or ambiguity denies.
**Owner:** Policy Maintainer<br>
**Compatibility owner:** Contract Maintainer<br>
**Approval:** Approved under sole-maintainer security-review exception (non-independent).

Successful canonicalization is deterministic and idempotent. A canonical value
canonicalizes to itself; malformed or authorization-ambiguous input fails closed.

## Domain

- Input is Unicode or ASCII hostname text, never a URL.
- Apply Unicode NFC and non-transitional UTS #46/IDNA2008 ASCII conversion with STD3 rules.
- Lowercase ASCII and remove exactly one terminal root dot.
- Reject empty labels, labels over 63 octets, total ASCII name over 253 characters, invalid hyphen placement, control characters, percent encoding, ports, paths, userinfo, and IP literals.
- Canonical representation: ASCII A-label hostname without a trailing dot.
- Wildcard input must use `*.` as the complete left-most label. Policies store the
  canonical `base_domain` plus explicit `include_apex`; matching occurs only on label boundaries.
- `example.com.evil.test` never matches `example.com`.

## URL

- Supported schemes in MVP: `http` and `https`.
- Reject userinfo, fragments for authorization, malformed percent encoding, backslashes in authority/path ambiguity, and non-absolute URLs.
- Canonicalize the hostname using Domain rules or IP rules.
- Remove the default port (`80` for HTTP, `443` for HTTPS); retain non-default ports.
- Empty path becomes `/`.
- Remove dot segments before policy comparison.
- Percent-decode only unreserved characters; uppercase retained percent-hex. Reject
  encoded `/`, `\\`, and `%` in paths to prevent separator and double-decoding ambiguity.
- Preserve query for request identity, but scope path matching does not infer query authorization.
- Policy path matching uses segment/boundary semantics: `/api` matches `/api` and `/api/...`, not `/apiv2`.
- Redirect targets are parsed and authorized as new runtime destinations.

Canonical object:

```json
{
  "scheme": "https",
  "host": {"kind": "domain", "value": "api.example.com"},
  "port": 443,
  "path": "/v1/items",
  "query": "page=1",
  "canonical_url": "https://api.example.com/v1/items?page=1"
}
```

The explicit numeric `port` records the effective port even when omitted from `canonical_url`.

## Port

- Decimal integer from 1 through 65535.
- No signs, whitespace, hexadecimal, octal interpretation, ranges, or service names.
- Policy ranges compile to closed integer intervals with start ≤ end.
- MVP execution permits ports only when scheme and asset policy explicitly allow them.

## IPv4

- Parse strict dotted-decimal with exactly four decimal octets.
- Each octet is 0–255; reject leading `+`, whitespace, shortened, integer, hexadecimal, octal, and leading-zero ambiguous forms.
- Canonical representation: standard dotted decimal.
- Classify loopback, private, link-local, multicast, documentation, reserved, unspecified, and public ranges.

## IPv6

- Parse as a 128-bit address.
- Canonical representation follows RFC 5952: lowercase hex, compressed longest zero run, no zone identifier.
- Reject zone IDs for target authorization.
- IPv4-mapped IPv6 is classified explicitly and cannot bypass IPv4 rules.
- Link-local, loopback, multicast, unspecified, unique-local, documentation, and reserved ranges are classified.
- IPv6 execution is disabled unless the policy includes an attested IPv6 egress identity.

## CIDR

- Parse an IPv4 or IPv6 address plus decimal prefix length.
- IPv4 prefix is 0–32; IPv6 prefix is 0–128.
- Host bits must be zero in policy input; reject rather than silently mask.
- Canonical representation uses the canonical network address and prefix.
- Membership is binary network containment, never string prefix comparison.

## Matching and precedence

1. Canonicalize both policy value and runtime value with the same contract version.
2. Determine all applicable rules.
3. Choose the most specific asset/range/path rule.
4. At equal or greater specificity, deny overrides allow.
5. If no explicit allow remains, deny.
6. Re-evaluate after DNS, CNAME, redirect, port, scheme, SNI/Host, or protocol changes.

## Deliberately stricter behavior

- `urllib.parse` is used only as a structural reference. PentAI additionally rejects
  userinfo, every fragment delimiter (including an empty fragment), port zero,
  IPv4-like hostnames, backslashes, and malformed percent escapes.
- `ipaddress` is the differential reference for accepted IP/CIDR values. PentAI also
  rejects IPv4 leading zeros, zone identifiers, and CIDRs with host bits set.
  IPv4-mapped IPv6 remains IPv6 and uses `ipaddress`'s stable compressed form.
- The `idna` package is the domain reference. PentAI adds DNS length/label limits and
  rejects URL, wildcard, and encoded syntax from ordinary domain values.
- Generic URL servers may assign meaning to encoded separators or repeated decoding;
  PentAI rejects those inputs because different intermediary behavior is unsafe for
  authorization.

The fixture corpus records discovered defects. Hypothesis tests cover determinism,
idempotence, boundaries, Unicode, arbitrary malicious text, and differential behavior
in the normal `pytest` CI job.
