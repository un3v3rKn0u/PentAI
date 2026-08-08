from __future__ import annotations

import ipaddress
import posixpath
import re
import unicodedata
from dataclasses import asdict, dataclass
from urllib.parse import quote, urlsplit, urlunsplit

import idna


class CanonicalizationError(ValueError):
    """Raised when a target value is invalid or authorization-ambiguous."""


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$|^[a-z0-9]$")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEX = frozenset("0123456789abcdefABCDEF")


def canonicalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise CanonicalizationError("domain must be text")
    if value != value.strip() or not value:
        raise CanonicalizationError("domain contains surrounding whitespace or is empty")
    if any(token in value for token in ("/", "\\", "@", "%", "[", "]")):
        raise CanonicalizationError("domain contains URL or encoded syntax")
    if re.fullmatch(r"[0-9.]+", value.removesuffix(".")):
        raise CanonicalizationError("ambiguous IPv4-like domain")
    normalized = unicodedata.normalize("NFC", value)
    if normalized.endswith("."):
        normalized = normalized[:-1]
    if not normalized:
        raise CanonicalizationError("domain is empty")
    try:
        ascii_domain = (
            idna.encode(normalized, uts46=True, transitional=False, std3_rules=True)
            .decode("ascii")
            .lower()
        )
    except idna.IDNAError as exc:
        raise CanonicalizationError("invalid internationalized domain") from exc
    if len(ascii_domain) > 253:
        raise CanonicalizationError("domain is too long")
    labels = ascii_domain.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise CanonicalizationError("invalid domain label")
    return ascii_domain


def canonicalize_wildcard_domain(value: str) -> str:
    """Return the canonical base of an explicit left-most-label wildcard."""
    if not isinstance(value, str) or not value.startswith("*."):
        raise CanonicalizationError("wildcard domain must start with '*.'")
    if "*" in value[2:]:
        raise CanonicalizationError("wildcard is allowed only as the complete left-most label")
    return canonicalize_domain(value[2:])


def canonicalize_port(value: int | str) -> int:
    if isinstance(value, bool):
        raise CanonicalizationError("boolean is not a port")
    if isinstance(value, str):
        if not value.isascii() or not value.isdecimal() or value.startswith("0"):
            raise CanonicalizationError("port must be unambiguous decimal")
        value = int(value)
    if not isinstance(value, int) or not 1 <= value <= 65535:
        raise CanonicalizationError("port must be from 1 through 65535")
    return value


def canonicalize_ip(value: str) -> dict[str, str]:
    if not isinstance(value, str) or value != value.strip() or "%" in value:
        raise CanonicalizationError("IP address is empty, spaced, or zone-qualified")
    if ":" not in value and "." in value:
        octets = value.split(".")
        if len(octets) != 4 or any(
            not octet.isascii()
            or not octet.isdecimal()
            or (len(octet) > 1 and octet.startswith("0"))
            for octet in octets
        ):
            raise CanonicalizationError("IPv4 must use strict dotted decimal")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise CanonicalizationError("invalid IP address") from exc
    return {
        "family": "ipv4" if address.version == 4 else "ipv6",
        "value": address.compressed.lower(),
    }


def canonicalize_cidr(value: str) -> dict[str, object]:
    if not isinstance(value, str) or value != value.strip() or "/" not in value or "%" in value:
        raise CanonicalizationError("CIDR must be unambiguous text with a prefix")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise CanonicalizationError("invalid CIDR or non-zero host bits") from exc
    return {
        "family": "ipv4" if network.version == 4 else "ipv6",
        "network": network.network_address.compressed.lower(),
        "prefix_length": network.prefixlen,
        "canonical": network.with_prefixlen.lower(),
    }


def _normalize_percent_encoding(value: str, *, path: bool) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "%":
            output.append(value[index])
            index += 1
            continue
        if index + 2 >= len(value) or any(
            character not in _HEX for character in value[index + 1 : index + 3]
        ):
            raise CanonicalizationError("malformed percent encoding")
        encoded = value[index : index + 3]
        decoded = chr(int(encoded[1:], 16))
        if path and decoded in {"/", "\\", "%"}:
            raise CanonicalizationError("encoded separator or percent is authorization-ambiguous")
        output.append(decoded if decoded in _UNRESERVED else encoded.upper())
        index += 3
    return "".join(output)


def canonicalize_path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise CanonicalizationError("path must be absolute")
    if "\\" in value or "?" in value or "#" in value:
        raise CanonicalizationError("path contains URL delimiters or backslashes")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise CanonicalizationError("path contains a control character")
    normalized_percent = _normalize_percent_encoding(value, path=True)
    normalized_path = posixpath.normpath(normalized_percent)
    if normalized_path.startswith("//"):
        normalized_path = "/" + normalized_path.lstrip("/")
    if normalized_percent.endswith("/") and normalized_path != "/":
        normalized_path += "/"
    safe_path = quote(normalized_path, safe="/:@-._~!$&'()*+,;=%")
    if _normalize_percent_encoding(safe_path, path=True) != safe_path:
        raise CanonicalizationError("path did not reach a stable canonical form")
    return safe_path


@dataclass(frozen=True)
class CanonicalUrl:
    scheme: str
    host: dict[str, str]
    port: int
    path: str
    query: str
    canonical_url: str


def canonicalize_url(value: str) -> dict[str, object]:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CanonicalizationError("URL is empty or contains surrounding whitespace")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise CanonicalizationError("URL contains a control character")
    if "\\" in value:
        raise CanonicalizationError("backslash is authorization-ambiguous")
    try:
        parsed = urlsplit(value)
        parsed_port = parsed.port
    except ValueError as exc:
        raise CanonicalizationError("invalid URL authority or port") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.netloc:
        raise CanonicalizationError("URL must be absolute HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise CanonicalizationError("URL userinfo is forbidden")
    if "#" in value:
        raise CanonicalizationError("URL fragments are not authorization targets")
    hostname = parsed.hostname
    if hostname is None:
        raise CanonicalizationError("URL hostname is missing")
    try:
        host = canonicalize_ip(hostname)
        host_kind = host["family"]
        host_value = host["value"]
    except CanonicalizationError:
        if re.fullmatch(r"[0-9.]+", hostname):
            raise CanonicalizationError("ambiguous IPv4-like hostname") from None
        host_kind = "domain"
        host_value = canonicalize_domain(hostname)
    port = parsed_port if parsed_port is not None else (443 if scheme == "https" else 80)
    canonicalize_port(port)
    safe_path = canonicalize_path(parsed.path or "/")
    query = _normalize_percent_encoding(parsed.query, path=False)
    display_host = f"[{host_value}]" if host_kind == "ipv6" else host_value
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    authority = display_host if default_port else f"{display_host}:{port}"
    canonical = urlunsplit((scheme, authority, safe_path, query, ""))
    return asdict(
        CanonicalUrl(
            scheme=scheme,
            host={"kind": host_kind, "value": host_value},
            port=port,
            path=safe_path,
            query=query,
            canonical_url=canonical,
        )
    )
