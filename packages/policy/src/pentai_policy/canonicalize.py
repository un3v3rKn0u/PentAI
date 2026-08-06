from __future__ import annotations

import ipaddress
import posixpath
import re
import unicodedata
from dataclasses import asdict, dataclass
from urllib.parse import quote, unquote, urlsplit, urlunsplit


class CanonicalizationError(ValueError):
    """Raised when a target value is invalid or authorization-ambiguous."""


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$|^[a-z0-9]$")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def canonicalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise CanonicalizationError("domain must be text")
    if value != value.strip() or not value:
        raise CanonicalizationError("domain contains surrounding whitespace or is empty")
    if any(token in value for token in ("/", "\\", "@", "%", "[", "]")):
        raise CanonicalizationError("domain contains URL or encoded syntax")
    normalized = unicodedata.normalize("NFC", value)
    if normalized.endswith("."):
        normalized = normalized[:-1]
    if not normalized:
        raise CanonicalizationError("domain is empty")
    try:
        ascii_domain = normalized.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise CanonicalizationError("invalid internationalized domain") from exc
    if len(ascii_domain) > 253:
        raise CanonicalizationError("domain is too long")
    labels = ascii_domain.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise CanonicalizationError("invalid domain label")
    return ascii_domain


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
    if "." in value:
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
    if not isinstance(value, str) or value != value.strip() or "/" not in value:
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


def _normalize_percent_encoding(path: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(path):
        if path[index] != "%":
            output.append(path[index])
            index += 1
            continue
        if index + 2 >= len(path) or not re.fullmatch(
            r"[0-9A-Fa-f]{2}", path[index + 1 : index + 3]
        ):
            raise CanonicalizationError("malformed percent encoding")
        encoded = path[index : index + 3]
        decoded = chr(int(encoded[1:], 16))
        output.append(decoded if decoded in _UNRESERVED else encoded.upper())
        index += 3
    return "".join(output)


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
    if parsed.fragment:
        raise CanonicalizationError("URL fragments are not authorization targets")
    hostname = parsed.hostname
    if hostname is None:
        raise CanonicalizationError("URL hostname is missing")
    try:
        host = canonicalize_ip(hostname)
        host_kind = host["family"]
        host_value = host["value"]
    except CanonicalizationError:
        host_kind = "domain"
        host_value = canonicalize_domain(hostname)
    port = parsed_port or (443 if scheme == "https" else 80)
    canonicalize_port(port)
    raw_path = _normalize_percent_encoding(parsed.path or "/")
    decoded_for_segments = unquote(raw_path, errors="strict")
    normalized_path = posixpath.normpath(decoded_for_segments)
    if raw_path.endswith("/") and normalized_path != "/":
        normalized_path += "/"
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    safe_path = quote(normalized_path, safe="/:@-._~!$&'()*+,;=%")
    display_host = f"[{host_value}]" if host_kind == "ipv6" else host_value
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    authority = display_host if default_port else f"{display_host}:{port}"
    canonical = urlunsplit((scheme, authority, safe_path, parsed.query, ""))
    return asdict(
        CanonicalUrl(
            scheme=scheme,
            host={"kind": host_kind, "value": host_value},
            port=port,
            path=safe_path,
            query=parsed.query,
            canonical_url=canonical,
        )
    )
