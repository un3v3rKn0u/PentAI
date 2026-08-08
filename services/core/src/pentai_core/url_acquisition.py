from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

import idna

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
ALLOWED_MEDIA_TYPES = {
    "application/json",
    "application/pdf",
    "text/html",
    "text/markdown",
    "text/plain",
}


class AcquisitionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class FetchResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    peer_ip: str


@dataclass(frozen=True)
class AcquiredSource:
    final_url: str
    media_type: str
    content: bytes


class Resolver(Protocol):
    def resolve(self, hostname: str, port: int) -> tuple[str, ...]: ...


class Transport(Protocol):
    def fetch(self, url: str, pinned_ip: str, timeout_seconds: float) -> FetchResponse: ...


class SystemResolver:
    def resolve(self, hostname: str, port: int) -> tuple[str, ...]:
        try:
            answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise AcquisitionError("SOURCE_DNS_FAILED", "source host resolution failed") from exc
        return tuple(sorted({str(answer[4][0]) for answer in answers}))


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class PinnedHttpTransport:
    def fetch(self, url: str, pinned_ip: str, timeout_seconds: float) -> FetchResponse:
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        sock = socket.create_connection((pinned_ip, port), timeout=timeout_seconds)
        try:
            if parsed.scheme == "https":
                sock = _tls_context().wrap_socket(sock, server_hostname=parsed.hostname)
            peer_ip = str(sock.getpeername()[0])
            request_target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            host = parsed.hostname or ""
            default_port = 443 if parsed.scheme == "https" else 80
            host_header = host if port == default_port else f"{host}:{port}"
            sock.sendall(
                f"GET {request_target} HTTP/1.1\r\nHost: {host_header}\r\n"
                "Accept: text/plain,text/markdown,text/html,application/json,application/pdf\r\n"
                "User-Agent: PentAI-Source-Acquirer/1\r\nConnection: close\r\n\r\n".encode()
            )
            response = http.client.HTTPResponse(sock)
            response.begin()
            length = response.getheader("Content-Length")
            if length is not None and int(length) > MAX_RESPONSE_BYTES:
                raise AcquisitionError("SOURCE_TOO_LARGE", "source response exceeds 2 MiB")
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise AcquisitionError("SOURCE_TOO_LARGE", "source response exceeds 2 MiB")
            return FetchResponse(
                response.status,
                {key.lower(): value for key, value in response.getheaders()},
                body,
                peer_ip,
            )
        except (OSError, http.client.HTTPException, ValueError) as exc:
            if isinstance(exc, AcquisitionError):
                raise
            raise AcquisitionError("SOURCE_FETCH_FAILED", "source request failed") from exc
        finally:
            sock.close()


def canonicalize_url(value: str) -> tuple[str, str, int]:
    try:
        stripped = value.strip()
        if len(stripped) > 2048 or any(
            ord(character) < 32 or ord(character) == 127 for character in stripped
        ):
            raise ValueError
        parsed = urlsplit(stripped)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError
        try:
            literal = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            hostname = (
                idna.encode(parsed.hostname, uts46=True, std3_rules=True).decode("ascii").lower()
            )
            display_hostname = hostname
        else:
            hostname = str(literal)
            display_hostname = f"[{hostname}]" if literal.version == 6 else hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in {80, 443}:
            raise ValueError
        default_port = 443 if parsed.scheme == "https" else 80
        authority = display_hostname if port == default_port else f"{display_hostname}:{port}"
        canonical = urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))
        return canonical, hostname, port
    except (ValueError, UnicodeError, idna.IDNAError) as exc:
        raise AcquisitionError("SOURCE_URL_INVALID", "source URL is invalid") from exc


def _validate_addresses(addresses: tuple[str, ...]) -> tuple[str, ...]:
    if not addresses:
        raise AcquisitionError("SOURCE_DNS_FAILED", "source host returned no addresses")
    try:
        parsed = tuple(ipaddress.ip_address(value) for value in addresses)
    except ValueError as exc:
        raise AcquisitionError("SOURCE_DNS_INVALID", "source DNS answer is invalid") from exc
    if any(not address.is_global for address in parsed):
        raise AcquisitionError("SOURCE_ADDRESS_DENIED", "source DNS answer is not public")
    return tuple(
        str(address) for address in sorted(parsed, key=lambda item: (item.version, int(item)))
    )


class UrlAcquirer:
    def __init__(
        self, resolver: Resolver | None = None, transport: Transport | None = None
    ) -> None:
        self.resolver = resolver or SystemResolver()
        self.transport = transport or PinnedHttpTransport()

    def acquire(self, initial_url: str) -> AcquiredSource:
        current, _, _ = canonicalize_url(initial_url)
        previous_scheme = urlsplit(current).scheme
        for redirect_count in range(MAX_REDIRECTS + 1):
            current, hostname, port = canonicalize_url(current)
            current_scheme = urlsplit(current).scheme
            if previous_scheme == "https" and current_scheme != "https":
                raise AcquisitionError("SOURCE_REDIRECT_DENIED", "HTTPS downgrade is denied")
            previous_scheme = current_scheme
            addresses = _validate_addresses(self.resolver.resolve(hostname, port))
            pinned_ip = addresses[0]
            response = self.transport.fetch(current, pinned_ip, 10.0)
            try:
                if ipaddress.ip_address(response.peer_ip) != ipaddress.ip_address(pinned_ip):
                    raise AcquisitionError(
                        "SOURCE_PEER_MISMATCH", "source peer did not match DNS pin"
                    )
            except ValueError as exc:
                raise AcquisitionError("SOURCE_PEER_MISMATCH", "source peer is invalid") from exc
            if response.status in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location or redirect_count == MAX_REDIRECTS:
                    raise AcquisitionError("SOURCE_REDIRECT_DENIED", "source redirect is invalid")
                current = urljoin(current, location)
                continue
            if response.status < 200 or response.status >= 300:
                raise AcquisitionError("SOURCE_HTTP_STATUS", "source server returned an error")
            if not response.body:
                raise AcquisitionError("SOURCE_EMPTY", "source content is required")
            if len(response.body) > MAX_RESPONSE_BYTES:
                raise AcquisitionError("SOURCE_TOO_LARGE", "source response exceeds 2 MiB")
            media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if media_type not in ALLOWED_MEDIA_TYPES:
                raise AcquisitionError(
                    "SOURCE_MEDIA_TYPE_INVALID", "source media type is not approved"
                )
            return AcquiredSource(current, media_type, response.body)
        raise AcquisitionError("SOURCE_REDIRECT_DENIED", "source redirect limit exceeded")
