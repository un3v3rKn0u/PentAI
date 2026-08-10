from __future__ import annotations

import secrets
import socket
import ssl
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Protocol

from pentai_policy import CanonicalizationError, canonicalize_domain

from pentai_core.controlled_dns import ControlledDnsError, RawDnsAnswer

_A = 1
_CNAME = 5
_AAAA = 28
_IN = 1
_MAX_DNS_MESSAGE_BYTES = 4096
_MAX_RESOURCE_RECORDS = 64
_MAX_POINTER_JUMPS = 16


class DnsWireTransport(Protocol):
    def exchange(
        self,
        query: bytes,
        *,
        server_ip: str,
        server_port: int,
        timeout_seconds: float,
        tls_hostname: str | None,
    ) -> bytes: ...


class SocketDnsWireTransport:
    """Pinned TCP/DoT transport with no ambient resolver or proxy use."""

    def exchange(
        self,
        query: bytes,
        *,
        server_ip: str,
        server_port: int,
        timeout_seconds: float,
        tls_hostname: str | None,
    ) -> bytes:
        framed = struct.pack("!H", len(query)) + query
        connection: socket.socket | ssl.SSLSocket | None = None
        deadline = time.monotonic() + timeout_seconds
        try:
            connection = socket.create_connection(
                (server_ip, server_port), timeout=_remaining(deadline)
            )
            connection.settimeout(_remaining(deadline))
            if tls_hostname is not None:
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                connection = context.wrap_socket(connection, server_hostname=tls_hostname)
            connection.settimeout(_remaining(deadline))
            connection.sendall(framed)
            size = struct.unpack("!H", _read_exact(connection, 2, deadline=deadline))[0]
            if not 12 <= size <= _MAX_DNS_MESSAGE_BYTES:
                raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS response size is invalid")
            return _read_exact(connection, size, deadline=deadline)
        except ControlledDnsError:
            raise
        except (OSError, ssl.SSLError, struct.error) as exc:
            raise ControlledDnsError(
                "DNS_TRANSPORT_FAILED", "controlled DNS transport failed"
            ) from exc
        finally:
            if connection is not None:
                connection.close()


@dataclass(frozen=True)
class ParsedDnsResponse:
    addresses: tuple[str, ...]
    cnames: tuple[str, ...]


class PinnedDnsBackend:
    def __init__(
        self,
        *,
        resolver_mode: str,
        server_ip: str,
        tls_hostname: str | None = None,
        timeout_seconds: float = 2,
        transport: DnsWireTransport | None = None,
        transaction_id: Callable[[], int] | None = None,
    ) -> None:
        try:
            canonical_server = ip_address(server_ip).compressed
        except ValueError as exc:
            raise ControlledDnsError("DNS_RESOLVER_INVALID", "resolver address is invalid") from exc
        if resolver_mode == "tunnel_resolver":
            if tls_hostname is not None:
                raise ControlledDnsError(
                    "DNS_RESOLVER_INVALID", "tunnel resolver must not configure a TLS name"
                )
            server_port = 53
            canonical_tls_name = None
        elif resolver_mode == "approved_resolver":
            if tls_hostname is None:
                raise ControlledDnsError(
                    "DNS_RESOLVER_INVALID", "approved resolver requires a TLS name"
                )
            try:
                canonical_tls_name = canonicalize_domain(tls_hostname)
            except CanonicalizationError as exc:
                raise ControlledDnsError(
                    "DNS_RESOLVER_INVALID", "resolver TLS name is invalid"
                ) from exc
            server_port = 853
        else:
            raise ControlledDnsError("DNS_RESOLVER_INVALID", "resolver mode is invalid")
        if not 0.1 <= timeout_seconds <= 10:
            raise ControlledDnsError("DNS_RESOLVER_INVALID", "resolver timeout is invalid")
        self._server_ip = canonical_server
        self._server_port = server_port
        self._tls_hostname = canonical_tls_name
        self._timeout_seconds = timeout_seconds
        self._transport = transport or SocketDnsWireTransport()
        self._transaction_id = transaction_id or (lambda: secrets.randbits(16))

    def resolve(self, hostname: str, port: int) -> RawDnsAnswer:
        del port
        try:
            canonical_hostname = canonicalize_domain(hostname)
        except CanonicalizationError as exc:
            raise ControlledDnsError("DNS_NAME_INVALID", "DNS name is invalid") from exc
        addresses: list[str] = []
        cname_chains: list[tuple[str, ...]] = []
        transaction_ids: set[int] = set()
        for query_type in (_A, _AAAA):
            transaction_id = self._next_transaction_id(transaction_ids)
            transaction_ids.add(transaction_id)
            query = _build_query(canonical_hostname, query_type, transaction_id)
            response = self._transport.exchange(
                query,
                server_ip=self._server_ip,
                server_port=self._server_port,
                timeout_seconds=self._timeout_seconds,
                tls_hostname=self._tls_hostname,
            )
            parsed = _parse_response(
                response,
                hostname=canonical_hostname,
                query_type=query_type,
                transaction_id=transaction_id,
            )
            addresses.extend(parsed.addresses)
            cname_chains.append(parsed.cnames)
        if cname_chains[0] != cname_chains[1]:
            raise ControlledDnsError(
                "DNS_CNAME_MISMATCH", "DNS address families returned different CNAME chains"
            )
        return RawDnsAnswer(tuple(addresses), cname_chains[0])

    def _next_transaction_id(self, used: set[int]) -> int:
        for _attempt in range(4):
            value = self._transaction_id()
            if 0 <= value <= 65535 and value not in used:
                return value
        raise ControlledDnsError(
            "DNS_TRANSACTION_INVALID", "DNS transaction identity is invalid"
        )


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ControlledDnsError("DNS_TRANSPORT_FAILED", "controlled DNS transport timed out")
    return remaining


def _read_exact(
    connection: socket.socket | ssl.SSLSocket, length: int, *, deadline: float
) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(remaining)
        if not chunk:
            raise ControlledDnsError("DNS_TRANSPORT_FAILED", "controlled DNS response ended early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _build_query(hostname: str, query_type: int, transaction_id: int) -> bytes:
    labels = hostname.split(".")
    encoded = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ControlledDnsError("DNS_NAME_INVALID", "DNS name is invalid")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + bytes(encoded) + struct.pack("!HH", query_type, _IN)


def _parse_response(
    packet: bytes, *, hostname: str, query_type: int, transaction_id: int
) -> ParsedDnsResponse:
    if not 12 <= len(packet) <= _MAX_DNS_MESSAGE_BYTES:
        raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS response size is invalid")
    try:
        response_id, flags, questions, answers, authorities, additionals = struct.unpack(
            "!HHHHHH", packet[:12]
        )
    except struct.error as exc:
        raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS response is malformed") from exc
    if response_id != transaction_id:
        raise ControlledDnsError("DNS_TRANSACTION_MISMATCH", "DNS response identity does not match")
    if (
        flags & 0x8000 == 0
        or flags & 0x7800
        or flags & 0x0200
        or flags & 0x0040
        or flags & 0x000F
        or questions != 1
        or answers + authorities + additionals > _MAX_RESOURCE_RECORDS
    ):
        raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS response flags or counts are invalid")
    question_name, offset = _decode_name(packet, 12)
    if offset + 4 > len(packet):
        raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS question is truncated")
    response_type, response_class = struct.unpack("!HH", packet[offset : offset + 4])
    offset += 4
    if question_name != hostname or response_type != query_type or response_class != _IN:
        raise ControlledDnsError("DNS_QUESTION_MISMATCH", "DNS response question does not match")

    addresses: list[str] = []
    cnames: list[str] = []
    allowed_names = {hostname}
    total_records = answers + authorities + additionals
    for index in range(total_records):
        owner, offset = _decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS record is truncated")
        record_type, record_class, _ttl, data_length = struct.unpack(
            "!HHIH", packet[offset : offset + 10]
        )
        offset += 10
        data_end = offset + data_length
        if data_end > len(packet):
            raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS record data is truncated")
        if index < answers and record_class == _IN:
            if record_type == _CNAME:
                if owner not in allowed_names:
                    raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS CNAME owner is unrelated")
                target, consumed = _decode_name(packet, offset)
                if consumed != data_end or target in allowed_names or target in cnames:
                    raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS CNAME chain is invalid")
                cnames.append(target)
                allowed_names.add(target)
            elif record_type == query_type:
                if owner not in allowed_names:
                    raise ControlledDnsError(
                        "DNS_RESPONSE_INVALID", "DNS answer owner is unrelated"
                    )
                expected_length = 4 if query_type == _A else 16
                if data_length != expected_length:
                    raise ControlledDnsError(
                        "DNS_RESPONSE_INVALID", "DNS address length is invalid"
                    )
                addresses.append(ip_address(packet[offset:data_end]).compressed)
        offset = data_end
    if offset != len(packet):
        raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS response has trailing data")
    if len(addresses) != len(set(addresses)):
        raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS response contains duplicates")
    return ParsedDnsResponse(tuple(addresses), tuple(cnames))


def _decode_name(packet: bytes, start: int) -> tuple[str, int]:
    labels: list[str] = []
    offset = start
    consumed: int | None = None
    visited: set[int] = set()
    jumps = 0
    while True:
        if offset >= len(packet):
            raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS name is truncated")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS pointer is truncated")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer >= len(packet) or pointer in visited or jumps >= _MAX_POINTER_JUMPS:
                raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS pointer is invalid")
            visited.add(pointer)
            jumps += 1
            if consumed is None:
                consumed = offset + 2
            offset = pointer
            continue
        if length & 0xC0:
            raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS label encoding is invalid")
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(packet):
            raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS label is invalid")
        try:
            labels.append(packet[offset : offset + length].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS label is not ASCII") from exc
        offset += length
    if not labels:
        return "", consumed if consumed is not None else offset
    try:
        name = canonicalize_domain(".".join(labels))
    except CanonicalizationError as exc:
        raise ControlledDnsError("DNS_RESPONSE_INVALID", "DNS name is invalid") from exc
    return name, consumed if consumed is not None else offset
