from __future__ import annotations

import os
import ssl
import struct
import unittest
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import ip_address
from unittest.mock import patch

from pentai_core.config import Settings
from pentai_core.controlled_dns import ControlledDnsError
from pentai_core.controlled_dns_composition import compose_controlled_resolver
from pentai_core.controlled_dns_transport import (
    PinnedDnsBackend,
    SocketDnsWireTransport,
    _parse_response,
)


def _name(value: str) -> bytes:
    encoded = bytearray()
    for label in value.split("."):
        raw = label.encode("ascii")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def _response(
    query: bytes,
    *,
    addresses: tuple[str, ...] = (),
    cname: str | None = None,
    flags: int = 0x8180,
    response_id: int | None = None,
    trailing: bytes = b"",
) -> bytes:
    query_id = struct.unpack("!H", query[:2])[0]
    query_type = struct.unpack("!H", query[-4:-2])[0]
    records: list[bytes] = []
    owner = b"\xc0\x0c"
    if cname is not None:
        cname_data = _name(cname)
        records.append(owner + struct.pack("!HHIH", 5, 1, 30, len(cname_data)) + cname_data)
        owner = _name(cname)
    for value in addresses:
        packed = ip_address(value).packed
        record_type = 1 if len(packed) == 4 else 28
        if record_type == query_type:
            records.append(
                owner + struct.pack("!HHIH", record_type, 1, 30, len(packed)) + packed
            )
    header = struct.pack(
        "!HHHHHH",
        query_id if response_id is None else response_id,
        flags,
        1,
        len(records),
        0,
        0,
    )
    return header + query[12:] + b"".join(records) + trailing


@dataclass
class FixtureTransport:
    responder: Callable[[bytes], bytes]
    calls: list[dict[str, object]] = field(default_factory=list)

    def exchange(
        self,
        query: bytes,
        *,
        server_ip: str,
        server_port: int,
        timeout_seconds: float,
        tls_hostname: str | None,
    ) -> bytes:
        self.calls.append(
            {
                "server_ip": server_ip,
                "server_port": server_port,
                "timeout_seconds": timeout_seconds,
                "tls_hostname": tls_hostname,
            }
        )
        return self.responder(query)


def network_settings(**changed: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "test_mode": True,
        "network_attestation_enabled": True,
        "network_observers": (
            "observer-a|ipv4|https://observer-a.invalid/ip",
            "observer-b|ipv4|https://observer-b.invalid/ip",
        ),
        "network_route_profile_id": "fixture-route",
        "network_route_interface": "tun0",
        "network_route_gateway": "10.0.0.1",
        "network_resolver_mode": "tunnel_resolver",
        "network_resolver_id": "fixture-resolver",
        "network_resolver_addresses": ("10.0.0.53",),
        "controlled_dns_enabled": True,
        "controlled_dns_server_ip": "10.0.0.53",
        "controlled_dns_timeout_seconds": 0.2,
    }
    values.update(changed)
    return Settings(**values)


class ControlledDnsTransportTests(unittest.TestCase):
    def test_socket_transport_frames_pinned_tcp_and_dot_without_proxy_resolution(self) -> None:
        class FixtureSocket:
            def __init__(self, response: bytes) -> None:
                self.incoming = bytearray(struct.pack("!H", len(response)) + response)
                self.sent = b""
                self.timeout = 0.0
                self.closed = False

            def settimeout(self, value: float) -> None:
                self.timeout = value

            def sendall(self, value: bytes) -> None:
                self.sent += value

            def recv(self, length: int) -> bytes:
                result = bytes(self.incoming[:length])
                del self.incoming[:length]
                return result

            def close(self) -> None:
                self.closed = True

        response = b"x" * 12
        connection = FixtureSocket(response)
        destinations: list[tuple[tuple[str, int], float]] = []

        def connect(destination: tuple[str, int], timeout: float) -> FixtureSocket:
            destinations.append((destination, timeout))
            return connection

        with patch(
            "pentai_core.controlled_dns_transport.socket.create_connection", connect
        ):
            result = SocketDnsWireTransport().exchange(
                b"query",
                server_ip="10.0.0.53",
                server_port=53,
                timeout_seconds=0.2,
                tls_hostname=None,
            )
        self.assertEqual(result, response)
        self.assertEqual(destinations[0][0], ("10.0.0.53", 53))
        self.assertGreater(destinations[0][1], 0)
        self.assertLessEqual(destinations[0][1], 0.2)
        self.assertEqual(connection.sent, b"\x00\x05query")
        self.assertTrue(connection.closed)

        tls_connection = FixtureSocket(response)

        class FixtureContext:
            minimum_version: object = None

            def wrap_socket(
                self, raw: FixtureSocket, *, server_hostname: str
            ) -> FixtureSocket:
                self.server_hostname = server_hostname
                return raw

        context = FixtureContext()
        with (
            patch(
                "pentai_core.controlled_dns_transport.socket.create_connection",
                return_value=tls_connection,
            ),
            patch(
                "pentai_core.controlled_dns_transport.ssl.create_default_context",
                return_value=context,
            ),
        ):
            SocketDnsWireTransport().exchange(
                b"query",
                server_ip="1.1.1.1",
                server_port=853,
                timeout_seconds=0.2,
                tls_hostname="resolver.example",
            )
        self.assertEqual(context.server_hostname, "resolver.example")
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_pinned_tcp_resolver_validates_transactions_and_combines_families(self) -> None:
        transport = FixtureTransport(
            lambda query: _response(
                query,
                addresses=("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"),
            )
        )
        identifiers = iter((0x1234, 0x5678))
        backend = PinnedDnsBackend(
            resolver_mode="tunnel_resolver",
            server_ip="10.0.0.53",
            timeout_seconds=0.2,
            transport=transport,
            transaction_id=lambda: next(identifiers),
        )
        answer = backend.resolve("example.com", 443)
        self.assertEqual(
            answer.addresses,
            ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"),
        )
        self.assertEqual(
            transport.calls,
            [
                {
                    "server_ip": "10.0.0.53",
                    "server_port": 53,
                    "timeout_seconds": 0.2,
                    "tls_hostname": None,
                },
                {
                    "server_ip": "10.0.0.53",
                    "server_port": 53,
                    "timeout_seconds": 0.2,
                    "tls_hostname": None,
                },
            ],
        )

    def test_approved_resolver_requires_dot_and_pins_tls_identity(self) -> None:
        transport = FixtureTransport(lambda query: _response(query, addresses=("1.1.1.1",)))
        backend = PinnedDnsBackend(
            resolver_mode="approved_resolver",
            server_ip="1.1.1.1",
            tls_hostname="Resolver.Example",
            transport=transport,
            transaction_id=iter((7, 8)).__next__,
        )
        self.assertEqual(backend.resolve("example.com", 443).addresses, ("1.1.1.1",))
        self.assertEqual(transport.calls[0]["server_port"], 853)
        self.assertEqual(transport.calls[0]["tls_hostname"], "resolver.example")
        for mode, hostname in (("approved_resolver", None), ("tunnel_resolver", "dns.test")):
            with self.subTest(mode=mode), self.assertRaises(ControlledDnsError):
                PinnedDnsBackend(
                    resolver_mode=mode,
                    server_ip="1.1.1.1",
                    tls_hostname=hostname,
                )

    def test_cname_chain_is_validated_and_deduplicated_across_queries(self) -> None:
        transport = FixtureTransport(
            lambda query: _response(
                query,
                cname="edge.example.com",
                addresses=("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"),
            )
        )
        answer = PinnedDnsBackend(
            resolver_mode="tunnel_resolver",
            server_ip="10.0.0.53",
            transport=transport,
            transaction_id=iter((9, 10)).__next__,
        ).resolve("example.com", 443)
        self.assertEqual(answer.cname_chain, ("edge.example.com",))

    def test_address_family_cname_disagreement_denies(self) -> None:
        calls = 0

        def disagree(query: bytes) -> bytes:
            nonlocal calls
            calls += 1
            return _response(
                query,
                cname="edge-a.example.com" if calls == 1 else "edge-b.example.com",
                addresses=("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"),
            )

        backend = PinnedDnsBackend(
            resolver_mode="tunnel_resolver",
            server_ip="10.0.0.53",
            transport=FixtureTransport(disagree),
            transaction_id=iter((11, 12)).__next__,
        )
        with self.assertRaises(ControlledDnsError) as raised:
            backend.resolve("example.com", 443)
        self.assertEqual(raised.exception.code, "DNS_CNAME_MISMATCH")

    def test_spoof_replay_truncation_and_trailing_data_deny(self) -> None:
        query_name = _name("example.com")
        query = struct.pack("!HHHHHH", 11, 0x0100, 1, 0, 0, 0) + query_name + struct.pack(
            "!HH", 1, 1
        )
        cases = (
            (_response(query, response_id=12), "DNS_TRANSACTION_MISMATCH"),
            (_response(query, flags=0x8380), "DNS_RESPONSE_INVALID"),
            (_response(query, flags=0x8183), "DNS_RESPONSE_INVALID"),
            (_response(query, trailing=b"x"), "DNS_RESPONSE_INVALID"),
        )
        for response, expected in cases:
            with self.subTest(expected=expected), self.assertRaises(ControlledDnsError) as raised:
                _parse_response(
                    response,
                    hostname="example.com",
                    query_type=1,
                    transaction_id=11,
                )
            self.assertEqual(raised.exception.code, expected)

    def test_question_pointer_and_record_corruption_deny(self) -> None:
        query = struct.pack("!HHHHHH", 11, 0x0100, 1, 0, 0, 0) + _name(
            "example.com"
        ) + struct.pack("!HH", 1, 1)
        wrong_question = bytearray(_response(query, addresses=("93.184.216.34",)))
        question_type_offset = 12 + len(_name("example.com"))
        wrong_question[question_type_offset : question_type_offset + 2] = struct.pack(
            "!H", 28
        )
        pointer_loop = (
            struct.pack("!HHHHHH", 11, 0x8180, 1, 1, 0, 0)
            + query[12:]
            + b"\xc0\x1d"
            + struct.pack("!HHIH", 1, 1, 30, 4)
            + ip_address("93.184.216.34").packed
        )
        for response in (bytes(wrong_question), pointer_loop, b"short"):
            with self.subTest(response=response[:12]), self.assertRaises(ControlledDnsError):
                _parse_response(
                    response,
                    hostname="example.com",
                    query_type=1,
                    transaction_id=11,
                )

    def test_transport_failure_and_invalid_transaction_source_deny(self) -> None:
        class FailedTransport(FixtureTransport):
            def exchange(self, *args: object, **kwargs: object) -> bytes:
                raise ControlledDnsError("DNS_TRANSPORT_FAILED", "private detail")

        for backend, expected in (
            (
                PinnedDnsBackend(
                    resolver_mode="tunnel_resolver",
                    server_ip="10.0.0.53",
                    transport=FailedTransport(lambda _query: b""),
                ),
                "DNS_TRANSPORT_FAILED",
            ),
            (
                PinnedDnsBackend(
                    resolver_mode="tunnel_resolver",
                    server_ip="10.0.0.53",
                    transport=FixtureTransport(lambda query: _response(query)),
                    transaction_id=lambda: 65536,
                ),
                "DNS_TRANSACTION_INVALID",
            ),
            (
                PinnedDnsBackend(
                    resolver_mode="tunnel_resolver",
                    server_ip="10.0.0.53",
                    transport=FixtureTransport(lambda query: _response(query)),
                    transaction_id=lambda: 7,
                ),
                "DNS_TRANSACTION_INVALID",
            ),
        ):
            with self.subTest(expected=expected), self.assertRaises(ControlledDnsError) as raised:
                backend.resolve("example.com", 443)
            self.assertEqual(raised.exception.code, expected)

    def test_configuration_is_explicit_attested_and_transport_specific(self) -> None:
        settings = network_settings()
        settings.validate()
        with self.assertRaisesRegex(ValueError, "explicit enablement"):
            Settings(
                environment="test",
                test_mode=True,
                controlled_dns_server_ip="10.0.0.53",
            ).validate()
        cases = (
            {"controlled_dns_server_ip": "10.0.0.54"},
            {"network_attestation_enabled": False},
            {"controlled_dns_tls_hostname": "unexpected.example"},
            {"network_resolver_mode": "ambient"},
            {"network_resolver_id": "invalid resolver"},
            {
                "network_resolver_mode": "approved_resolver",
                "controlled_dns_tls_hostname": "bad host",
            },
            {"controlled_dns_timeout_seconds": 11},
        )
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                network_settings(**changed).validate()

    def test_environment_and_composition_bind_attested_resolver(self) -> None:
        environment = {
            "PENTAI_ENVIRONMENT": "test",
            "PENTAI_TEST_MODE": "1",
            "PENTAI_NETWORK_ATTESTATION_ENABLED": "1",
            "PENTAI_NETWORK_OBSERVERS": (
                "observer-a|ipv4|https://a.invalid/ip;"
                "observer-b|ipv4|https://b.invalid/ip"
            ),
            "PENTAI_NETWORK_ROUTE_PROFILE_ID": "fixture-route",
            "PENTAI_NETWORK_ROUTE_INTERFACE": "tun0",
            "PENTAI_NETWORK_ROUTE_GATEWAY": "10.0.0.1",
            "PENTAI_NETWORK_RESOLVER_MODE": "tunnel_resolver",
            "PENTAI_NETWORK_RESOLVER_ID": "fixture-resolver",
            "PENTAI_NETWORK_RESOLVER_ADDRESSES": "10.0.0.53",
            "PENTAI_CONTROLLED_DNS_ENABLED": "1",
            "PENTAI_CONTROLLED_DNS_SERVER_IP": "10.0.0.53",
            "PENTAI_CONTROLLED_DNS_TIMEOUT_SECONDS": "1",
        }
        with patch.dict(os.environ, environment, clear=True):
            settings = Settings.from_environment()
        transport = FixtureTransport(lambda query: _response(query, addresses=("1.1.1.1",)))
        resolver = compose_controlled_resolver(settings=settings, transport=transport)
        self.assertIsNotNone(resolver)
        assert resolver is not None
        answer = resolver.resolve(
            "example.com",
            443,
            attestation={
                "resolver_mode": "tunnel_resolver",
                "resolver_id": "fixture-resolver",
            },
        )
        self.assertEqual(answer.addresses, ("1.1.1.1",))


if __name__ == "__main__":
    unittest.main()
