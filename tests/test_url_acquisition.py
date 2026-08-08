from __future__ import annotations

import ssl
from dataclasses import dataclass

import pytest
from pentai_core.url_acquisition import (
    AcquisitionError,
    FetchResponse,
    UrlAcquirer,
    _tls_context,
    canonicalize_url,
)


def test_tls_context_requires_tls_1_2_or_newer() -> None:
    assert _tls_context().minimum_version == ssl.TLSVersion.TLSv1_2


@dataclass
class FakeResolver:
    answers: dict[str, tuple[str, ...]]

    def resolve(self, hostname: str, port: int) -> tuple[str, ...]:
        return self.answers.get(hostname, ())


class FakeTransport:
    def __init__(self, responses: list[FetchResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str]] = []

    def fetch(self, url: str, pinned_ip: str, timeout_seconds: float) -> FetchResponse:
        self.calls.append((url, pinned_ip))
        return self.responses.pop(0)


def test_acquisition_pins_dns_and_reauthorizes_redirect() -> None:
    transport = FakeTransport(
        [
            FetchResponse(
                302, {"location": "https://docs.example.org/rules"}, b"", "93.184.216.34"
            ),
            FetchResponse(
                200,
                {"content-type": "application/json; charset=utf-8"},
                b'{"scope": ["owned.invalid"]}',
                "93.184.216.35",
            ),
        ]
    )
    acquired = UrlAcquirer(
        FakeResolver(
            {
                "example.org": ("93.184.216.34",),
                "docs.example.org": ("93.184.216.35",),
            }
        ),
        transport,
    ).acquire("HTTPS://Example.org")
    assert acquired.final_url == "https://docs.example.org/rules"
    assert acquired.media_type == "application/json"
    assert transport.calls == [
        ("https://example.org/", "93.184.216.34"),
        ("https://docs.example.org/rules", "93.184.216.35"),
    ]


@pytest.mark.parametrize(
    ("answers", "code"),
    [
        (("127.0.0.1",), "SOURCE_ADDRESS_DENIED"),
        (("93.184.216.34", "10.0.0.1"), "SOURCE_ADDRESS_DENIED"),
        (("::1",), "SOURCE_ADDRESS_DENIED"),
        ((), "SOURCE_DNS_FAILED"),
    ],
)
def test_private_mixed_and_empty_dns_answers_fail_closed(
    answers: tuple[str, ...], code: str
) -> None:
    with pytest.raises(AcquisitionError) as raised:
        UrlAcquirer(FakeResolver({"example.org": answers}), FakeTransport([])).acquire(
            "https://example.org/rules"
        )
    assert raised.value.code == code


def test_redirect_to_private_host_is_blocked_before_second_connection() -> None:
    transport = FakeTransport(
        [FetchResponse(302, {"location": "https://127.0.0.1/admin"}, b"", "93.184.216.34")]
    )
    with pytest.raises(AcquisitionError) as raised:
        UrlAcquirer(
            FakeResolver({"example.org": ("93.184.216.34",), "127.0.0.1": ("127.0.0.1",)}),
            transport,
        ).acquire("https://example.org")
    assert raised.value.code == "SOURCE_ADDRESS_DENIED"
    assert len(transport.calls) == 1


def test_https_redirect_downgrade_is_blocked_before_second_connection() -> None:
    transport = FakeTransport(
        [FetchResponse(302, {"location": "http://example.org/plain"}, b"", "93.184.216.34")]
    )
    with pytest.raises(AcquisitionError) as raised:
        UrlAcquirer(FakeResolver({"example.org": ("93.184.216.34",)}), transport).acquire(
            "https://example.org"
        )
    assert raised.value.code == "SOURCE_REDIRECT_DENIED"
    assert len(transport.calls) == 1


def test_peer_mismatch_response_limit_and_media_type_fail_closed() -> None:
    cases = [
        (
            FetchResponse(200, {"content-type": "text/plain"}, b"ok", "93.184.216.35"),
            "SOURCE_PEER_MISMATCH",
        ),
        (
            FetchResponse(
                200, {"content-type": "text/plain"}, b"x" * (2 * 1024 * 1024 + 1), "93.184.216.34"
            ),
            "SOURCE_TOO_LARGE",
        ),
        (
            FetchResponse(200, {"content-type": "application/octet-stream"}, b"x", "93.184.216.34"),
            "SOURCE_MEDIA_TYPE_INVALID",
        ),
    ]
    for response, code in cases:
        with pytest.raises(AcquisitionError) as raised:
            UrlAcquirer(
                FakeResolver({"example.org": ("93.184.216.34",)}),
                FakeTransport([response]),
            ).acquire("https://example.org")
        assert raised.value.code == code


@pytest.mark.parametrize(
    "value",
    [
        "file:///etc/passwd",
        "https://user@example.org/",
        "https://example.org:8443/",
        "https://example.org/#fragment",
        "https://example.org/\r\nHost: attacker.invalid",
        "https://example.org/" + "x" * 2049,
        "https://[::1",
    ],
)
def test_malformed_or_unsafe_urls_are_rejected(value: str) -> None:
    with pytest.raises(AcquisitionError) as raised:
        canonicalize_url(value)
    assert raised.value.code == "SOURCE_URL_INVALID"


def test_public_ipv6_literal_is_canonicalized() -> None:
    assert canonicalize_url("https://[2606:2800:220:1:248:1893:25c8:1946]")[0] == (
        "https://[2606:2800:220:1:248:1893:25c8:1946]/"
    )
