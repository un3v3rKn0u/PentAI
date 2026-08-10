from __future__ import annotations

import http.client
import json
import platform
import re
import ssl
import subprocess
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from pentai_core.network_attestation import (
    AttestationError,
    RouteSnapshot,
    SourceObservation,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_MAX_OBSERVER_BYTES = 1024
_MAX_ROUTE_OUTPUT_BYTES = 65_536


class ObservationTransport(Protocol):
    def fetch(self, url: str, *, timeout_seconds: float, max_bytes: int) -> bytes: ...


class RouteProbe(Protocol):
    def inspect(self) -> HostRouteSnapshot: ...


@dataclass(frozen=True)
class HostRouteSnapshot:
    interface: str
    gateway: str | None
    resolver_addresses: tuple[str, ...]


class TlsObservationTransport:
    """Small HTTPS-only transport that ignores ambient proxy configuration."""

    def fetch(self, url: str, *, timeout_seconds: float, max_bytes: int) -> bytes:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if hostname is None:
            raise AttestationError("ATTESTATION_ENDPOINT_INVALID", "observer host is missing")
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection(
            hostname, parsed.port or 443, timeout=timeout_seconds, context=context
        )
        target = parsed.path or "/"
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "PentAI-Network-Attestor/1",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                raise AttestationError(
                    "ATTESTATION_OBSERVATION_FAILED", "observer response was not successful"
                )
            media_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                raise AttestationError(
                    "ATTESTATION_OBSERVATION_INVALID", "observer response type is invalid"
                )
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > max_bytes):
                raise AttestationError(
                    "ATTESTATION_OBSERVATION_INVALID", "observer response is oversized"
                )
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise AttestationError(
                    "ATTESTATION_OBSERVATION_INVALID", "observer response is oversized"
                )
            return payload
        except AttestationError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise AttestationError(
                "ATTESTATION_OBSERVATION_FAILED", "source identity observation failed"
            ) from exc
        finally:
            connection.close()


class HttpsSourceObserver:
    def __init__(
        self,
        *,
        endpoint_id: str,
        url: str,
        address_family: str,
        transport: ObservationTransport | None = None,
        timeout_seconds: float = 3,
    ) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not _IDENTIFIER.fullmatch(endpoint_id)
            or address_family not in {"ipv4", "ipv6"}
            or not 0.1 <= timeout_seconds <= 10
        ):
            raise AttestationError(
                "ATTESTATION_ENDPOINT_INVALID", "observer configuration is invalid"
            )
        try:
            port = parsed.port
        except ValueError as exc:
            raise AttestationError(
                "ATTESTATION_ENDPOINT_INVALID", "observer configuration is invalid"
            ) from exc
        if port not in {None, 443}:
            raise AttestationError(
                "ATTESTATION_ENDPOINT_INVALID", "observer must use the HTTPS default port"
            )
        if parsed.hostname == "localhost":
            raise AttestationError(
                "ATTESTATION_ENDPOINT_INVALID", "observer host must be an approved DNS name"
            )
        try:
            ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            raise AttestationError(
                "ATTESTATION_ENDPOINT_INVALID", "observer host must be an approved DNS name"
            )
        self._endpoint_id = endpoint_id
        self._url = url
        self._address_family = address_family
        self._transport = transport or TlsObservationTransport()
        self._timeout_seconds = timeout_seconds

    def observe(self) -> SourceObservation:
        payload = self._transport.fetch(
            self._url,
            timeout_seconds=self._timeout_seconds,
            max_bytes=_MAX_OBSERVER_BYTES,
        )
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AttestationError(
                "ATTESTATION_OBSERVATION_INVALID", "observer response is malformed"
            ) from exc
        if not isinstance(document, dict) or set(document) != {"ip"}:
            raise AttestationError(
                "ATTESTATION_OBSERVATION_INVALID", "observer response is malformed"
            )
        value = document["ip"]
        if not isinstance(value, str):
            raise AttestationError(
                "ATTESTATION_OBSERVATION_INVALID", "observer response is malformed"
            )
        try:
            address = ip_address(value)
        except ValueError as exc:
            raise AttestationError(
                "ATTESTATION_ADDRESS_INVALID", "observer returned an invalid address"
            ) from exc
        if (self._address_family == "ipv4" and address.version != 4) or (
            self._address_family == "ipv6" and address.version != 6
        ):
            raise AttestationError(
                "ATTESTATION_ADDRESS_INVALID", "observer returned the wrong address family"
            )
        if not address.is_global:
            raise AttestationError(
                "ATTESTATION_ADDRESS_INVALID", "observer returned a non-public address"
            )
        canonical = address.compressed
        return SourceObservation(
            self._endpoint_id,
            source_ipv4=canonical if address.version == 4 else None,
            source_ipv6=canonical if address.version == 6 else None,
        )


class ExactRouteInspector:
    def __init__(
        self,
        *,
        probe: RouteProbe,
        route_profile_id: str,
        expected_interface: str,
        expected_gateway: str | None,
        resolver_mode: str,
        resolver_id: str,
        expected_resolvers: tuple[str, ...],
    ) -> None:
        if (
            not _IDENTIFIER.fullmatch(route_profile_id)
            or not expected_interface.strip()
            or resolver_mode not in {"tunnel_resolver", "approved_resolver"}
            or not _IDENTIFIER.fullmatch(resolver_id)
            or not expected_resolvers
        ):
            raise AttestationError("ATTESTATION_ROUTE_INVALID", "route configuration is invalid")
        try:
            gateway = ip_address(expected_gateway).compressed if expected_gateway else None
            resolvers = tuple(ip_address(value).compressed for value in expected_resolvers)
        except ValueError as exc:
            raise AttestationError(
                "ATTESTATION_ROUTE_INVALID", "route configuration is invalid"
            ) from exc
        if len(set(resolvers)) != len(resolvers):
            raise AttestationError("ATTESTATION_ROUTE_INVALID", "resolver configuration is invalid")
        self._probe = probe
        self._profile = route_profile_id
        self._interface = expected_interface
        self._gateway = gateway
        self._resolver_mode = resolver_mode
        self._resolver_id = resolver_id
        self._resolvers = frozenset(resolvers)

    def inspect(self) -> RouteSnapshot:
        observed = self._probe.inspect()
        try:
            gateway = ip_address(observed.gateway).compressed if observed.gateway else None
            resolvers = frozenset(
                ip_address(value).compressed for value in observed.resolver_addresses
            )
        except ValueError as exc:
            raise AttestationError("ATTESTATION_ROUTE_INVALID", "route probe is invalid") from exc
        if (
            observed.interface != self._interface
            or gateway != self._gateway
            or resolvers != self._resolvers
        ):
            raise AttestationError("ATTESTATION_ROUTE_MISMATCH", "route identity changed")
        return RouteSnapshot(self._profile, self._resolver_mode, self._resolver_id)


class SystemRouteProbe:
    def __init__(self, *, timeout_seconds: float = 2) -> None:
        if not 0.1 <= timeout_seconds <= 10:
            raise ValueError("route probe timeout must be 0.1–10 seconds")
        self._timeout_seconds = timeout_seconds

    def inspect(self) -> HostRouteSnapshot:
        system = platform.system()
        if system == "Darwin":
            return self._darwin()
        if system == "Linux":
            return self._linux()
        if system == "Windows":
            return self._windows()
        raise AttestationError(
            "ATTESTATION_ROUTE_UNSUPPORTED", "host route inspection is unsupported"
        )

    def _run(self, command: tuple[str, ...]) -> str:
        try:
            completed = subprocess.run(  # noqa: S603 - commands are fixed below
                command,
                check=False,
                capture_output=True,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AttestationError("ATTESTATION_ROUTE_FAILED", "route inspection failed") from exc
        if completed.returncode != 0 or len(completed.stdout) > _MAX_ROUTE_OUTPUT_BYTES:
            raise AttestationError("ATTESTATION_ROUTE_FAILED", "route inspection failed")
        try:
            return completed.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AttestationError(
                "ATTESTATION_ROUTE_INVALID", "route output is malformed"
            ) from exc

    def _darwin(self) -> HostRouteSnapshot:
        route = self._run(("/sbin/route", "-n", "get", "default"))
        dns = self._run(("/usr/sbin/scutil", "--dns"))
        interface = _single_match(route, r"^\s*interface:\s*(\S+)\s*$")
        gateway = _optional_single_match(route, r"^\s*gateway:\s*(\S+)\s*$")
        resolvers = tuple(re.findall(r"^\s*nameserver\[\d+\]\s*:\s*(\S+)\s*$", dns, re.M))
        return _host_snapshot(interface, gateway, resolvers)

    def _linux(self) -> HostRouteSnapshot:
        raw = self._run(("/usr/sbin/ip", "-json", "route", "show", "default"))
        try:
            routes = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AttestationError(
                "ATTESTATION_ROUTE_INVALID", "route output is malformed"
            ) from exc
        if not isinstance(routes, list) or len(routes) != 1 or not isinstance(routes[0], dict):
            raise AttestationError("ATTESTATION_ROUTE_INVALID", "default route is ambiguous")
        interface = routes[0].get("dev")
        gateway = routes[0].get("gateway")
        if not isinstance(interface, str) or (gateway is not None and not isinstance(gateway, str)):
            raise AttestationError("ATTESTATION_ROUTE_INVALID", "route output is malformed")
        try:
            resolver_text = Path("/etc/resolv.conf").read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise AttestationError(
                "ATTESTATION_ROUTE_FAILED", "resolver inspection failed"
            ) from exc
        resolvers = tuple(re.findall(r"^\s*nameserver\s+(\S+)\s*$", resolver_text, re.M))
        return _host_snapshot(interface, gateway, resolvers)

    def _windows(self) -> HostRouteSnapshot:
        script = (
            "$r=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
            "Where-Object {$_.State -eq 'Alive'} | Sort-Object RouteMetric);"
            "if($r.Count -ne 1){exit 3};$i=Get-NetIPInterface -InterfaceIndex $r[0].InterfaceIndex;"
            "$d=@(Get-DnsClientServerAddress -InterfaceIndex $r[0].InterfaceIndex | "
            "Select-Object -ExpandProperty ServerAddresses);"
            "@{interface=$i.InterfaceAlias;gateway=$r[0].NextHop;resolvers=$d}|"
            "ConvertTo-Json -Compress"
        )
        raw = self._run(("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script))
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AttestationError(
                "ATTESTATION_ROUTE_INVALID", "route output is malformed"
            ) from exc
        if not isinstance(document, dict):
            raise AttestationError("ATTESTATION_ROUTE_INVALID", "route output is malformed")
        interface, gateway, resolvers = (
            document.get("interface"),
            document.get("gateway"),
            document.get("resolvers"),
        )
        if not isinstance(interface, str) or not isinstance(resolvers, list):
            raise AttestationError("ATTESTATION_ROUTE_INVALID", "route output is malformed")
        return _host_snapshot(
            interface, gateway if isinstance(gateway, str) else None, tuple(resolvers)
        )


def _single_match(value: str, pattern: str) -> str:
    matches = re.findall(pattern, value, re.M)
    if len(matches) != 1:
        raise AttestationError("ATTESTATION_ROUTE_INVALID", "route output is ambiguous")
    return str(matches[0])


def _optional_single_match(value: str, pattern: str) -> str | None:
    matches = re.findall(pattern, value, re.M)
    if len(matches) > 1:
        raise AttestationError("ATTESTATION_ROUTE_INVALID", "route output is ambiguous")
    return matches[0] if matches else None


def _host_snapshot(
    interface: str, gateway: str | None, resolvers: tuple[object, ...]
) -> HostRouteSnapshot:
    if (
        not interface.strip()
        or not resolvers
        or any(not isinstance(value, str) for value in resolvers)
    ):
        raise AttestationError("ATTESTATION_ROUTE_INVALID", "route output is incomplete")
    return HostRouteSnapshot(interface, gateway, tuple(str(value) for value in resolvers))
