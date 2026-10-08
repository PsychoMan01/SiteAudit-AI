"""URL validation and destination policy (SSRF protection).

Two layers protect every outbound request:

1. `normalize_target()` validates what the user typed (scheme, credentials, port, hostname shape).
2. `resolve_allowed()` is called at *connection time* by the guarded network backend, so every request —
   including each redirect hop and every link check — is re-validated against the resolved IP addresses.
   The socket connects to the exact address that was checked, which defeats DNS rebinding.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = ("http", "https")
ALLOWED_PORTS = (80, 443)

_BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
    ".private",
    ".localdomain",
    ".home.arpa",
    ".arpa",
)
_BLOCKED_HOSTS = {"localhost", "metadata", "metadata.google.internal", "instance-data"}


_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


class UnsafeURLError(ValueError):
    """Raised when a URL is malformed or points to a forbidden destination."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class BlockedDestinationError(ConnectionError):
    """Raised at connection time when a hostname resolves to a forbidden address."""

    code = "blocked_destination"


class DNSResolutionError(ConnectionError):
    code = "dns"


@dataclass(frozen=True)
class Policy:
    allow_private: bool = False

    def port_allowed(self, port: int) -> bool:
        return self.allow_private or port in ALLOWED_PORTS

    def ip_allowed(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return self.allow_private or ip_is_public(ip)

    def hostname_allowed(self, host: str) -> bool:
        return self.allow_private or _hostname_shape_ok(host)


def ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        for embedded in (ip.ipv4_mapped, ip.sixtofour):
            if embedded is not None:
                return ip_is_public(embedded)
        teredo = ip.teredo
        if teredo is not None:
            return ip_is_public(teredo[1])
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return False
    return bool(ip.is_global)


def _hostname_shape_ok(host: str) -> bool:
    if host in _BLOCKED_HOSTS or any(host.endswith(s) for s in _BLOCKED_HOST_SUFFIXES):
        return False
    labels = host.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    return all(
        set(label) <= allowed and not label.startswith("-") and not label.endswith("-") for label in labels
    )


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    # Legacy numeric forms such as "2130706433" or "0x7f.1" are rejected outright.
    if host.replace(".", "").replace("x", "").isalnum() and all(
        part.isdigit() or part.startswith("0x") for part in host.split(".")
    ):
        raise UnsafeURLError("invalid_host", "Numeric host notation is not supported.")
    return None


def normalize_target(raw: str, policy: Policy | None = None) -> str:
    """Validate a user-supplied website address and return a normalized absolute URL."""
    policy = policy or Policy()
    value = (raw or "").strip()
    if not value:
        raise UnsafeURLError("empty", "Enter a website address.")
    if len(value) > MAX_URL_LENGTH:
        raise UnsafeURLError("too_long", "The address is too long.")
    if any(ch.isspace() for ch in value) or any(ord(ch) < 32 for ch in value):
        raise UnsafeURLError("invalid", "The address contains invalid characters.")
    scheme_match = _SCHEME.match(value)
    if scheme_match and not value[scheme_match.end() :][:1].isdigit():
        # "javascript:…", "file:/…", "data:…": an explicit scheme without "//".
        if "://" not in value:
            raise UnsafeURLError("scheme", "Only http:// and https:// addresses can be audited.")
    elif "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError("scheme", "Only http:// and https:// addresses can be audited.")
    if parts.username is not None or parts.password is not None:
        raise UnsafeURLError("credentials", "Addresses with embedded credentials are not allowed.")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise UnsafeURLError("invalid_host", "The address has no host name.")
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeURLError("invalid_port", "The port number is invalid.") from exc
    if port is not None and not policy.port_allowed(port):
        raise UnsafeURLError("port", "Only the standard web ports (80 and 443) can be audited.")

    ip = _parse_ip(host)
    if ip is not None:
        if not policy.ip_allowed(ip):
            raise UnsafeURLError(
                "private_address", "Private, local and reserved addresses cannot be audited."
            )
        host_out = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    else:
        try:
            host_ascii = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise UnsafeURLError("invalid_host", "The host name is invalid.") from exc
        if not policy.hostname_allowed(host_ascii):
            raise UnsafeURLError("invalid_host", "Enter a public website address, such as example.com.")
        host_out = host_ascii

    default_port = 443 if scheme == "https" else 80
    netloc = host_out if port in (None, default_port) else f"{host_out}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def resolve_allowed(host: str, port: int, policy: Policy) -> list[str]:
    """Resolve `host` and return the addresses that may be contacted. Raises if none may."""
    if not policy.port_allowed(port):
        raise BlockedDestinationError(f"port {port} is not allowed")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise DNSResolutionError(str(exc)) from exc
    addresses: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
        if not policy.ip_allowed(ip):
            # A single forbidden record poisons the whole answer: do not try to "pick the safe one".
            raise BlockedDestinationError("destination resolves to a non-public address")
        if addr not in addresses:
            addresses.append(addr)
    if not addresses:
        raise DNSResolutionError("no addresses")
    return addresses
