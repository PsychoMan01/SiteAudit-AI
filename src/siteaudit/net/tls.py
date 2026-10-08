"""TLS certificate inspection (read-only handshake against a validated address)."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime

from .urlsafety import Policy, resolve_allowed


@dataclass
class TLSInfo:
    checked: bool
    valid: bool = False
    expires_at: datetime | None = None
    issuer: str | None = None
    protocol: str | None = None
    error: str | None = None

    @property
    def days_left(self) -> int | None:
        if self.expires_at is None:
            return None
        return (self.expires_at - datetime.now(UTC)).days


def inspect_certificate(host: str, port: int = 443, *, policy: Policy, timeout: float = 10.0) -> TLSInfo:
    try:
        addresses = resolve_allowed(host, port, policy)
    except Exception as exc:
        return TLSInfo(checked=False, error=getattr(exc, "code", "connection_error"))
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((addresses[0], port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            cert = tls.getpeercert() or {}
            protocol = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return TLSInfo(checked=True, valid=False, error=(exc.verify_message or "certificate_invalid")[:120])
    except (ssl.SSLError, OSError) as exc:
        return TLSInfo(checked=False, error=type(exc).__name__)
    expires = None
    not_after = cert.get("notAfter")
    if isinstance(not_after, str):
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
    issuer = None
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:  # type: ignore[str-unpack]
            if key in ("organizationName", "commonName") and issuer is None:
                issuer = str(value)[:120]
    return TLSInfo(checked=True, valid=True, expires_at=expires, issuer=issuer, protocol=protocol)
