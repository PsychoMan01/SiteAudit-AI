"""Outbound HTTP client used for every request made on behalf of a user.

- Connections go through `GuardedBackend`, which validates resolved addresses (see `urlsafety`).
- Environment proxies are ignored, redirects are followed manually and re-validated, bodies are size-capped.
"""

from __future__ import annotations

import socket
import ssl
import time
import typing
from dataclasses import dataclass, field

import httpcore
import httpx
from httpcore._backends.sync import SyncBackend, SyncStream

from .urlsafety import (
    BlockedDestinationError,
    DNSResolutionError,
    Policy,
    UnsafeURLError,
    normalize_target,
    resolve_allowed,
)

MAX_REDIRECTS = 5


class GuardedBackend(SyncBackend):
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ) -> httpcore.NetworkStream:
        addresses = resolve_allowed(host, port, self.policy)
        last_exc: Exception | None = None
        for addr in addresses:
            try:
                sock = socket.create_connection((addr, port), timeout)
            except TimeoutError as exc:
                raise httpcore.ConnectTimeout(str(exc)) from exc
            except OSError as exc:
                last_exc = exc
                continue
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return SyncStream(sock)
        raise httpcore.ConnectError(str(last_exc))

    def connect_unix_socket(self, *args: typing.Any, **kwargs: typing.Any) -> httpcore.NetworkStream:
        raise BlockedDestinationError("unix sockets are not allowed")


class GuardedTransport(httpx.HTTPTransport):
    def __init__(self, policy: Policy, verify: bool = True) -> None:
        super().__init__(trust_env=False)
        ssl_context = httpx.create_ssl_context(verify=verify, trust_env=False)
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=10,
            max_keepalive_connections=5,
            keepalive_expiry=5.0,
            network_backend=GuardedBackend(policy),
        )


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int | None = None
    headers: httpx.Headers = field(default_factory=httpx.Headers)
    body: bytes = b""
    elapsed_ms: int | None = None
    redirects: list[tuple[str, int]] = field(default_factory=list)
    truncated: bool = False
    error: str | None = None
    http_version: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 300

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";", 1)[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return self.content_type in {"text/html", "application/xhtml+xml"}

    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype.lower():
            charset = ctype.lower().split("charset=", 1)[1].split(";", 1)[0].strip().strip("\"'") or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


def classify_exception(exc: BaseException) -> str:
    if isinstance(exc, BlockedDestinationError | UnsafeURLError):
        return "blocked_destination"
    if isinstance(exc, DNSResolutionError):
        return "dns"
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        text = str(exc).lower()
        if "certificate" in text or "ssl" in text or "tls" in text:
            return "tls"
        if "refused" in text:
            return "connection_refused"
        return "connection_error"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, httpx.RemoteProtocolError):
        return "protocol_error"
    if isinstance(exc, httpx.HTTPError):
        return "connection_error"
    return "connection_error"


class SafeClient:
    def __init__(
        self,
        *,
        user_agent: str,
        timeout: float = 10.0,
        max_bytes: int = 5 * 1024 * 1024,
        policy: Policy | None = None,
        verify: bool = True,
    ) -> None:
        self.policy = policy or Policy()
        self.max_bytes = max_bytes
        self.timeout = timeout
        self._client = httpx.Client(
            transport=GuardedTransport(self.policy, verify=verify),
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en;q=0.9,*;q=0.5",
            },
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SafeClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        follow_redirects: bool = True,
        max_bytes: int | None = None,
        read_body: bool = True,
    ) -> FetchResult:
        limit = self.max_bytes if max_bytes is None else max_bytes
        result = FetchResult(url=url, final_url=url)
        current = url
        started = time.monotonic()
        try:
            for _ in range(MAX_REDIRECTS + 1):
                current = normalize_target(current, self.policy)
                with self._client.stream(method, current) as resp:
                    result.final_url = current
                    result.status = resp.status_code
                    result.headers = resp.headers
                    result.http_version = resp.http_version
                    if resp.is_redirect and follow_redirects:
                        location = resp.headers.get("location", "")
                        if not location:
                            break
                        result.redirects.append((current, resp.status_code))
                        current = str(resp.url.join(location))
                        continue
                    if result.elapsed_ms is None:
                        result.elapsed_ms = int((time.monotonic() - started) * 1000)
                    if read_body and method != "HEAD":
                        chunks: list[bytes] = []
                        size = 0
                        for chunk in resp.iter_bytes():
                            size += len(chunk)
                            if size > limit:
                                result.truncated = True
                                break
                            chunks.append(chunk)
                        result.body = b"".join(chunks)
                    break
            else:
                result.error = "too_many_redirects"
        except Exception as exc:  # network errors are data, not crashes
            result.error = classify_exception(exc)
        if result.elapsed_ms is None:
            result.elapsed_ms = int((time.monotonic() - started) * 1000)
        return result
