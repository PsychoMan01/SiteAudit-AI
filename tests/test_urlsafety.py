"""SSRF protection: URL validation and connection-time destination checks."""

from __future__ import annotations

import ipaddress
import socket

import pytest

from siteaudit.net.client import SafeClient
from siteaudit.net.urlsafety import (
    BlockedDestinationError,
    DNSResolutionError,
    Policy,
    UnsafeURLError,
    ip_is_public,
    normalize_target,
    resolve_allowed,
)

STRICT = Policy(allow_private=False)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("  Example.COM/path?q=1#frag ", "https://example.com/path?q=1"),
        ("http://example.com", "http://example.com/"),
        ("https://example.com:443/", "https://example.com/"),
        ("http://example.com:80/a", "http://example.com/a"),
        ("https://bücher.de", "https://xn--bcher-kva.de/"),
        ("https://93.184.215.14/", "https://93.184.215.14/"),
    ],
)
def test_normalize_accepts_public_targets(raw: str, expected: str) -> None:
    assert normalize_target(raw, STRICT) == expected


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("", "empty"),
        ("ftp://example.com", "scheme"),
        ("file:///etc/passwd", "scheme"),
        ("javascript:alert(1)", "scheme"),
        ("gopher://example.com", "scheme"),
        ("https://user:pass@example.com", "credentials"),
        ("https://example.com:22", "port"),
        ("https://example.com:6379", "port"),
        ("http://localhost", "invalid_host"),
        ("http://localhost:8000", "port"),
        ("http://app.localhost", "invalid_host"),
        ("http://intranet", "invalid_host"),
        ("http://printer.local", "invalid_host"),
        ("http://metadata.google.internal", "invalid_host"),
        ("http://127.0.0.1", "private_address"),
        ("http://127.1.2.3", "private_address"),
        ("http://10.0.0.5", "private_address"),
        ("http://172.16.4.4", "private_address"),
        ("http://192.168.1.1", "private_address"),
        ("http://169.254.169.254/latest/meta-data", "private_address"),
        ("http://100.64.0.1", "private_address"),
        ("http://0.0.0.0", "private_address"),
        ("http://[::1]/", "private_address"),
        ("http://[fd00::1]/", "private_address"),
        ("http://[fe80::1]/", "private_address"),
        ("http://[::ffff:127.0.0.1]/", "private_address"),
        ("http://[::ffff:10.0.0.1]/", "private_address"),
        ("http://2130706433/", "invalid_host"),
        ("http://0x7f.0.0.1/", "invalid_host"),
        ("http://exa mple.com", "invalid"),
        ("https://example.com/\x00", "invalid"),
        ("https://" + "a" * 2050 + ".com", "too_long"),
    ],
)
def test_normalize_rejects_dangerous_targets(raw: str, code: str) -> None:
    with pytest.raises(UnsafeURLError) as exc:
        normalize_target(raw, STRICT)
    assert exc.value.code == code


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.1.1",
        "::1",
        "fc00::1",
        "::ffff:192.168.1.1",
        "2002:7f00:1::1",
        "224.0.0.1",
        "240.0.0.1",
        "198.18.0.1",
    ],
)
def test_non_public_ips(ip: str) -> None:
    assert not ip_is_public(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips(ip: str) -> None:
    assert ip_is_public(ipaddress.ip_address(ip))


def _fake_dns(monkeypatch: pytest.MonkeyPatch, answers: list[str]) -> None:
    def fake(host: str, port: int, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        out = []
        for a in answers:
            fam = socket.AF_INET6 if ":" in a else socket.AF_INET
            out.append((fam, socket.SOCK_STREAM, 6, "", (a, port)))
        return out

    monkeypatch.setattr(socket, "getaddrinfo", fake)


def test_dns_answer_with_private_address_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dns(monkeypatch, ["10.0.0.7"])
    with pytest.raises(BlockedDestinationError):
        resolve_allowed("rebind.example", 443, STRICT)


def test_mixed_dns_answer_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    # One public and one private record: the whole answer is rejected, never "pick the safe one".
    _fake_dns(monkeypatch, ["93.184.215.14", "127.0.0.1"])
    with pytest.raises(BlockedDestinationError):
        resolve_allowed("mixed.example", 443, STRICT)


def test_unresolvable_host(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_a: object, **_k: object) -> None:
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(DNSResolutionError):
        resolve_allowed("does-not-exist.example", 443, STRICT)


def test_client_blocks_hostname_resolving_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dns(monkeypatch, ["127.0.0.1"])
    with SafeClient(user_agent="test", policy=STRICT, timeout=2) as client:
        result = client.fetch("http://looks-public.example/")
    assert result.error == "blocked_destination"
    assert result.status is None


class LoopbackOnlyPolicy(Policy):
    """Lets tests reach the local test server while still forbidding every other private address."""

    def port_allowed(self, port: int) -> bool:
        return True

    def ip_allowed(self, ip):  # type: ignore[no-untyped-def]
        return str(ip) == "127.0.0.1" or ip_is_public(ip)

    def hostname_allowed(self, host: str) -> bool:
        return True


@pytest.mark.parametrize(
    "target",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://[::1]/",
        "file:///etc/passwd",
        "http://192.168.1.1:8080/admin",
    ],
)
def test_redirect_to_private_destination_is_blocked(site, target: str) -> None:  # type: ignore[no-untyped-def]
    site.add("/go", status=302, Location=target)
    with SafeClient(user_agent="test", policy=LoopbackOnlyPolicy(), timeout=2) as client:
        result = client.fetch(site.base + "/go")
    assert result.error == "blocked_destination"
    # Nothing beyond the first request reached any server.
    assert [h[1] for h in site.hits] == ["/go"]


def test_redirect_loop_is_bounded(site) -> None:  # type: ignore[no-untyped-def]
    site.add("/a", status=302, Location="/b")
    site.add("/b", status=302, Location="/a")
    with SafeClient(user_agent="test", policy=LoopbackOnlyPolicy(), timeout=2) as client:
        result = client.fetch(site.base + "/a")
    assert result.error == "too_many_redirects"
    assert len(site.hits) == 6


def test_response_size_is_capped(site) -> None:  # type: ignore[no-untyped-def]
    site.add("/big", body=b"x" * 200_000)
    with SafeClient(user_agent="test", policy=LoopbackOnlyPolicy(), timeout=2, max_bytes=50_000) as client:
        result = client.fetch(site.base + "/big")
    assert result.truncated
    assert len(result.body) <= 50_000


def test_environment_proxies_are_ignored(site, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HTTP_PROXY", "http://10.255.255.1:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://10.255.255.1:3128")
    site.add("/", body="<!doctype html><title>x</title>")
    with SafeClient(user_agent="test", policy=LoopbackOnlyPolicy(), timeout=2) as client:
        result = client.fetch(site.base + "/")
    assert result.status == 200
