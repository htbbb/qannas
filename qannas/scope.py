"""Scope enforcement — the authorization gate.

Every outbound request in Qannas must pass ScopeGuard.check(). A target that
is not explicitly authorized (or that is explicitly blocked) raises
ScopeViolation and the request never leaves the process. This is the single
chokepoint that keeps the tool on the right side of the law: unauthorized
testing is illegal in most jurisdictions.

Matching a hostname pattern is not enough on its own. A name you are allowed
to test (say ``*.example.com``) can still point at an address you are *not*
allowed to touch — a loopback, a RFC1918 LAN host, a cloud metadata endpoint —
whether by accident or by a DNS-rebinding trick. So, unless disabled, the guard
resolves every hostname and refuses any target that lands on an internal /
private / loopback / reserved address, except when that exact address or a CIDR
covering it is itself listed in ``scope.authorized``. Set ``resolve_dns: false``
to skip resolution for offline runs (e.g. the mock pipeline with no network).
"""
from __future__ import annotations

import fnmatch
import ipaddress
import socket
from urllib.parse import urlparse

from .config import ScopeConfig

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _lookup(host: str) -> list[str]:
    """Resolve a hostname to a list of IP strings.

    Isolated in a module-level function so tests can substitute it without
    touching the network.
    """
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized scope."""


class ScopeGuard:
    def __init__(self, cfg: ScopeConfig) -> None:
        self.authorized = [p.lower().strip() for p in cfg.authorized]
        self.blocked = [p.lower().strip() for p in cfg.blocked]
        self.resolve_dns = cfg.resolve_dns
        if not self.authorized:
            raise ValueError(
                "Refusing to run with an empty authorized scope. "
                "List the hosts you have written permission to test in config `scope.authorized`."
            )

    @staticmethod
    def _host_of(target: str) -> str:
        if "://" not in target:
            target = "http://" + target
        host = urlparse(target).hostname or ""
        return host.lower()

    @staticmethod
    def _matches(host: str, pattern: str) -> bool:
        # CIDR match
        if "/" in pattern:
            try:
                net = ipaddress.ip_network(pattern, strict=False)
                return ipaddress.ip_address(host) in net
            except ValueError:
                return False
        # wildcard / exact hostname match
        return fnmatch.fnmatch(host, pattern)

    @staticmethod
    def _as_network(pattern: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        """Return the network for a literal IP or CIDR pattern, else None.

        Hostname / wildcard patterns return None: they never count as explicit
        authorization of an IP address.
        """
        try:
            return ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return None

    @staticmethod
    def _is_internal(ip: IPAddress) -> bool:
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    def _explicitly_allows_ip(self, ip: IPAddress) -> bool:
        for pattern in self.authorized:
            net = self._as_network(pattern)
            if net is not None and ip.version == net.version and ip in net:
                return True
        return False

    def _resolve(self, host: str) -> tuple[list[IPAddress], str | None]:
        """Resolve ``host`` to IP addresses.

        Returns ``(ips, error)``. A literal IP resolves to itself. When DNS is
        disabled a hostname resolves to an empty list and the IP guard is
        skipped. A resolution failure returns an error string so the caller can
        fail closed.
        """
        try:
            return [ipaddress.ip_address(host)], None
        except ValueError:
            pass  # not a literal IP — needs DNS
        if not self.resolve_dns:
            return [], None
        try:
            raw = _lookup(host)
        except OSError:
            return [], f"could not resolve host '{host}'"
        ips: list[IPAddress] = []
        for addr in raw:
            addr = addr.split("%")[0]  # drop any IPv6 zone id
            try:
                ips.append(ipaddress.ip_address(addr))
            except ValueError:
                continue
        if not ips:
            return [], f"could not resolve host '{host}'"
        return ips, None

    def _denial_reason(self, target: str) -> str | None:
        """Return why ``target`` is out of scope, or None if it is allowed."""
        host = self._host_of(target)
        if not host:
            return f"could not parse a host from target '{target}'"
        if any(self._matches(host, p) for p in self.blocked):
            return f"target '{target}' matches a blocked scope entry."
        if not any(self._matches(host, p) for p in self.authorized):
            return (
                f"target '{target}' is not in the authorized scope. "
                f"Add it to config `scope.authorized` only if you have written permission to test it."
            )
        ips, error = self._resolve(host)
        if error:
            return (
                f"{error}; refusing to send traffic to a target that cannot be verified. "
                f"Set `scope.resolve_dns: false` to skip DNS resolution for offline runs."
            )
        for ip in ips:
            if self._is_internal(ip) and not self._explicitly_allows_ip(ip):
                return (
                    f"target '{target}' resolves to internal address {ip}, which is not "
                    f"explicitly authorized. Add that IP or a covering CIDR to "
                    f"`scope.authorized` only if you have permission to test it."
                )
        return None

    def is_authorized(self, target: str) -> bool:
        return self._denial_reason(target) is None

    def check(self, target: str) -> None:
        """Raise ScopeViolation if target is not authorized. No return value."""
        reason = self._denial_reason(target)
        if reason is not None:
            raise ScopeViolation(reason)
