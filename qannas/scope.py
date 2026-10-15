"""Scope enforcement — the authorization gate.

Every outbound request in Qannas must pass ScopeGuard.check(). A target that
is not explicitly authorized (or that is explicitly blocked) raises
ScopeViolation and the request never leaves the process. This is the single
chokepoint that keeps the tool on the right side of the law: unauthorized
testing is illegal in most jurisdictions.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from urllib.parse import urlparse

from .config import ScopeConfig


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized scope."""


class ScopeGuard:
    def __init__(self, cfg: ScopeConfig) -> None:
        self.authorized = [p.lower().strip() for p in cfg.authorized]
        self.blocked = [p.lower().strip() for p in cfg.blocked]
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

    def is_authorized(self, target: str) -> bool:
        host = self._host_of(target)
        if not host:
            return False
        if any(self._matches(host, p) for p in self.blocked):
            return False
        return any(self._matches(host, p) for p in self.authorized)

    def check(self, target: str) -> None:
        """Raise ScopeViolation if target is not authorized. No return value."""
        if not self.is_authorized(target):
            raise ScopeViolation(
                f"Target '{target}' is not in the authorized scope. "
                f"Add it to config `scope.authorized` only if you have written permission to test it."
            )
