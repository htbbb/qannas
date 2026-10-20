from qannas.config import ScopeConfig
from qannas.scope import ScopeGuard, ScopeViolation
import qannas.scope as scope_mod

import socket

import pytest


# ---------------------------------------------------------------------------
# Pattern-matching tests (hermetic: resolve_dns=False so no network is touched;
# the internal-IP guard has its own tests below).
# ---------------------------------------------------------------------------
def guard():
    return ScopeGuard(ScopeConfig(
        authorized=["localhost", "*.example.com", "192.168.56.0/24"],
        blocked=["*.gov"],
        resolve_dns=False,
    ))


def test_exact_host_authorized():
    assert guard().is_authorized("http://localhost:8080/app")


def test_wildcard_authorized():
    assert guard().is_authorized("https://api.example.com/v1/users")


def test_cidr_authorized():
    # Private IP literal, but explicitly authorized via the lab CIDR.
    assert guard().is_authorized("http://192.168.56.12/")


def test_out_of_scope_rejected():
    assert not guard().is_authorized("https://victim.com/")


def test_blocked_beats_authorized():
    g = ScopeGuard(ScopeConfig(authorized=["*.gov"], blocked=["*.gov"], resolve_dns=False))
    assert not g.is_authorized("https://whitehouse.gov/")


def test_check_raises():
    with pytest.raises(ScopeViolation):
        guard().check("https://victim.com/")


def test_empty_scope_refused():
    with pytest.raises(ValueError):
        ScopeGuard(ScopeConfig(authorized=[]))


# ---------------------------------------------------------------------------
# DNS resolution + internal-address guard.
# ---------------------------------------------------------------------------
def _fake_lookup(mapping):
    def _inner(host):
        if host in mapping:
            return list(mapping[host])
        raise socket.gaierror(f"no fake record for {host}")
    return _inner


def dns_guard(authorized, blocked=None):
    return ScopeGuard(ScopeConfig(
        authorized=authorized,
        blocked=blocked or [],
        resolve_dns=True,
    ))


def test_hostname_resolving_to_public_is_allowed(monkeypatch):
    monkeypatch.setattr(scope_mod, "_lookup", _fake_lookup({"app.example.com": ["93.184.216.34"]}))
    g = dns_guard(["*.example.com"])
    assert g.is_authorized("https://app.example.com/")


def test_hostname_resolving_to_private_is_rejected(monkeypatch):
    # DNS-rebinding / SSRF shape: an in-scope name points at a LAN address.
    monkeypatch.setattr(scope_mod, "_lookup", _fake_lookup({"app.example.com": ["10.0.0.5"]}))
    g = dns_guard(["*.example.com"])
    assert not g.is_authorized("https://app.example.com/")
    with pytest.raises(ScopeViolation, match="internal address"):
        g.check("https://app.example.com/")


def test_hostname_resolving_to_loopback_is_rejected(monkeypatch):
    monkeypatch.setattr(scope_mod, "_lookup", _fake_lookup({"app.example.com": ["127.0.0.1"]}))
    g = dns_guard(["*.example.com"])
    assert not g.is_authorized("https://app.example.com/")


def test_private_resolution_allowed_when_cidr_listed(monkeypatch):
    monkeypatch.setattr(scope_mod, "_lookup", _fake_lookup({"lab.example.com": ["10.0.0.5"]}))
    g = dns_guard(["*.example.com", "10.0.0.0/8"])
    assert g.is_authorized("https://lab.example.com/")


def test_localhost_allowed_via_explicit_ip(monkeypatch):
    # The shipped default config authorizes both "localhost" and "127.0.0.1";
    # the loopback result is allowed because 127.0.0.1 is listed explicitly.
    monkeypatch.setattr(scope_mod, "_lookup", _fake_lookup({"localhost": ["127.0.0.1"]}))
    g = dns_guard(["localhost", "127.0.0.1"])
    assert g.is_authorized("http://localhost:8080/")


def test_loopback_literal_allowed_when_listed():
    g = dns_guard(["127.0.0.1"])
    assert g.is_authorized("http://127.0.0.1:8080/")  # IP literal, no DNS needed


def test_mixed_results_rejected_if_any_internal(monkeypatch):
    monkeypatch.setattr(scope_mod, "_lookup",
                        _fake_lookup({"app.example.com": ["93.184.216.34", "169.254.169.254"]}))
    g = dns_guard(["*.example.com"])
    assert not g.is_authorized("https://app.example.com/")


def test_resolution_failure_fails_closed(monkeypatch):
    monkeypatch.setattr(scope_mod, "_lookup", _fake_lookup({}))  # every lookup raises
    g = dns_guard(["*.example.com"])
    assert not g.is_authorized("https://app.example.com/")
    with pytest.raises(ScopeViolation, match="could not resolve"):
        g.check("https://app.example.com/")


def test_offline_mode_skips_resolution(monkeypatch):
    # resolve_dns=False must not call the resolver at all.
    def _boom(host):
        raise AssertionError("resolver must not be called when resolve_dns is False")
    monkeypatch.setattr(scope_mod, "_lookup", _boom)
    g = ScopeGuard(ScopeConfig(authorized=["*.example.com"], resolve_dns=False))
    assert g.is_authorized("https://app.example.com/")


def test_metadata_endpoint_literal_out_of_scope():
    # 169.254.169.254 is link-local; not matched by a hostname pattern anyway.
    g = dns_guard(["*.example.com"])
    assert not g.is_authorized("http://169.254.169.254/latest/meta-data/")


def test_resolve_dns_defaults_true():
    assert ScopeConfig(authorized=["x"]).resolve_dns is True


# ---------------------------------------------------------------------------
# Explicit coverage for the early-return denial paths in _denial_reason.
# ---------------------------------------------------------------------------
def test_target_without_host_is_rejected():
    g = dns_guard(["*.example.com"])
    # No parseable host (empty authority) -> denied, never resolved.
    assert not g.is_authorized("http:///nohost")
    with pytest.raises(ScopeViolation, match="could not parse a host"):
        g.check("http:///nohost")


def test_blocked_entry_is_rejected():
    g = dns_guard(["*.example.com"], blocked=["evil.example.com"])
    # In-scope by wildcard, but the blocklist wins before any resolution.
    assert not g.is_authorized("https://evil.example.com/")
    with pytest.raises(ScopeViolation, match="blocked"):
        g.check("https://evil.example.com/")


def test_private_resolution_goes_through_denial_reason(monkeypatch):
    # Regression guard: _denial_reason must flow past the authorized check into
    # the IP inspection and return a *string reason*, never a bool or None.
    monkeypatch.setattr(scope_mod, "_lookup", _fake_lookup({"app.example.com": ["10.0.0.5"]}))
    g = dns_guard(["*.example.com"])
    reason = g._denial_reason("https://app.example.com/")
    assert isinstance(reason, str)
    assert "internal address" in reason
    assert reason not in (None, True, False)
