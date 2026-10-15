from qannas.config import ScopeConfig
from qannas.scope import ScopeGuard, ScopeViolation

import pytest


def guard():
    return ScopeGuard(ScopeConfig(
        authorized=["localhost", "*.example.com", "192.168.56.0/24"],
        blocked=["*.gov"],
    ))


def test_exact_host_authorized():
    assert guard().is_authorized("http://localhost:8080/app")


def test_wildcard_authorized():
    assert guard().is_authorized("https://api.example.com/v1/users")


def test_cidr_authorized():
    assert guard().is_authorized("http://192.168.56.12/")


def test_out_of_scope_rejected():
    assert not guard().is_authorized("https://victim.com/")


def test_blocked_beats_authorized():
    g = ScopeGuard(ScopeConfig(authorized=["*.gov"], blocked=["*.gov"]))
    assert not g.is_authorized("https://whitehouse.gov/")


def test_check_raises():
    with pytest.raises(ScopeViolation):
        guard().check("https://victim.com/")


def test_empty_scope_refused():
    with pytest.raises(ValueError):
        ScopeGuard(ScopeConfig(authorized=[]))
