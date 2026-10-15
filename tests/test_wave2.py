from qannas.chaining import find_chains
from qannas.tech import fingerprint
from qannas.blackboard import Finding


class F:
    def __init__(self, vc, status="confirmed"):
        self.vuln_class = vc
        self.status = status


def test_chaining_detects_known_chain():
    findings = [F("open_redirect"), F("ssrf", "needs_human")]
    chains = find_chains(findings)
    assert any("internal pivot" in c.title for c in chains)


def test_chaining_requires_all_components():
    assert find_chains([F("open_redirect")]) == []


def test_fingerprint_headers_and_body():
    tech = fingerprint({"server": "nginx", "x-powered-by": "Express"},
                       '<app ng-version="17.0.0"></app>')
    joined = " ".join(tech).lower()
    assert "nginx" in joined and "express" in joined and "angular" in joined


def test_fingerprint_empty():
    assert fingerprint({}, "") == []
