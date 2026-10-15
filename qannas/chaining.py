"""Vulnerability chaining.

A lone agent is bad at recognising that finding A enables finding B. This
rule engine inspects the confirmed + needs-review findings and surfaces
attack chains — the thing that turns two medium issues into one critical
account-takeover path. Rules are intentionally explicit and auditable.

Each rule: a set of required vuln classes (any-endpoint), a resulting chain
title, severity, and narrative.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Chain:
    title: str
    severity: str
    narrative: str
    components: list[str]


# (required_classes, title, severity, narrative)
_RULES = [
    ({"reflected_xss", "csrf"}, "XSS + CSRF → session-riding account actions", "high",
     "Reflected XSS can forge the anti-CSRF token or fire state-changing requests in the victim's session."),
    ({"dom_xss", "authentication_jwt"}, "Client XSS + JWT in storage → token theft", "critical",
     "DOM XSS can read a JWT kept in localStorage/sessionStorage and exfiltrate it for full account takeover."),
    ({"idor", "authentication_jwt"}, "IDOR + weak JWT → cross-account takeover", "critical",
     "A forgeable/weak JWT plus object-reference access lets an attacker act as any user."),
    ({"idor", "mass_assignment"}, "IDOR + mass assignment → privilege escalation", "high",
     "Writing another user's object and binding a role/isAdmin field escalates privileges."),
    ({"open_redirect", "ssrf"}, "Open redirect + SSRF → internal pivot", "high",
     "An open redirect can bounce an SSRF-controlled fetch toward internal services."),
    ({"open_redirect", "authentication_jwt"}, "Open redirect → OAuth/token leak", "high",
     "Open redirect on an auth flow can leak tokens/codes to an attacker-controlled host."),
    ({"information_disclosure", "sql_injection"}, "Leaked config + SQLi → data breach", "critical",
     "Exposed credentials/connection strings combined with SQLi widen access to the datastore."),
    ({"sql_injection", "authentication_jwt"}, "SQLi + JWT secret exposure → forge any token", "critical",
     "SQLi that reads the signing secret lets an attacker mint valid tokens for any account."),
    ({"ssrf", "information_disclosure"}, "SSRF + metadata/secret exposure → cloud creds", "critical",
     "SSRF to a metadata endpoint or exposed secret store can yield cloud credentials."),
]


def find_chains(findings) -> list[Chain]:
    present = {f.vuln_class for f in findings if f.status in ("confirmed", "needs_human")}
    chains: list[Chain] = []
    for req, title, sev, narr in _RULES:
        if req.issubset(present):
            chains.append(Chain(title=title, severity=sev, narrative=narr,
                                components=sorted(req)))
    return chains
