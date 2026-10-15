"""Validator agent — the false-positive killer.

This is intentionally a *different* agent from the one that found the issue,
with a clean context. Its only job: independently reproduce the deterministic
evidence. A candidate is promoted to `confirmed` only when the proof replays;
otherwise it is `rejected`. Heuristic-only classes (idor, ssrf) are never
auto-confirmed — they are marked `needs_human`, because confirming them
requires business/auth context a scanner cannot safely assume.

XBOW's reported accuracy comes largely from exactly this: the system that
surfaces a vulnerability is never the one that confirms it.
"""
from __future__ import annotations

from .base import AgentContext
from .exploit import SQL_ERRORS, _with_param

HEURISTIC_CLASSES = {"idor", "ssrf"}


class ValidatorAgent:
    def __init__(self, ctx: AgentContext) -> None:
        self.ctx = ctx

    def run(self) -> None:
        bb = self.ctx.bb
        for f in bb.candidates():
            try:
                verdict, evidence = self._verify(f)
            except Exception as e:
                verdict, evidence = "rejected", f"validation error: {e}"
            bb.update_finding(f.id, status=verdict, evidence=evidence or f.evidence)
            bb.note(f"validate {f.vuln_class}@{f.endpoint}: {verdict}")

    def _verify(self, f):
        if f.vuln_class in HEURISTIC_CLASSES:
            return "needs_human", f.evidence + " (manual auth-context check required)"

        if f.vuln_class == "security_headers":
            r = self.ctx.http.get(f.endpoint)
            still = [h for h in ("content-security-policy", "x-frame-options",
                                 "strict-transport-security", "x-content-type-options")
                     if h not in r.headers]
            return ("confirmed", f"reconfirmed missing: {still}") if still else ("rejected", "headers now present")

        if f.vuln_class == "reflected_xss":
            marker = "qnx7391"
            url = f.poc.replace("GET ", "") if f.poc else _with_param(f.endpoint, "q", f"<{marker}>")
            r = self.ctx.http.get(url)
            return ("confirmed", f"marker reflected unencoded on replay") if f"<{marker}>" in r.text \
                else ("rejected", "marker not reflected on replay")

        if f.vuln_class == "sql_injection":
            param = "id"
            url = f.poc.replace("GET ", "") if f.poc else _with_param(f.endpoint, param, "'")
            r = self.ctx.http.get(url)
            body = r.text.lower()
            hit = next((s for s in SQL_ERRORS if s in body), None)
            return ("confirmed", f"db error replayed: '{hit}'") if hit else ("rejected", "no error on replay")

        if f.vuln_class == "open_redirect":
            url = f.poc.replace("GET ", "") if f.poc else f.endpoint
            r = self.ctx.http.get(url)
            loc = r.headers.get("location", "")
            return ("confirmed", f"redirect replayed: {loc}") if "qannas.invalid" in loc \
                else ("rejected", "redirect not reproduced")

        return "rejected", "no validator for this class"
