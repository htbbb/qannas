"""DOM XSS agent — browser-based, execution-confirmed.

Uses the headless browser to inject marker payloads and detect actual script
execution in the DOM (not reflection). Only runs when a browser is attached to
the context; otherwise it is a no-op and the run proceeds without it.
"""
from __future__ import annotations

from .base import AgentContext
from ..blackboard import Finding


class DomXssAgent:
    def __init__(self, ctx: AgentContext) -> None:
        self.ctx = ctx

    def run(self, vuln_class: str = "dom_xss") -> None:
        bb = self.ctx.bb
        br = self.ctx.browser
        if br is None:
            for ep in bb.untested(vuln_class):
                bb.mark_tested(ep.url, ep.method, vuln_class)
            return
        pb = self.ctx.kb.get(vuln_class) if self.ctx.kb else None
        payloads = pb.payloads if pb else []
        hints = pb.param_hints if pb else []

        for ep in bb.untested(vuln_class):
            params = ep.params or [h for h in hints][:1] or ["q"]
            try:
                for param in params:
                    hit, evidence, poc = br.probe_dom_xss(ep.url, param, payloads)
                    if hit:
                        bb.add_finding(Finding(
                            vuln_class="dom_xss", endpoint=ep.url,
                            severity=pb.severity if pb else "high", status="candidate",
                            detail=f"DOM XSS via '{param}'", evidence=evidence, poc=poc))
                        break
            except Exception as e:
                bb.note(f"dom_xss on {ep.url}: {e}")
            finally:
                bb.mark_tested(ep.url, ep.method, vuln_class)
