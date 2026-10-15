"""Recon agent — maps the attack surface into the blackboard."""
from __future__ import annotations

from .base import AgentContext
from ..tools.recon import ReconTool


class ReconAgent:
    def __init__(self, ctx: AgentContext) -> None:
        self.ctx = ctx
        self.recon = ReconTool(ctx.http)

    def run(self) -> None:
        bb = self.ctx.bb
        for target in bb.targets:
            try:
                if self.ctx.browser is not None:
                    # Browser recon renders the SPA and captures XHR/fetch API calls.
                    endpoints = self.ctx.browser.crawl(target, max_pages=15)
                    bb.note(f"browser recon: {target} -> {len(endpoints)} endpoints")
                else:
                    endpoints = self.recon.crawl(target, max_pages=20)
            except Exception as e:  # scope violations included — recorded, not fatal
                bb.note(f"recon failed for {target}: {e}")
                continue
            for e in endpoints:
                bb.add_endpoint(e["url"], e["method"], e["params"])
            bb.note(f"recon: {target} -> {len(endpoints)} endpoints")
