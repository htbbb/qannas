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
                endpoints = self.recon.crawl(target, max_pages=20)
            except Exception as e:  # scope violations included — recorded, not fatal
                bb.note(f"recon failed for {target}: {e}")
                continue
            for e in endpoints:
                bb.add_endpoint(e["url"], e["method"], e["params"])
            bb.note(f"recon: {target} -> {len(endpoints)} endpoints")
