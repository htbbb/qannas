"""Orchestrator — the main loop that drives planner + agents over the blackboard."""
from __future__ import annotations

import time
from pathlib import Path

from rich.console import Console

from .agents.ai_exploit import AIExploitAgent
from .agents.base import AgentContext
from .agents.recon import ReconAgent
from .agents.validator import ValidatorAgent
from .blackboard import Blackboard, Phase
from .config import Config
from .kb import KnowledgeBase
from .llm import LLM
from .planner import Planner
from .report import write_reports
from .scope import ScopeGuard
from .tools.http import HttpTool

console = Console()


class Orchestrator:
    def __init__(self, cfg: Config, targets: list[str], run_name: str | None = None,
                 seed_endpoints: list[dict] | None = None) -> None:
        self.cfg = cfg
        self.guard = ScopeGuard(cfg.scope)
        # Fail closed: refuse the whole run if any target is out of scope.
        for t in targets:
            self.guard.check(t)

        run_name = run_name or time.strftime("run-%Y%m%d-%H%M%S")
        run_dir = Path(cfg.engine.runs_dir) / run_name
        self.bb = Blackboard(run_dir)
        self.bb.targets = list(targets)

        # Seed endpoints from an API spec / list. Each is scope-checked before
        # it ever enters the blackboard — nothing out of scope gets tested.
        for e in (seed_endpoints or []):
            try:
                self.guard.check(e["url"])
            except Exception:
                self.bb.note(f"seed skipped (out of scope): {e['url']}")
                continue
            self.bb.add_endpoint(e["url"], e.get("method", "GET"), e.get("params", []))
        if seed_endpoints:
            self.bb.note(f"seeded {len(self.bb.endpoints)} endpoints from spec/list")

        http = HttpTool(self.guard, cfg.engine.request_timeout, cfg.engine.rate_limit_per_sec)
        llm = LLM(cfg.llm)
        self.kb = KnowledgeBase()
        # If config lists no classes, test everything the knowledge base knows.
        classes = cfg.vuln_classes or self.kb.classes()
        self.ctx = AgentContext(cfg=cfg, bb=self.bb, llm=llm, http=http, kb=self.kb)
        self.planner = Planner(classes, cfg.engine.max_iterations)
        self.recon = ReconAgent(self.ctx)
        self.exploit = AIExploitAgent(self.ctx)
        self.validator = ValidatorAgent(self.ctx)

    def run(self) -> dict:
        console.print(f"[bold cyan]Qannas[/] starting on {', '.join(self.bb.targets)}")
        console.print(f"[dim]run dir: {self.bb.run_dir}[/]")
        while True:
            action = self.planner.next_action(self.bb)
            if action.kind == "recon":
                self.recon.run()
            elif action.kind == "exploit":
                console.print(f"[yellow]exploit[/] · {action.detail}")
                self.exploit.run(action.detail)
            elif action.kind == "validate":
                console.print("[magenta]validate[/] · reproducing candidates")
                self.validator.run()
            elif action.kind == "report":
                break
        self.bb.phase = Phase.REPORT
        paths = write_reports(self.bb)

        # Persist confirmed findings to the cross-run memory so the next scan
        # of this target knows its history.
        primary = self.bb.targets[0] if self.bb.targets else ""
        for f in self.bb.findings:
            if f.status in ("confirmed", "needs_human"):
                self.kb.record_finding(primary, f.endpoint, f.vuln_class,
                                       f.severity, f.status, f.evidence)
        self.bb.phase = Phase.DONE

        snap = self.bb.snapshot()
        console.print(f"[bold green]done[/] · {snap['confirmed']} confirmed / "
                      f"{snap['findings']} total across {snap['endpoints']} endpoints")
        console.print(f"[dim]report: {paths['markdown']}[/]")
        self.ctx.http.close()
        self.kb.close()
        return {"snapshot": snap, "reports": {k: str(v) for k, v in paths.items()}}
