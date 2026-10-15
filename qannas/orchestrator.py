"""Orchestrator — the main loop that drives planner + agents over the blackboard."""
from __future__ import annotations

import time
from pathlib import Path

from rich.console import Console

from .agents.ai_exploit import AIExploitAgent
from .agents.base import AgentContext
from .agents.dom_xss import DomXssAgent
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
                 seed_endpoints: list[dict] | None = None, use_browser: bool = False) -> None:
        self.cfg = cfg
        self.use_browser = use_browser
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
        # dom_xss needs a browser; drop it unless browser mode is on.
        if not use_browser:
            classes = [c for c in classes if c != "dom_xss"]
        self.ctx = AgentContext(cfg=cfg, bb=self.bb, llm=llm, http=http, kb=self.kb)
        self.planner = Planner(classes, cfg.engine.max_iterations)
        self.recon = ReconAgent(self.ctx)
        self.exploit = AIExploitAgent(self.ctx)
        self.dom_xss = DomXssAgent(self.ctx)
        self.validator = ValidatorAgent(self.ctx)

    def run(self) -> dict:
        from .tools import browser as browsermod
        if self.use_browser and browsermod.available():
            with browsermod.Browser(self.guard) as br:
                self.ctx.browser = br
                console.print("[cyan]browser mode on[/] · headless Chromium, scope-gated")
                return self._run_loop()
        if self.use_browser:
            console.print("[yellow]browser mode requested but Playwright/Chromium missing — "
                          "falling back to HTTP crawler. Install: pip install playwright && playwright install chromium[/]")
        return self._run_loop()

    def _run_loop(self) -> dict:
        import time as _t
        console.print(f"[bold cyan]Qannas[/] starting on {', '.join(self.bb.targets)}")
        console.print(f"[dim]run dir: {self.bb.run_dir}[/]")
        start = _t.time()
        budget = self.cfg.engine
        while True:
            # Budget policy: stop gracefully on request or time cap.
            if self.ctx.http.request_count >= budget.max_total_requests:
                self.bb.note(f"budget: request cap ({budget.max_total_requests}) reached")
                console.print("[yellow]budget[/] · request cap reached, finalizing")
                break
            if _t.time() - start >= budget.max_seconds:
                self.bb.note(f"budget: time cap ({budget.max_seconds}s) reached")
                console.print("[yellow]budget[/] · time cap reached, finalizing")
                break
            action = self.planner.next_action(self.bb)
            if action.kind == "recon":
                self.recon.run()
                self._fingerprint()
            elif action.kind == "exploit":
                console.print(f"[yellow]exploit[/] · {action.detail}")
                if action.detail == "dom_xss":
                    self.dom_xss.run(action.detail)
                else:
                    self.exploit.run(action.detail)
            elif action.kind == "validate":
                console.print("[magenta]validate[/] · reproducing candidates")
                self.validator.run()
            elif action.kind == "report":
                break
        self.bb.phase = Phase.REPORT

        # Chaining, reports, transaction log, fixes, PDF.
        from .chaining import find_chains
        from .fixes import write_fixes
        from . import report_pdf
        chains = find_chains(self.bb.findings)
        paths = write_reports(self.bb, self.kb, chains)
        self._write_transactions()
        write_fixes(self.bb.run_dir, self.bb.findings, self.kb, self.ctx.llm)
        try:
            report_pdf.write_pdf(self.bb.run_dir, self.bb, self.kb, chains)
        except Exception as e:
            self.bb.note(f"pdf skipped: {e}")

        # Persist confirmed findings to the cross-run memory so the next scan
        # of this target knows its history.
        primary = self.bb.targets[0] if self.bb.targets else ""
        for f in self.bb.findings:
            if f.status in ("confirmed", "needs_human"):
                self.kb.record_finding(primary, f.endpoint, f.vuln_class,
                                       f.severity, f.status, f.evidence)
        self.bb.phase = Phase.DONE

        snap = self.bb.snapshot()
        self._print_summary()
        if chains:
            console.print(f"[bold red]attack chains:[/] {len(chains)} — see report")
        if self.bb.technologies:
            console.print(f"[dim]tech:[/] {', '.join(self.bb.technologies[:6])}")
        console.print(f"[dim]reports: report.md · findings.csv · report.sarif.json · "
                      f"report.pdf · fixes.md[/]")
        console.print(f"[dim]view dashboard:[/] [cyan]qannas view {self.bb.run_dir.name}[/]")
        self.ctx.http.close()
        self.kb.close()
        return {"snapshot": snap, "reports": {k: str(v) for k, v in paths.items()},
                "chains": len(chains)}

    def _fingerprint(self) -> None:
        if self.bb.technologies or not self.bb.targets:
            return
        try:
            from .tech import fingerprint
            r = self.ctx.http.get(self.bb.targets[0])
            self.bb.technologies = fingerprint(r.headers, r.text)
            if self.bb.technologies:
                self.bb.note("tech: " + ", ".join(self.bb.technologies))
        except Exception:
            pass

    def _write_transactions(self) -> None:
        import json as _j
        try:
            with (self.bb.run_dir / "transactions.jsonl").open("w") as fh:
                for tx in self.ctx.http.transactions:
                    fh.write(_j.dumps(tx) + "\n")
        except Exception:
            pass

    def _print_summary(self) -> None:
        from rich.table import Table
        from rich.panel import Panel

        sev_color = {"critical": "bold red", "high": "red", "medium": "yellow",
                     "low": "cyan", "info": "dim"}
        confirmed = [f for f in self.bb.findings if f.status == "confirmed"]
        needs = [f for f in self.bb.findings if f.status == "needs_human"]
        rejected = [f for f in self.bb.findings if f.status == "rejected"]

        if confirmed or needs:
            t = Table(title="Findings", title_style="bold", show_lines=False, expand=False)
            t.add_column("SEV"); t.add_column("Class"); t.add_column("Endpoint", overflow="fold")
            t.add_column("Status")
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            for f in sorted(confirmed + needs, key=lambda x: order.get(x.severity, 9)):
                c = sev_color.get(f.severity, "white")
                st = "[green]confirmed[/]" if f.status == "confirmed" else "[yellow]needs review[/]"
                t.add_row(f"[{c}]{f.severity.upper()}[/]", f.vuln_class, f.endpoint, st)
            console.print(t)

        rate = (len(confirmed) / (len(confirmed) + len(rejected)) * 100) if (confirmed or rejected) else 100.0
        console.print(Panel.fit(
            f"[bold green]{len(confirmed)}[/] confirmed   "
            f"[yellow]{len(needs)}[/] needs review   "
            f"[dim]{len(rejected)} false positives filtered[/]\n"
            f"endpoints: {len(self.bb.endpoints)}   "
            f"validated-vulnerability-rate: [bold]{rate:.0f}%[/]",
            title="Qannas summary", border_style="green"))
