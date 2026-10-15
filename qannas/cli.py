"""Qannas CLI."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from .agents.base import AgentContext
from .blackboard import Blackboard
from .config import Config
from .ctf import CTFSolver
from .llm import LLM
from .orchestrator import Orchestrator
from .scope import ScopeGuard
from .tools.http import HttpTool

console = Console()

BANNER = r"""
  ___
 / _ \ __ _ _ __  _ __   __ _ ___   qannas — authorized pentest + CTF
| | | / _` | '_ \| '_ \ / _` / __|  planner-driven · validator-gated
| |_| | (_| | | | | | | | (_| \__ \
 \__\_\\__,_|_| |_|_| |_|\__,_|___/
"""


def _load_cfg(path: str | None) -> Config:
    if path:
        return Config.load(path)
    if Path("config.yaml").exists():
        return Config.load("config.yaml")
    console.print("[yellow]No config.yaml found — using localhost-only default scope.[/]")
    return Config.default()


def cmd_scan(args) -> int:
    cfg = _load_cfg(args.config)
    targets = list(args.target)
    if args.target_list:
        for line in Path(args.target_list).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    seed: list[dict] = []
    if args.openapi or args.endpoints:
        from .tools.apispec import load
        base = targets[0] if targets else None
        spec_file = args.openapi or args.endpoints
        seed = load(spec_file, base_url=base)
        console.print(f"[cyan]ingested {len(seed)} endpoints from {spec_file}[/]")
        # Make sure the spec's hosts are represented as targets for reporting.
        for e in seed:
            host = urlparse(e["url"]).hostname
            if host and not any(urlparse(t).hostname == host for t in targets):
                targets.append(f"{urlparse(e['url']).scheme}://{urlparse(e['url']).netloc}")
    if not targets and not seed:
        console.print("[red]No targets given.[/]")
        return 2
    orch = Orchestrator(cfg, targets, run_name=args.name, seed_endpoints=seed,
                        use_browser=args.browser)
    result = orch.run()
    return 1 if result["snapshot"]["confirmed"] else 0


def cmd_ctf(args) -> int:
    cfg = _load_cfg(args.config)
    guard = ScopeGuard(cfg.scope)
    guard.check(args.target)
    run_dir = Path(cfg.engine.runs_dir) / (args.name or time.strftime("ctf-%Y%m%d-%H%M%S"))
    bb = Blackboard(run_dir)
    bb.targets = [args.target]
    ctx = AgentContext(cfg=cfg, bb=bb,
                       llm=LLM(cfg.llm),
                       http=HttpTool(guard, cfg.engine.request_timeout, cfg.engine.rate_limit_per_sec))
    solver = CTFSolver(ctx, max_steps=args.max_steps)
    res = solver.solve(args.target, args.brief or "Find and submit the flag.")
    ctx.http.close()
    if res.get("solved"):
        console.print(f"[bold green]FLAG:[/] {res['flag']}  [dim](in {res['steps']} steps)[/]")
        return 0
    console.print(f"[yellow]No flag captured in {res['steps']} steps.[/]")
    return 1


def cmd_view(args) -> int:
    from .viewer import serve
    cfg = _load_cfg(args.config)
    runs_dir = Path(cfg.engine.runs_dir)
    if not runs_dir.exists():
        console.print(f"[yellow]No runs directory at {runs_dir} — run a scan first.[/]")
        return 1
    serve(runs_dir, host=args.host, port=args.port, open_browser=not args.no_open)
    return 0


def cmd_scope(args) -> int:
    cfg = _load_cfg(args.config)
    guard = ScopeGuard(cfg.scope)
    ok = guard.is_authorized(args.target)
    console.print(f"{args.target}: " + ("[green]AUTHORIZED[/]" if ok else "[red]OUT OF SCOPE[/]"))
    return 0 if ok else 1


def main(argv=None) -> int:
    console.print(f"[cyan]{BANNER}[/]")
    p = argparse.ArgumentParser(prog="qannas")
    p.add_argument("-c", "--config", help="path to config.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run the pentest pipeline against authorized targets")
    s.add_argument("-t", "--target", action="append", default=[], help="target URL (repeatable)")
    s.add_argument("--target-list", help="file with one target per line")
    s.add_argument("--openapi", help="OpenAPI/Swagger file: test every declared endpoint")
    s.add_argument("--endpoints", help="plain text file, one 'METHOD url' per line")
    s.add_argument("--browser", action="store_true",
                   help="render SPAs with headless Chromium + test DOM XSS (needs playwright)")
    s.add_argument("--name", help="run name")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("ctf", help="solve a CTF challenge")
    c.add_argument("-t", "--target", required=True, help="challenge URL")
    c.add_argument("--brief", help="short description of the challenge")
    c.add_argument("--max-steps", type=int, default=25)
    c.add_argument("--name", help="run name")
    c.set_defaults(func=cmd_ctf)

    v = sub.add_parser("view", help="open the local web dashboard for scan results")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8787)
    v.add_argument("--no-open", action="store_true", help="don't auto-open a browser")
    v.set_defaults(func=cmd_view)

    sc = sub.add_parser("scope", help="check whether a target is in scope")
    sc.add_argument("-t", "--target", required=True)
    sc.set_defaults(func=cmd_scope)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except Exception as e:  # ScopeViolation and friends surface cleanly here
        console.print(f"[red]error:[/] {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
