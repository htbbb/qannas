"""End-to-end orchestrator loop against a loopback HTTP server.

This exercises the real main loop (recon -> exploit <-> validate -> report ->
done) with the offline mock model and no external network: the only host
touched is a throwaway server bound to 127.0.0.1, which is the authorized
scope. The KB is redirected to a temp HOME so the run never touches
~/.qannas.
"""
from __future__ import annotations

import pathlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from qannas.config import Config, EngineConfig, LLMConfig, ScopeConfig
from qannas.orchestrator import Orchestrator

PAGE = (b"<html><body><a href='/profile?id=1'>p</a>"
        b"<form action='/search' method='get'><input name='q'></form>"
        b"</body></html>")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):            # keep test output quiet
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(PAGE)


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_full_run_completes_and_writes_reports(server, tmp_path, monkeypatch):
    # Redirect ~/.qannas (the KB) into the temp dir.
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)

    runs_dir = tmp_path / "runs"
    cfg = Config(
        llm=LLMConfig(model="mock"),
        scope=ScopeConfig(authorized=["127.0.0.1"]),   # literal IP, explicitly allowed
        engine=EngineConfig(runs_dir=str(runs_dir), rate_limit_per_sec=1000.0,
                            max_iterations=40),
        vuln_classes=["security_headers", "reflected_xss"],
    )

    orch = Orchestrator(cfg, [server], run_name="itest", use_browser=False)
    result = orch.run()

    # main loop reached the terminal phase
    snap = result["snapshot"]
    assert set(snap) >= {"phase", "endpoints", "findings", "confirmed"}
    assert snap["phase"] == "done"
    assert snap["endpoints"] >= 1

    # all report artifacts landed in the run dir
    run_dir = runs_dir / "itest"
    for name in ("report.json", "report.md", "findings.csv",
                 "report.sarif.json", "state.json"):
        assert (run_dir / name).exists(), f"missing {name}"


def test_out_of_scope_target_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path)
    cfg = Config(
        llm=LLMConfig(model="mock"),
        scope=ScopeConfig(authorized=["127.0.0.1"], resolve_dns=False),
        engine=EngineConfig(runs_dir=str(tmp_path / "runs")),
        vuln_classes=["security_headers"],
    )
    from qannas.scope import ScopeViolation
    with pytest.raises(ScopeViolation):
        Orchestrator(cfg, ["http://example.com/"], run_name="nope")
