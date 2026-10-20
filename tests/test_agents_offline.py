"""Recon + Validator agents, exercised fully offline with a fake HTTP tool.

No sockets are opened: a FakeHttp routes every request to a canned Response,
so these run deterministically with no network and the mock model.
"""
from __future__ import annotations

from qannas.agents.base import AgentContext
from qannas.agents.recon import ReconAgent
from qannas.agents.validator import ValidatorAgent
from qannas.blackboard import Blackboard, Finding
from qannas.config import Config, LLMConfig
from qannas.llm import LLM
from qannas.tools.http import Response


class FakeHttp:
    """Stands in for HttpTool; serves canned responses, counts calls."""
    def __init__(self, router):
        self._router = router
        self.calls = []
        self.request_count = 0
        self.transactions = []

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def request(self, method, url, **kw):
        self.calls.append((method, url))
        self.request_count += 1
        status, headers, text = self._router(method, url)
        return Response(url=url, status=status, headers=headers, text=text, elapsed_ms=1.0)

    def close(self):
        pass


def _ctx(tmp_path, http, kb=None):
    bb = Blackboard(tmp_path / "run")
    cfg = Config.default()
    llm = LLM(LLMConfig(model="mock"))
    return AgentContext(cfg=cfg, bb=bb, llm=llm, http=http, kb=kb)


# ---- recon ---------------------------------------------------------------
PAGE = ('<html><a href="/p?x=1">l</a>'
        '<form action="/s"><input name="q"></form></html>')


def test_recon_maps_endpoints_into_blackboard(tmp_path):
    http = FakeHttp(lambda m, u: (200, {"content-type": "text/html"}, PAGE))
    ctx = _ctx(tmp_path, http)
    ctx.bb.targets = ["http://127.0.0.1/"]
    ReconAgent(ctx).run()
    urls = {e.url for e in ctx.bb.endpoints.values()}
    assert ctx.bb.endpoints, "recon discovered no endpoints"
    assert any("127.0.0.1" in u for u in urls)
    assert http.request_count >= 1


def test_recon_records_note_on_failure(tmp_path):
    def boom(m, u):
        raise RuntimeError("scope violation")
    # ReconTool.crawl swallows per-URL errors; with every fetch failing no
    # endpoint is produced but the run must not raise.
    http = FakeHttp(boom)
    ctx = _ctx(tmp_path, http)
    ctx.bb.targets = ["http://127.0.0.1/"]
    ReconAgent(ctx).run()
    assert ctx.bb.endpoints == {}


# ---- validator -----------------------------------------------------------
def _validate_one(tmp_path, finding, router, kb=None):
    http = FakeHttp(router)
    ctx = _ctx(tmp_path, http, kb=kb)
    ctx.bb.add_finding(finding)
    ValidatorAgent(ctx).run()
    return ctx.bb.findings[0]


def test_security_headers_confirmed_when_missing(tmp_path):
    f = Finding(vuln_class="security_headers", endpoint="http://127.0.0.1/",
                status="candidate", severity="low")
    out = _validate_one(tmp_path, f, lambda m, u: (200, {}, "ok"))
    assert out.status == "confirmed"


def test_security_headers_rejected_when_present(tmp_path):
    present = {"content-security-policy": "x", "x-frame-options": "DENY",
               "strict-transport-security": "x", "x-content-type-options": "nosniff"}
    f = Finding(vuln_class="security_headers", endpoint="http://127.0.0.1/",
                status="candidate", severity="low")
    out = _validate_one(tmp_path, f, lambda m, u: (200, present, "ok"))
    assert out.status == "rejected"


def test_reflected_xss_confirmed_on_replay(tmp_path):
    # The validator injects marker "qnx7391"; reflect it unencoded in the body.
    f = Finding(vuln_class="reflected_xss", endpoint="http://127.0.0.1/", status="candidate")
    out = _validate_one(tmp_path, f, lambda m, u: (200, {}, "<qnx7391> reflected here"))
    assert out.status == "confirmed"


def test_reflected_xss_rejected_when_not_reflected(tmp_path):
    f = Finding(vuln_class="reflected_xss", endpoint="http://127.0.0.1/", status="candidate")
    out = _validate_one(tmp_path, f, lambda m, u: (200, {}, "nothing here"))
    assert out.status == "rejected"


def test_heuristic_class_needs_human(tmp_path):
    f = Finding(vuln_class="idor", endpoint="http://127.0.0.1/x?id=1", status="candidate")
    out = _validate_one(tmp_path, f, lambda m, u: (200, {}, ""))
    assert out.status == "needs_human"


def test_unknown_class_rejected(tmp_path):
    f = Finding(vuln_class="totally_unknown", endpoint="http://127.0.0.1/", status="candidate")
    out = _validate_one(tmp_path, f, lambda m, u: (200, {}, ""))
    assert out.status == "rejected"
    assert "no validator" in out.evidence
