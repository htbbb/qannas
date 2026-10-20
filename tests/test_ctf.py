"""CTF solver basic path with the mock model, plus deterministic win paths."""
from __future__ import annotations

from qannas.agents.base import AgentContext
from qannas.blackboard import Blackboard
from qannas.config import Config, LLMConfig
from qannas.ctf import CTFSolver
from qannas.llm import LLM
from qannas.tools.http import Response


class ScriptedLLM:
    """Returns queued responses; repeats the last once exhausted."""
    def __init__(self, responses):
        self._responses = list(responses)

    def complete(self, system, user):
        return self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]


class FakeHttp:
    def __init__(self, body=""):
        self.body = body
        self.request_count = 0

    def get(self, url, **kw):
        self.request_count += 1
        return Response(url=url, status=200, headers={}, text=self.body, elapsed_ms=1.0)


def _ctx(tmp_path, llm, http):
    bb = Blackboard(tmp_path / "run")
    return AgentContext(cfg=Config.default(), bb=bb, llm=llm, http=http)


def test_mock_model_runs_without_solving(tmp_path):
    # The mock model never emits a real tool call, so the loop exhausts its
    # step budget and returns unsolved — exercised fully offline.
    ctx = _ctx(tmp_path, LLM(LLMConfig(model="mock")), FakeHttp())
    res = CTFSolver(ctx, max_steps=3).solve("http://127.0.0.1/", "find the flag")
    assert res == {"solved": False, "steps": 3}


def test_submit_valid_flag_solves(tmp_path):
    llm = ScriptedLLM(['{"tool": "submit", "flag": "flag{winner}"}'])
    ctx = _ctx(tmp_path, llm, FakeHttp())
    res = CTFSolver(ctx, max_steps=5).solve("http://127.0.0.1/", "brief")
    assert res["solved"] is True
    assert res["flag"] == "flag{winner}"
    assert res["steps"] == 1


def test_flag_found_in_http_body_solves(tmp_path):
    llm = ScriptedLLM(['{"tool": "http_get", "url": "http://127.0.0.1/secret"}'])
    http = FakeHttp(body="congrats flag{from_body} enjoy")
    ctx = _ctx(tmp_path, llm, http)
    res = CTFSolver(ctx, max_steps=5).solve("http://127.0.0.1/", "brief")
    assert res["solved"] is True
    assert res["flag"] == "flag{from_body}"
    assert http.request_count == 1


def test_bad_flag_format_keeps_going(tmp_path):
    # First a malformed flag (rejected), then a valid one.
    llm = ScriptedLLM([
        '{"tool": "submit", "flag": "not-a-flag"}',
        '{"tool": "submit", "flag": "flag{ok}"}',
    ])
    ctx = _ctx(tmp_path, llm, FakeHttp())
    res = CTFSolver(ctx, max_steps=5).solve("http://127.0.0.1/", "brief")
    assert res["solved"] is True
    assert res["steps"] == 2
