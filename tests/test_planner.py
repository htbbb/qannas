"""Planner = the deterministic core of the orchestrator's main loop.

The orchestrator delegates every phase decision to Planner.next_action, so
these tests pin the phase transitions and the max_iterations stop without
needing the network or a model.
"""
from __future__ import annotations

from qannas.blackboard import Blackboard, Finding, Phase
from qannas.planner import Planner


def bb(tmp_path):
    b = Blackboard(tmp_path / "run")
    b.targets = ["http://127.0.0.1/"]
    return b


def test_recon_first_when_no_endpoints(tmp_path):
    p = Planner(["reflected_xss"], max_iterations=40)
    a = p.next_action(bb(tmp_path))
    assert a.kind == "recon"
    assert a.phase == Phase.RECON


def test_exploit_next_untested_class(tmp_path):
    b = bb(tmp_path)
    b.add_endpoint("http://127.0.0.1/a", "GET", ["q"])
    p = Planner(["reflected_xss", "sql_injection"], max_iterations=40)
    a = p.next_action(b)
    assert a.kind == "exploit"
    assert a.detail == "reflected_xss"      # first untested class in order
    assert a.phase == Phase.EXPLOIT


def test_validate_takes_priority_over_exploit(tmp_path):
    b = bb(tmp_path)
    b.add_endpoint("http://127.0.0.1/a", "GET", ["q"])
    b.add_finding(Finding(vuln_class="reflected_xss", endpoint="http://127.0.0.1/a",
                          status="candidate"))
    p = Planner(["reflected_xss"], max_iterations=40)
    a = p.next_action(b)
    assert a.kind == "validate"
    assert a.phase == Phase.VALIDATE


def test_report_when_coverage_complete(tmp_path):
    b = bb(tmp_path)
    b.add_endpoint("http://127.0.0.1/a", "GET", ["q"])
    b.mark_tested("http://127.0.0.1/a", "GET", "reflected_xss")
    p = Planner(["reflected_xss"], max_iterations=40)
    a = p.next_action(b)
    assert a.kind == "report"
    assert a.phase == Phase.REPORT


def test_stops_at_max_iterations(tmp_path):
    b = bb(tmp_path)
    p = Planner(["reflected_xss"], max_iterations=1)
    first = p.next_action(b)          # iteration 1 -> recon
    assert first.kind == "recon"
    second = p.next_action(b)         # iteration 2 > max -> report/stop
    assert second.kind == "report"
    assert second.phase == Phase.REPORT
    assert "budget" in second.detail.lower()
    assert b.iteration == 2
