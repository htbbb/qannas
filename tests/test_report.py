"""report.write_reports must emit json / md / csv / sarif without error."""
from __future__ import annotations

import csv
import json

from qannas.blackboard import Blackboard, Finding
from qannas.kb import KnowledgeBase
from qannas.report import write_reports


def _bb(tmp_path):
    bb = Blackboard(tmp_path / "run")
    bb.targets = ["http://127.0.0.1/"]
    bb.add_endpoint("http://127.0.0.1/a", "GET", ["q"])
    bb.mark_tested("http://127.0.0.1/a", "GET", "reflected_xss")
    bb.technologies = ["nginx"]
    bb.add_finding(Finding(vuln_class="reflected_xss", endpoint="http://127.0.0.1/a?q=x",
                           severity="high", status="confirmed",
                           evidence="marker reflected", detail="reflected", poc="GET http://127.0.0.1/a?q=<x>"))
    bb.add_finding(Finding(vuln_class="idor", endpoint="http://127.0.0.1/o?id=1",
                           severity="medium", status="needs_human", evidence="context"))
    bb.add_finding(Finding(vuln_class="sql_injection", endpoint="http://127.0.0.1/a",
                           severity="high", status="rejected"))
    return bb


def test_all_four_reports_written_and_valid(tmp_path):
    bb = _bb(tmp_path)
    paths = write_reports(bb, kb=None)
    assert set(paths) == {"json", "markdown", "csv", "sarif"}
    for p in paths.values():
        assert p.exists() and p.stat().st_size > 0

    data = json.loads(paths["json"].read_text())
    assert data["summary"]["confirmed"] == 1
    assert data["summary"]["needs_human"] == 1
    assert data["summary"]["rejected_false_positives"] == 1
    assert data["technologies"] == ["nginx"]

    sarif = json.loads(paths["sarif"].read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Qannas"
    assert len(sarif["runs"][0]["results"]) == 2   # confirmed + needs_human

    rows = list(csv.reader(paths["csv"].read_text().splitlines()))
    assert rows[0] == ["id", "title", "severity", "status", "endpoint"]
    assert len(rows) == 3                           # header + 2 reported findings

    md = paths["markdown"].read_text()
    assert "Qannas assessment report" in md
    assert "http://127.0.0.1/" in md


def test_reports_enrich_from_kb(tmp_path):
    bb = _bb(tmp_path)
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    try:
        paths = write_reports(bb, kb=kb)
        data = json.loads(paths["json"].read_text())
        conf = data["confirmed"][0]
        # reflected_xss playbook ships CWE/title metadata that enrich() pulls in.
        assert conf["title"]
        assert conf["cwe"]
        assert conf["confidence"] == "High"
    finally:
        kb.close()


def test_reports_handle_empty_findings(tmp_path):
    bb = Blackboard(tmp_path / "run")
    bb.targets = ["http://127.0.0.1/"]
    paths = write_reports(bb, kb=None)
    data = json.loads(paths["json"].read_text())
    assert data["summary"]["confirmed"] == 0
    assert paths["markdown"].exists()
