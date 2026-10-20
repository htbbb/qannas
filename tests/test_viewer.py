"""viewer._runs indexes run directories for the dashboard (no server needed)."""
from __future__ import annotations

import json

from qannas import viewer


def test_runs_lists_runs_with_reports(tmp_path):
    runs = tmp_path / "runs"
    good = runs / "run-1"
    good.mkdir(parents=True)
    (good / "report.json").write_text(json.dumps({
        "target": ["http://127.0.0.1/"],
        "summary": {"confirmed": 2, "needs_human": 1, "endpoints": 5},
    }))
    # a directory without a report.json is skipped
    (runs / "run-empty").mkdir()

    out = viewer._runs(runs)
    assert len(out) == 1
    assert out[0]["name"] == "run-1"
    assert out[0]["confirmed"] == 2
    assert out[0]["needs_human"] == 1
    assert out[0]["endpoints"] == 5
    assert out[0]["target"] == ["http://127.0.0.1/"]


def test_runs_empty_when_dir_missing(tmp_path):
    assert viewer._runs(tmp_path / "does-not-exist") == []


def test_runs_skips_corrupt_report(tmp_path):
    runs = tmp_path / "runs"
    bad = runs / "run-bad"
    bad.mkdir(parents=True)
    (bad / "report.json").write_text("{ not json")
    assert viewer._runs(runs) == []
