from pathlib import Path

from qannas.blackboard import Blackboard, Finding
from qannas.config import Config
from qannas.planner import Planner


def test_endpoint_tracking(tmp_path: Path):
    bb = Blackboard(tmp_path)
    bb.add_endpoint("http://localhost/a", "GET", ["q"])
    bb.add_endpoint("http://localhost/a", "GET", ["q"])  # dup
    assert len(bb.endpoints) == 1
    assert bb.untested("reflected_xss")
    bb.mark_tested("http://localhost/a", "GET", "reflected_xss")
    assert not bb.untested("reflected_xss")


def test_finding_lifecycle(tmp_path: Path):
    bb = Blackboard(tmp_path)
    f = bb.add_finding(Finding(vuln_class="sql_injection", endpoint="http://localhost/x"))
    assert bb.candidates()
    bb.update_finding(f.id, status="confirmed")
    assert not bb.candidates()


def test_planner_phase_flow(tmp_path: Path):
    bb = Blackboard(tmp_path)
    planner = Planner(["security_headers"], max_iterations=10)
    # no endpoints -> recon
    assert planner.next_action(bb).kind == "recon"
    bb.add_endpoint("http://localhost/a", "GET")
    # endpoints, no candidates -> exploit
    assert planner.next_action(bb).kind == "exploit"
    bb.add_finding(Finding(vuln_class="security_headers", endpoint="http://localhost/a"))
    # candidate pending -> validate takes priority
    assert planner.next_action(bb).kind == "validate"


def test_state_persisted(tmp_path: Path):
    bb = Blackboard(tmp_path)
    bb.add_endpoint("http://localhost/a", "GET")
    assert (tmp_path / "state.json").exists()


def test_config_default():
    cfg = Config.default()
    assert "localhost" in cfg.scope.authorized
