from pathlib import Path

from qannas.kb import KnowledgeBase


def test_seed_and_get(tmp_path: Path):
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    assert "sql_injection" in kb.classes()
    pb = kb.get("sql_injection")
    assert pb and pb.cwe == "CWE-89"
    assert pb.payloads and "'" in pb.payloads
    kb.close()


def test_findings_memory(tmp_path: Path):
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.record_finding("http://t", "http://t/x", "reflected_xss", "medium", "confirmed", "ev")
    hist = kb.history("http://t")
    assert len(hist) == 1 and hist[0]["vuln_class"] == "reflected_xss"
    assert "http://t/x" in kb.known_endpoints("http://t", "reflected_xss")
    kb.close()


def test_custom_playbook_persists(tmp_path: Path):
    from qannas.kb import Playbook
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.upsert_playbook(Playbook(
        vuln_class="my_custom", title="Custom", cwe="CWE-0", owasp="x",
        severity="high", non_destructive=True, methodology="m",
        payloads=["p"], detect_signatures=["s"], param_hints=["h"],
    ))
    assert "my_custom" in kb.classes()
    kb.close()
