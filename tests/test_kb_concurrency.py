"""Concurrency regression: parallel scans share one on-disk KB file.

`qannas scan --parallel` runs each target in its own worker thread, and each
thread builds its own Orchestrator -> its own KnowledgeBase -> its own SQLite
connection to the same ~/.qannas/kb.sqlite file. With SQLite's default rollback
journal and a zero busy-timeout, concurrent writers fail immediately with
"database is locked". These tests pin the fix (WAL + busy_timeout).
"""
from __future__ import annotations

import sqlite3
import threading

from qannas.kb import KnowledgeBase

WRITERS = 8
PER_WRITER = 25


def _hammer(db_path):
    """Open an independent KB on this thread and write many findings."""
    errors: list[Exception] = []

    def worker(wid: int) -> None:
        try:
            kb = KnowledgeBase(db_path)
            for i in range(PER_WRITER):
                kb.record_finding(
                    target=f"target-{wid}", endpoint=f"/e{i}",
                    vuln_class="reflected_xss", severity="high",
                    status="confirmed", evidence="x" * 32,
                )
                # Interleave the reads a real scan performs between writes;
                # with a rollback journal this reader/writer mix is what
                # triggers "database is locked" under concurrency.
                kb.known_endpoints(f"target-{wid}", "reflected_xss")
                kb.history(f"target-{wid}")
            kb.close()
        except Exception as e:  # noqa: BLE001 - we want to inspect any failure
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(WRITERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


def test_parallel_writes_do_not_lock(tmp_path):
    db_path = tmp_path / "kb.sqlite"
    errors = _hammer(db_path)

    locked = [e for e in errors if isinstance(e, sqlite3.OperationalError)
              and "database is locked" in str(e).lower()]
    assert not locked, f"got 'database is locked' errors: {locked}"
    assert not errors, f"unexpected errors during parallel writes: {errors}"

    kb = KnowledgeBase(db_path)
    try:
        assert kb._count("findings") == WRITERS * PER_WRITER
    finally:
        kb.close()


def test_connection_uses_wal_and_busy_timeout(tmp_path):
    db_path = tmp_path / "kb.sqlite"
    kb = KnowledgeBase(db_path)
    try:
        mode = kb.conn.execute("PRAGMA journal_mode").fetchone()[0]
        busy = kb.conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert str(mode).lower() == "wal"
        assert int(busy) >= 1000
    finally:
        kb.close()
