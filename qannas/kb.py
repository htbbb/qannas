"""Knowledge base + cross-run findings store (SQLite).

Two things Strix's open-source edition does not give you locally:

1. A queryable **knowledge base** of per-vuln-class playbooks (methodology,
   payloads, detection signatures, CWE/OWASP refs). Strix ships its expertise as
   markdown skills injected into the model; Qannas keeps the same knowledge in a
   database the AI agent queries per target, so it is structured, extensible, and
   inspectable — and you can add your own playbooks with one INSERT.

2. A **persistent findings memory** across runs. Every confirmed finding is
   recorded, so Qannas learns what a target looked like last time and can flag
   regressions / new issues. (Strix calls this "continuous learning" and keeps it
   in the paid cloud; here it is a local SQLite file.)

The DB lives at ~/.qannas/kb.sqlite by default and is seeded from
qannas/data/kb_seed.json on first use.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path


@dataclass
class Playbook:
    vuln_class: str
    title: str
    cwe: str
    owasp: str
    severity: str
    non_destructive: bool
    methodology: str
    payloads: list[str]
    detect_signatures: list[str]
    param_hints: list[str]


class KnowledgeBase:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.path = Path(db_path) if db_path else (Path.home() / ".qannas" / "kb.sqlite")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        # Seed on first use, and RE-seed (upsert) whenever the shipped seed
        # version is newer than what's stored — so KB updates reach an existing
        # DB on the next run after a `git pull`, without wiping findings history.
        shipped = self._shipped_version()
        if not self._count("playbooks") or shipped > self._stored_version():
            self.seed()
            self._set_meta("seed_version", str(shipped))

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS playbooks (
                vuln_class TEXT PRIMARY KEY,
                title TEXT, cwe TEXT, owasp TEXT, severity TEXT,
                non_destructive INTEGER,
                methodology TEXT, payloads TEXT,
                detect_signatures TEXT, param_hints TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, target TEXT, endpoint TEXT, vuln_class TEXT,
                severity TEXT, status TEXT, evidence TEXT
            );
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
            """
        )
        self.conn.commit()

    def _shipped_version(self) -> int:
        raw = resources.files("qannas.data").joinpath("kb_seed.json").read_text()
        return int(json.loads(raw).get("version", 1))

    def _stored_version(self) -> int:
        row = self.conn.execute("SELECT value FROM meta WHERE key='seed_version'").fetchone()
        return int(row["value"]) if row else 0

    def _set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value))
        self.conn.commit()

    def _count(self, table: str) -> int:
        return self.conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]

    # ---- seeding ---------------------------------------------------------
    def seed(self) -> int:
        raw = resources.files("qannas.data").joinpath("kb_seed.json").read_text()
        data = json.loads(raw)
        n = 0
        for pb in data["playbooks"]:
            self.upsert_playbook(Playbook(
                vuln_class=pb["vuln_class"], title=pb["title"], cwe=pb["cwe"],
                owasp=pb["owasp"], severity=pb["severity"],
                non_destructive=pb.get("non_destructive", True),
                methodology=pb["methodology"], payloads=pb.get("payloads", []),
                detect_signatures=pb.get("detect_signatures", []),
                param_hints=pb.get("param_hints", []),
            ))
            n += 1
        return n

    def upsert_playbook(self, pb: Playbook) -> None:
        self.conn.execute(
            """INSERT INTO playbooks
               (vuln_class,title,cwe,owasp,severity,non_destructive,methodology,payloads,detect_signatures,param_hints)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(vuln_class) DO UPDATE SET
                 title=excluded.title, cwe=excluded.cwe, owasp=excluded.owasp,
                 severity=excluded.severity, non_destructive=excluded.non_destructive,
                 methodology=excluded.methodology, payloads=excluded.payloads,
                 detect_signatures=excluded.detect_signatures, param_hints=excluded.param_hints""",
            (pb.vuln_class, pb.title, pb.cwe, pb.owasp, pb.severity,
             int(pb.non_destructive), pb.methodology, json.dumps(pb.payloads),
             json.dumps(pb.detect_signatures), json.dumps(pb.param_hints)),
        )
        self.conn.commit()

    # ---- queries ---------------------------------------------------------
    def get(self, vuln_class: str) -> Playbook | None:
        row = self.conn.execute("SELECT * FROM playbooks WHERE vuln_class=?", (vuln_class,)).fetchone()
        return self._row_to_pb(row) if row else None

    def classes(self) -> list[str]:
        return [r["vuln_class"] for r in self.conn.execute("SELECT vuln_class FROM playbooks ORDER BY vuln_class")]

    @staticmethod
    def _row_to_pb(row: sqlite3.Row) -> Playbook:
        return Playbook(
            vuln_class=row["vuln_class"], title=row["title"], cwe=row["cwe"],
            owasp=row["owasp"], severity=row["severity"],
            non_destructive=bool(row["non_destructive"]), methodology=row["methodology"],
            payloads=json.loads(row["payloads"]), detect_signatures=json.loads(row["detect_signatures"]),
            param_hints=json.loads(row["param_hints"]),
        )

    # ---- findings memory -------------------------------------------------
    def record_finding(self, target: str, endpoint: str, vuln_class: str,
                       severity: str, status: str, evidence: str) -> None:
        self.conn.execute(
            "INSERT INTO findings (ts,target,endpoint,vuln_class,severity,status,evidence) VALUES (?,?,?,?,?,?,?)",
            (time.time(), target, endpoint, vuln_class, severity, status, evidence),
        )
        self.conn.commit()

    def history(self, target: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ts,endpoint,vuln_class,severity,status FROM findings WHERE target=? ORDER BY ts DESC",
            (target,),
        ).fetchall()
        return [dict(r) for r in rows]

    def known_endpoints(self, target: str, vuln_class: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT endpoint FROM findings WHERE target=? AND vuln_class=? AND status='confirmed'",
            (target, vuln_class),
        ).fetchall()
        return {r["endpoint"] for r in rows}

    def close(self) -> None:
        self.conn.close()
