"""Shared state blackboard.

The blackboard is the single source of truth every agent reads from and writes
to. It fixes the classic failure modes of long-running LLM agents — state
drift, re-testing the same endpoint, forgetting what was found — by persisting
every discovery immediately and tracking exactly what has and hasn't been
tested. Serialises to JSON so a run is fully inspectable (and resumable).
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path


class Phase(str, Enum):
    RECON = "recon"
    ENUM = "enum"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    REPORT = "report"
    DONE = "done"


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    tested_classes: list[str] = field(default_factory=list)
    request_count: int = 0


@dataclass
class Finding:
    vuln_class: str
    endpoint: str
    severity: str = "info"            # info | low | medium | high | critical
    status: str = "candidate"         # candidate | confirmed | rejected
    evidence: str = ""                # deterministic proof from the validator
    detail: str = ""
    poc: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    ts: float = field(default_factory=time.time)


class Blackboard:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.phase: Phase = Phase.RECON
        self.targets: list[str] = []
        self.endpoints: dict[str, Endpoint] = {}
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self.iteration: int = 0

    # ---- endpoints -------------------------------------------------------
    def add_endpoint(self, url: str, method: str = "GET", params: list[str] | None = None) -> None:
        with self._lock:
            key = f"{method} {url}"
            if key not in self.endpoints:
                self.endpoints[key] = Endpoint(url=url, method=method, params=params or [])
                self._flush()

    def untested(self, vuln_class: str) -> list[Endpoint]:
        with self._lock:
            return [e for e in self.endpoints.values() if vuln_class not in e.tested_classes]

    def mark_tested(self, endpoint_url: str, method: str, vuln_class: str) -> None:
        with self._lock:
            ep = self.endpoints.get(f"{method} {endpoint_url}")
            if ep and vuln_class not in ep.tested_classes:
                ep.tested_classes.append(vuln_class)
                ep.request_count += 1
                self._flush()

    # ---- findings --------------------------------------------------------
    def add_finding(self, f: Finding) -> Finding:
        with self._lock:
            self.findings.append(f)
            self._flush()
            return f

    def candidates(self) -> list[Finding]:
        with self._lock:
            return [f for f in self.findings if f.status == "candidate"]

    def update_finding(self, fid: str, **changes) -> None:
        with self._lock:
            for f in self.findings:
                if f.id == fid:
                    for k, v in changes.items():
                        setattr(f, k, v)
                    break
            self._flush()

    def note(self, msg: str) -> None:
        with self._lock:
            self.notes.append(msg)

    # ---- persistence -----------------------------------------------------
    def _flush(self) -> None:
        state = {
            "phase": self.phase.value,
            "iteration": self.iteration,
            "targets": self.targets,
            "endpoints": [asdict(e) for e in self.endpoints.values()],
            "findings": [asdict(f) for f in self.findings],
            "notes": self.notes,
        }
        (self.run_dir / "state.json").write_text(json.dumps(state, indent=2))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "phase": self.phase.value,
                "endpoints": len(self.endpoints),
                "findings": len(self.findings),
                "confirmed": len([f for f in self.findings if f.status == "confirmed"]),
            }
