"""Optional integration hook for ProjectDiscovery's `nuclei`.

If the `nuclei` binary is on PATH, this runs its template-based checks against
an authorized target and returns structured findings. If it's absent, callers
simply skip it. This is how you bolt a mature signature engine onto the agent
loop without reinventing it — the agent decides *when* to run it; nuclei does
the pattern matching.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..scope import ScopeGuard


def available() -> bool:
    return shutil.which("nuclei") is not None


def run(target: str, guard: ScopeGuard, severity: str = "low,medium,high,critical", timeout: int = 300) -> list[dict]:
    guard.check(target)                 # authorization gate before spawning the scanner
    if not available():
        return []
    cmd = ["nuclei", "-u", target, "-silent", "-jsonl", "-severity", severity]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    out = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
