"""Docker sandbox for running generated proof-of-concept scripts in isolation.

PoCs that the agent writes are untrusted code. They run inside a throwaway
container (network 'none' by default) so a buggy or hostile PoC cannot touch
the host or reach anything it shouldn't. If Docker isn't available the caller
can fall back to not executing PoCs at all.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import SandboxConfig


def available() -> bool:
    return shutil.which("docker") is not None


class Sandbox:
    def __init__(self, cfg: SandboxConfig) -> None:
        self.cfg = cfg

    def run_python(self, code: str, timeout: int = 60) -> dict:
        if not self.cfg.enabled:
            return {"ran": False, "reason": "sandbox disabled in config"}
        if not available():
            return {"ran": False, "reason": "docker not found on PATH"}
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "poc.py"
            script.write_text(code)
            cmd = [
                "docker", "run", "--rm",
                "--network", self.cfg.network,
                "--memory", "256m", "--cpus", "0.5",
                "--pids-limit", "128",
                "-v", f"{tmp}:/poc:ro",
                self.cfg.image, "python", "-I", "/poc/poc.py",
            ]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                return {"ran": True, "timeout": True}
            return {"ran": True, "exit_code": p.returncode,
                    "stdout": p.stdout[-4000:], "stderr": p.stderr[-2000:]}
