"""CTF mode — an LLM-driven ReAct loop aimed at capturing a flag.

Unlike the pentest pipeline (which maps a surface and reports findings), a CTF
challenge has a single win condition: retrieve the flag. The loop gives the
model a small, scope-gated tool surface (HTTP + sandboxed shell/python) and
iterates until the flag regex matches or the step budget runs out. The flag is
the deterministic success signal — no model self-grading.
"""
from __future__ import annotations

import json
import re

from .agents.base import AgentContext
from .sandbox import Sandbox

DEFAULT_FLAG_RE = r"(flag\{[^}]+\}|[A-Za-z0-9_]+\{[^}]+\})"

SYSTEM = """You are a CTF-solving agent working strictly within an authorized challenge.
You may call tools by replying with a single JSON object:
  {"tool": "http_get", "url": "..."}          -> fetch a page (scope-gated)
  {"tool": "python", "code": "..."}           -> run python in an isolated sandbox
  {"tool": "submit", "flag": "..."}           -> submit the flag you found
Think step by step. Prefer the smallest action that gains information.
Respond with JSON only, one tool call per turn."""


class CTFSolver:
    def __init__(self, ctx: AgentContext, flag_regex: str = DEFAULT_FLAG_RE, max_steps: int = 25) -> None:
        self.ctx = ctx
        self.flag_re = re.compile(flag_regex)
        self.max_steps = max_steps
        self.sandbox = Sandbox(ctx.cfg.sandbox)

    def solve(self, target: str, brief: str) -> dict:
        bb = self.ctx.bb
        transcript: list[str] = [f"Challenge target: {target}\nBrief: {brief}"]
        for step in range(1, self.max_steps + 1):
            user = "\n\n".join(transcript[-8:]) + "\n\nYour next tool call (JSON only):"
            raw = self.ctx.llm.complete(SYSTEM, user)
            call = _parse(raw)
            bb.note(f"ctf step {step}: {call.get('tool')}")
            tool = call.get("tool")

            if tool == "submit":
                flag = call.get("flag", "")
                if self.flag_re.search(flag):
                    return {"solved": True, "flag": flag, "steps": step}
                transcript.append(f"Submitted '{flag}' — not a valid flag format, keep going.")
                continue

            if tool == "http_get":
                url = call.get("url", "")
                try:
                    r = self.ctx.http.get(url)
                    body = r.text[:3000]
                    m = self.flag_re.search(body)
                    if m:
                        return {"solved": True, "flag": m.group(0), "steps": step}
                    transcript.append(f"[http_get {url}] -> HTTP {r.status}\n{body}")
                except Exception as e:
                    transcript.append(f"[http_get {url}] error: {e}")
                continue

            if tool == "python":
                res = self.sandbox.run_python(call.get("code", ""))
                out = json.dumps(res)[:3000]
                m = self.flag_re.search(out)
                if m:
                    return {"solved": True, "flag": m.group(0), "steps": step}
                transcript.append(f"[python] -> {out}")
                continue

            transcript.append(f"Unknown tool '{tool}'. Use http_get, python, or submit.")

        return {"solved": False, "steps": self.max_steps}


def _parse(raw: str) -> dict:
    raw = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", raw, re.S)
    if fence:
        raw = fence.group(1).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
    return {"tool": "noop"}
