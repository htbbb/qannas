"""Auto-fix suggestions.

Strix generates patches; here we generate remediation guidance per confirmed
finding — the KB remediation always, plus an LLM-tailored code fix when a real
model is configured (offline mode falls back to the KB guidance). Written to
fixes.md in the run directory.
"""
from __future__ import annotations

from pathlib import Path

FIX_SYSTEM = (
    "You are a secure-coding assistant. Given a vulnerability class and endpoint, "
    "produce a concise, framework-agnostic code-level fix (max 8 lines), focusing "
    "on the correct secure pattern. No prose preamble."
)


def write_fixes(run_dir: Path, findings, kb, llm) -> Path:
    confirmed = [f for f in findings if f.status == "confirmed"]
    lines = ["# Qannas remediation guide", ""]
    if not confirmed:
        lines.append("_No confirmed findings to remediate._")
    for f in confirmed:
        pb = kb.get(f.vuln_class) if kb else None
        title = pb.title if pb else f.vuln_class
        lines += [f"## {title} — `{f.endpoint}`",
                  f"- **Remediation:** {pb.remediation if pb else 'See OWASP guidance.'}"]
        if llm is not None and not llm.is_mock:
            try:
                fix = llm.complete(FIX_SYSTEM,
                                   f"Class: {f.vuln_class}\nEndpoint: {f.endpoint}\nEvidence: {f.evidence}")
                lines += ["", "```", fix.strip()[:800], "```"]
            except Exception:
                pass
        lines.append("")
    path = run_dir / "fixes.md"
    path.write_text("\n".join(lines))
    return path
