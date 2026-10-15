"""Render blackboard findings to JSON + Markdown (+ CSV) in the run directory.

Finding detail is modelled on Strix's report writer: title, severity, CWE,
OWASP, confidence, evidence, PoC and remediation, severity-ordered. Metadata
(CWE/OWASP/remediation/title) is pulled from the knowledge base so every report
is consistent and maintained in one place.
"""
from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from .blackboard import Blackboard

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CONFIDENCE = {"confirmed": "High", "needs_human": "Medium", "candidate": "Low"}


def _dedupe(findings):
    seen, out = set(), []
    for f in findings:
        k = (f.vuln_class, f.endpoint, f.status)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def write_reports(bb: Blackboard, kb=None, chains=None) -> dict[str, Path]:
    chains = chains or []
    confirmed = _dedupe([f for f in bb.findings if f.status == "confirmed"])
    needs_human = _dedupe([f for f in bb.findings if f.status == "needs_human"])
    rejected = [f for f in bb.findings if f.status == "rejected"]
    coverage = sorted({c for e in bb.endpoints.values() for c in e.tested_classes})

    def enrich(f):
        pb = kb.get(f.vuln_class) if kb else None
        d = asdict(f)
        d["title"] = pb.title if pb else f.vuln_class
        d["cwe"] = pb.cwe if pb else ""
        d["owasp"] = pb.owasp if pb else ""
        d["remediation"] = pb.remediation if pb else ""
        d["confidence"] = CONFIDENCE.get(f.status, "Low")
        return d

    json_path = bb.run_dir / "report.json"
    json_path.write_text(json.dumps({
        "target": bb.targets,
        "summary": {
            "endpoints": len(bb.endpoints),
            "confirmed": len(confirmed),
            "needs_human": len(needs_human),
            "rejected_false_positives": len(rejected),
            "by_severity": _severity_counts(confirmed),
            "coverage_classes": coverage,
            "coverage_count": len(coverage),
        },
        "technologies": bb.technologies,
        "chains": [{"title": c.title, "severity": c.severity,
                    "narrative": c.narrative, "components": c.components} for c in chains],
        "confirmed": [enrich(f) for f in _sorted(confirmed)],
        "needs_human": [enrich(f) for f in needs_human],
    }, indent=2))

    # SARIF 2.1.0 — importable into GitHub code scanning and SARIF viewers.
    sarif_path = bb.run_dir / "report.sarif.json"
    sarif_path.write_text(json.dumps(_sarif(confirmed + needs_human, kb), indent=2))

    # CSV index (Strix-style): id,title,severity,status,endpoint
    csv_path = bb.run_dir / "findings.csv"
    with csv_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "title", "severity", "status", "endpoint"])
        for f in _sorted(confirmed + needs_human):
            pb = kb.get(f.vuln_class) if kb else None
            w.writerow([f.id, (pb.title if pb else f.vuln_class),
                        f.severity.upper(), f.status, f.endpoint])

    md_path = bb.run_dir / "report.md"
    md_path.write_text(_markdown(bb, confirmed, needs_human, rejected, kb, coverage, chains))
    return {"json": json_path, "markdown": md_path, "csv": csv_path, "sarif": sarif_path}


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def _sarif(findings, kb) -> dict:
    rules, rule_ids = [], set()
    results = []
    for f in findings:
        pb = kb.get(f.vuln_class) if kb else None
        if f.vuln_class not in rule_ids:
            rule_ids.add(f.vuln_class)
            rules.append({
                "id": f.vuln_class,
                "name": (pb.title if pb else f.vuln_class).replace(" ", ""),
                "shortDescription": {"text": pb.title if pb else f.vuln_class},
                "properties": {"cwe": pb.cwe if pb else "", "owasp": pb.owasp if pb else "",
                               "security-severity": {"critical": "9.5", "high": "8.0",
                               "medium": "5.5", "low": "3.0", "info": "1.0"}.get(f.severity, "1.0")},
            })
        results.append({
            "ruleId": f.vuln_class,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.detail}. {f.evidence}".strip()},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.endpoint}}}],
            "properties": {"status": f.status, "poc": f.poc},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Qannas", "informationUri":
                 "https://github.com/htbbb/qannas", "rules": rules}}, "results": results}],
    }


def _sorted(items):
    return sorted(items, key=lambda x: (SEV_ORDER.get(x.severity, 9), x.ts))


def _severity_counts(findings) -> dict:
    out = {}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _markdown(bb, confirmed, needs_human, rejected, kb, coverage=None, chains=None) -> str:
    chains = chains or []
    L = ["# Qannas assessment report", ""]
    L += [f"- **Target(s):** {', '.join(bb.targets)}",
          f"- **Endpoints mapped:** {len(bb.endpoints)}",
          f"- **Vulnerability classes tested:** {len(coverage or [])}",
          f"- **Confirmed:** {len(confirmed)}  ·  **Needs review:** {len(needs_human)}"
          f"  ·  **False positives filtered:** {len(rejected)}"]
    if bb.technologies:
        L.append(f"- **Technologies:** {', '.join(bb.technologies)}")
    sc = _severity_counts(confirmed)
    if sc:
        L.append("- **By severity:** " + ", ".join(f"{k.upper()}: {v}" for k, v in
                 sorted(sc.items(), key=lambda kv: SEV_ORDER.get(kv[0], 9))))
    L.append("")

    if chains:
        L += ["## Attack chains", ""]
        for c in sorted(chains, key=lambda x: SEV_ORDER.get(x.severity, 9)):
            L += [f"### [{c.severity.upper()}] {c.title}",
                  f"- Components: {', '.join(c.components)}",
                  f"- {c.narrative}", ""]

    if confirmed:
        L += ["## Confirmed findings", ""]
        for f in _sorted(confirmed):
            L += _finding_block(f, kb)

    if needs_human:
        L += ["## Needs human review (heuristic / context-dependent)", ""]
        for f in _sorted(needs_human):
            L += _finding_block(f, kb)

    L += ["---", "_Generated by Qannas. Authorized testing only; every finding above "
          "was produced against a target in the configured scope._"]
    return "\n".join(x for x in L if x is not None)


def _finding_block(f, kb) -> list[str]:
    pb = kb.get(f.vuln_class) if kb else None
    title = pb.title if pb else f.vuln_class
    out = [f"### [{f.severity.upper()}] {title} — `{f.endpoint}`",
           f"- **Class:** {f.vuln_class}"
           + (f"  ·  **CWE:** {pb.cwe}" if pb and pb.cwe else "")
           + (f"  ·  **OWASP:** {pb.owasp}" if pb and pb.owasp else ""),
           f"- **Confidence:** {CONFIDENCE.get(f.status, 'Low')}  ·  **Status:** {f.status}",
           f"- **Detail:** {f.detail}" if f.detail else None,
           f"- **Evidence:** {f.evidence}" if f.evidence else None,
           f"- **PoC:** `{f.poc}`" if f.poc else None]
    if pb and pb.remediation:
        out.append(f"- **Remediation:** {pb.remediation}")
    out.append("")
    return [x for x in out if x is not None]
