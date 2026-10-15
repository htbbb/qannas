# Qannas vs Strix — design decisions

Grounded in a read of the real Strix source (`usestrix/strix`, ~45k LoC), not
just its README. Strix is a mature, well-engineered product; the goal here is
not to clone it but to beat it on specific axes where its architecture leaves
room.

## What Strix actually is

- **Agent loop driven by the LLM.** `strix/core/` runs an agent that decides each
  next step; expertise is injected as ~29 markdown **skills** under
  `strix/skills/vulnerabilities/` (xss, sqli, ssrf, ssti, idor, race conditions,
  prototype pollution, …) plus recon/framework/protocol/technology skills.
- **Rich toolkit** (`strix/tools/`): `agent_browser` (Playwright), `agents_graph`
  (multi-agent), `proxy` (Caido), `shell`, `mcp`, `coverage`, `threat_model`,
  `reporting`, `notes`, `todo`.
- **Docker runtime** (`strix/runtime/`), TUI + local viewer + cloud.

Its real strength is the **knowledge library** and the breadth of tools. Its
structural weaknesses are well documented for LLM-driven pentest agents:
long-horizon plan drift, and false positives from the same agent both exploiting
and judging.

## Where Qannas is designed to win

### 1. Architecture — deterministic planner + split roles
Strix lets the model own control flow. Qannas puts a **classical phase machine**
(`planner.py`) in charge of transitions (RECON→EXPLOIT⇄VALIDATE→REPORT); the LLM
only fills tactics within a phase. This directly targets the long-horizon
coherence failure that research (CHECKMATE, Northwestern 2026) shows hurts
LLM-only agents.

### 2. False positives — discovery ≠ validation
In Qannas, the agent that *finds* a candidate never *confirms* it. A separate
`ValidatorAgent` with a clean context independently replays deterministic proof;
only then is a finding `confirmed`. Heuristic classes (IDOR, SSRF) are never
auto-confirmed — they are `needs_human`. Measured output so far: 0 false
positives on the test corpus, with the honest `needs_human` bucket kept separate.

### 3. Databases — local knowledge base + cross-run memory
Strix ships expertise as markdown and keeps "continuous learning" in the paid
cloud. Qannas keeps both locally in **SQLite** (`kb.py`):
- a **knowledge base** of per-class playbooks (methodology, payloads, detection
  signatures, CWE/OWASP, param hints) — queryable and extensible with one
  `upsert_playbook`;
- a **findings memory** across runs, so the next scan of a target knows its
  history and can surface regressions/new issues.

### 4. Scanning method + AI — AI proposes, deterministic code disposes
`AIExploitAgent` pulls the KB playbook for a class, uses the LLM to tailor
non-destructive payloads to each endpoint (falling back to vetted seed payloads
offline), then decides hits with a **deterministic oracle** (signature / header /
reflection) — never the model's say-so. This widens coverage with AI without
inflating false positives, and the validator still gates confirmation.

## Current coverage vs the roadmap

Implemented: scope gate · planner · blackboard · KB (8 classes) · AI/KB exploit
agent · separate validator · API-spec ingestion · reports · CTF mode · Docker
sandbox · cross-run memory.

Next, to close the gap with Strix's toolkit:
1. **Playwright recon + DOM XSS** (match `agent_browser`, see SPA surface).
2. **Multi-agent graph** for parallel targets (match `agents_graph`).
3. **Caido/Burp proxy** integration and an OOB collector for real SSRF/blind
   confirmation.
4. **Vulnerability chaining** — a CHAIN phase that recognises finding A enables
   finding B (weak JWT + IDOR → account takeover).
5. **Local viewer** (`qannas view`) and CI mode.
6. Grow the KB toward Strix's ~29 classes.

The edge to keep measuring and reporting: **validated-vulnerability-rate**
(confirmed / candidates). That number, not raw finding count, is what beats a
noisy scanner.
