# Qannas (قنّاص)

Autonomous, **scope-gated** web pentesting + CTF platform with a planner-driven
agent loop and a **separate deterministic validator**. Built to be stronger than
a naive "let the LLM decide every step" scanner on the two axes that actually
matter in 2026: *long-horizon coherence* and *false-positive rate*.

```
RECON ──▶ ENUM ──▶ EXPLOIT ⇄ VALIDATE ──▶ REPORT
                     (deterministic phase machine, not the model, owns transitions)
```

## Why this design

Current autonomous pentesters (Strix, XBOW, and the 39+ open-source agents of
2026) are strong at exploitation on web benchmarks but share three weak spots.
Qannas is architected to attack them:

| Weakness in the field | Qannas's answer |
|---|---|
| LLM agents lose a coherent long-horizon plan (erratic path choice, repeated/forgotten work) | A **classical phase planner** (`planner.py`) owns phase transitions deterministically; the LLM only fills tactics *within* a phase. |
| False positives — agents "scale the noise" | **Discovery and validation are separate agents.** A candidate is only `confirmed` when a clean-context validator independently replays deterministic proof. |
| State drift / re-testing / lost findings | A single **blackboard** (`blackboard.py`) is the source of truth, persisted to `state.json` on every write; every `(endpoint, vuln-class)` is tested at most once. |

## Install

```bash
cd qannas
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Configure (authorization is mandatory)

```bash
cp config.example.yaml config.yaml
# edit scope.authorized to list ONLY hosts you have written permission to test
```

Run with no API key first — the built-in `mock` model drives the whole pipeline
offline so you can see it work:

```yaml
llm:
  model: "mock"
```

Then switch to any real model (same as Strix, via litellm):

```yaml
llm:
  model: "openrouter/z-ai/glm-5.3"   # or openai/gpt-5.4, anthropic/claude-sonnet-4-6
  api_key_env: "LLM_API_KEY"
```

## Use

```bash
# confirm a target is in scope before you ever touch it
qannas scope -t http://localhost:8080

# run the pentest pipeline
qannas scan -t http://localhost:8080

# multiple targets / a target list
qannas scan -t http://localhost:8080 -t https://app.example.com
qannas scan --target-list targets.txt

# solve a CTF challenge (needs a real model; mock won't actually solve)
qannas ctf -t http://localhost:9000 --brief "find the flag in the web app"
```

Results land in `qannas_runs/<run-name>/`: `state.json` (live state),
`report.json`, and `report.md`.

## Layout

```
qannas/
  scope.py          # authorization gate — the single egress chokepoint
  blackboard.py     # shared, persisted state
  planner.py        # deterministic phase machine (the long-horizon fix)
  llm.py            # litellm wrapper + offline mock model
  sandbox.py        # Docker isolation for generated PoCs
  kb.py             # SQLite knowledge base + cross-run findings memory
  ctf.py            # ReAct CTF solver (flag regex = win signal)
  report.py         # JSON + Markdown reports
  orchestrator.py   # the main loop
  cli.py            # entrypoint
  tools/            # http (scope-checked), recon crawler, nuclei hook
  agents/           # recon · ai_exploit (KB+LLM) · validator (separate contexts)
  data/             # kb_seed.json — seed vulnerability playbooks
tests/              # scope + blackboard + planner unit tests
```

## Roadmap (where to take it next)

1. **Deeper detectors** — boolean/time-based blind SQLi, DOM XSS via a headless
   browser, SSRF with an out-of-band collector, auth-aware IDOR (two sessions).
2. **Chaining** — let the planner recognise that finding A enables finding B
   (weak JWT + IDOR → account takeover). Add a `CHAIN` phase.
3. **MCP tools** — expose Caido/Burp, nuclei, and your own tools over MCP.
4. **Live viewer** — a `qannas view` dashboard over the run dir (Strix-style).
5. **CI mode** — `--non-interactive`, non-zero exit on confirmed findings,
   diff-scoped to changed files on pull requests.
6. **Metric that sells it** — track and report **validated-vulnerability-rate**
   (confirmed / total candidates). That number is your edge over noisy scanners.

## Authorized use only

Qannas actively tests the targets you point it at. Run it **only** against
systems you own or have explicit, written permission to test, and stay within
the agreed scope. The `scope` gate is a safeguard, not a legal substitute for
authorization. Unauthorized testing is illegal in most jurisdictions; you alone
are responsible for obtaining authorization and complying with the law.
Provided "as is", without warranty or liability for misuse.
