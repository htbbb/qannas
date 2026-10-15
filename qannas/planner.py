"""Deterministic phase planner.

This is the piece that separates Qannas from a naive "let the LLM pick the next
step" loop. Published research (e.g. CHECKMATE, Northwestern 2026) shows LLM
agents lose coherence over long engagements: erratic path selection, repeated
or incomplete execution, forgetting earlier findings. We fix that by letting a
classical state machine own the *phase transitions*, while the LLM only fills
in tactics *within* a phase. The planner's decisions are reproducible and
auditable — they do not depend on the model's mood.

Phase flow:
    RECON -> ENUM -> EXPLOIT -> VALIDATE -> REPORT -> DONE
with EXPLOIT<->VALIDATE cycling while candidate findings and untested
endpoints remain, bounded by engine.max_iterations.
"""
from __future__ import annotations

from dataclasses import dataclass

from .blackboard import Blackboard, Phase


@dataclass
class Action:
    phase: Phase
    kind: str          # recon | enumerate | exploit | validate | report | stop
    detail: str = ""


class Planner:
    def __init__(self, vuln_classes: list[str], max_iterations: int) -> None:
        self.vuln_classes = vuln_classes
        self.max_iterations = max_iterations

    def next_action(self, bb: Blackboard) -> Action:
        bb.iteration += 1
        if bb.iteration > self.max_iterations:
            bb.phase = Phase.REPORT
            return Action(Phase.REPORT, "report", "iteration budget exhausted")

        # 1. RECON: no endpoints discovered yet.
        if not bb.endpoints:
            bb.phase = Phase.RECON
            return Action(Phase.RECON, "recon", "map attack surface for targets")

        # 2. VALIDATE takes priority: never let candidates pile up unverified.
        #    Discovery and validation are deliberately separated so a candidate
        #    is confirmed by a clean-context agent, not the one that found it.
        if bb.candidates():
            bb.phase = Phase.VALIDATE
            return Action(Phase.VALIDATE, "validate", "reproduce pending candidates")

        # 3. EXPLOIT: probe the next untested (endpoint, vuln-class) pair.
        for vc in self.vuln_classes:
            if bb.untested(vc):
                bb.phase = Phase.EXPLOIT
                return Action(Phase.EXPLOIT, "exploit", vc)

        # 4. Nothing left to test and nothing pending -> report.
        bb.phase = Phase.REPORT
        return Action(Phase.REPORT, "report", "coverage complete")
