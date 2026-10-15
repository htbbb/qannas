"""Shared context object passed to every agent."""
from __future__ import annotations

from dataclasses import dataclass

from ..blackboard import Blackboard
from ..config import Config
from ..kb import KnowledgeBase
from ..llm import LLM
from ..tools.http import HttpTool


@dataclass
class AgentContext:
    cfg: Config
    bb: Blackboard
    llm: LLM
    http: HttpTool
    kb: KnowledgeBase | None = None
    browser: object | None = None   # tools.browser.Browser when --browser is on
