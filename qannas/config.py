"""Configuration loading and typed access."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class LLMConfig:
    model: str = "mock"
    api_key_env: str = "LLM_API_KEY"
    api_base_env: str = "LLM_API_BASE"
    temperature: float = 0.2
    max_tokens: int = 2048

    @property
    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env)

    @property
    def api_base(self) -> str | None:
        return os.environ.get(self.api_base_env)


@dataclass
class ScopeConfig:
    authorized: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    # Resolve hostnames and reject targets that land on internal / private /
    # loopback addresses unless that address (or a covering CIDR) is itself
    # authorized. Turn off for offline runs with no DNS (e.g. the mock pipeline).
    resolve_dns: bool = True


@dataclass
class EngineConfig:
    max_iterations: int = 40
    max_requests_per_endpoint: int = 25
    request_timeout: int = 15
    rate_limit_per_sec: float = 4.0
    runs_dir: str = "qannas_runs"
    max_total_requests: int = 5000   # budget: hard cap on HTTP requests per run
    max_seconds: int = 1800          # budget: wall-clock cap per run


@dataclass
class SandboxConfig:
    enabled: bool = False
    image: str = "python:3.12-slim"
    network: str = "none"


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    vuln_classes: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        raw: dict[str, Any] = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            llm=LLMConfig(**(raw.get("llm") or {})),
            scope=ScopeConfig(**(raw.get("scope") or {})),
            engine=EngineConfig(**(raw.get("engine") or {})),
            sandbox=SandboxConfig(**(raw.get("sandbox") or {})),
            vuln_classes=raw.get("vuln_classes") or [],
        )

    @classmethod
    def default(cls) -> "Config":
        """A minimal localhost-only config used when no file is given."""
        return cls(scope=ScopeConfig(authorized=["localhost", "127.0.0.1"]),
                   vuln_classes=["security_headers", "reflected_xss"])
