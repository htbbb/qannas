"""LLM access layer (provider-agnostic via litellm) with an offline mock.

The mock model lets the whole pipeline run deterministically with no API key
and no network, which is how the unit tests and `--model mock` dry-runs work.
Swap in any real model string (openrouter/..., openai/..., anthropic/...) and
the same agents drive it unchanged.
"""
from __future__ import annotations

import json
import re

from .config import LLMConfig


class LLM:
    def __init__(self, cfg: LLMConfig) -> None:
        self.cfg = cfg
        self.is_mock = cfg.model.lower() == "mock"

    def complete(self, system: str, user: str) -> str:
        if self.is_mock:
            return _MockModel.respond(system, user)
        import litellm  # imported lazily so mock mode needs no dependency

        kwargs = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
        }
        if self.cfg.api_key:
            kwargs["api_key"] = self.cfg.api_key
        if self.cfg.api_base:
            kwargs["api_base"] = self.cfg.api_base
        resp = litellm.completion(**kwargs)
        return resp["choices"][0]["message"]["content"]

    def complete_json(self, system: str, user: str) -> dict | list:
        """Ask for JSON and parse it defensively (models wrap it in prose/fences)."""
        raw = self.complete(system + "\nRespond with JSON only.", user)
        return _extract_json(raw)


def _extract_json(text: str) -> dict | list:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"(\{.*\}|\[.*\])", text, re.S)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass
    return {}


class _MockModel:
    """A deterministic stand-in. Returns plausible, safe, structured answers so
    the orchestration can be exercised end-to-end without a provider."""

    @staticmethod
    def respond(system: str, user: str) -> str:
        s = (system + user).lower()
        if "payload" in s and "xss" in s:
            return json.dumps({"payloads": ["<qnx>", "\"'><qnx>"], "marker": "qnx"})
        if "payload" in s and "sql" in s:
            return json.dumps({"payloads": ["'", "' OR '1'='1", "1;--"], "marker": "sql"})
        if "reproduce" in s or "validate" in s:
            # Conservative validator: default to NOT confirmed unless proof given.
            return json.dumps({"confirmed": False, "reason": "mock: no deterministic proof available"})
        return json.dumps({"ok": True})
