"""Ingest endpoints from an API contract or a plain list.

Point Qannas at an OpenAPI/Swagger file (or a simple endpoints.txt) and it
tests every declared endpoint directly, instead of trying to discover a SPA's
surface by crawling rendered HTML it can't see. This is the single biggest
coverage win against JS apps (Angular/React) whose real attack surface is the
REST API, not the index page.

Formats:
  * OpenAPI/Swagger JSON or YAML (dict with a top-level "paths")
  * Plain text: one entry per line, "METHOD url" or "url"; query params in the
    URL are picked up as testable parameters.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs

import yaml


def load(path: str, base_url: str | None = None) -> list[dict]:
    text = Path(path).read_text()
    stripped = text.lstrip()
    if stripped.startswith("{") or "openapi" in text[:200] or "swagger" in text[:200]:
        try:
            data = yaml.safe_load(text)
            if isinstance(data, dict) and "paths" in data:
                return _from_openapi(data, base_url)
        except yaml.YAMLError:
            pass
    return _from_lines(text, base_url)


def _from_openapi(data: dict, base_url: str | None) -> list[dict]:
    base = base_url
    if not base:
        servers = data.get("servers") or []
        if servers and isinstance(servers[0], dict):
            base = servers[0].get("url")
    base = base or ""
    endpoints: list[dict] = []
    for raw_path, item in (data.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        url = urljoin(base.rstrip("/") + "/", raw_path.lstrip("/")) if base else raw_path
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            params = []
            if isinstance(op, dict):
                for p in op.get("parameters") or []:
                    if isinstance(p, dict) and "name" in p:
                        params.append(p["name"])
            endpoints.append({"url": url, "method": method.upper(), "params": params})
    return endpoints


def _from_lines(text: str, base_url: str | None) -> list[dict]:
    endpoints: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2 and parts[0].isalpha():
            method, url = parts[0].upper(), parts[1]
        else:
            method, url = "GET", parts[0]
        if base_url and not url.startswith(("http://", "https://")):
            url = urljoin(base_url.rstrip("/") + "/", url.lstrip("/"))
        params = list(parse_qs(urlparse(url).query).keys())
        endpoints.append({"url": url, "method": method, "params": params})
    return endpoints
