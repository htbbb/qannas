"""Lightweight recon: fetch a page, extract links and forms, map endpoints.

Deliberately simple and dependency-free (regex over HTML) so it runs anywhere.
For production coverage, wire in a real crawler/headless browser and the
nuclei hook in nuclei.py — the blackboard interface stays the same.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs

from .http import HttpTool

_LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
_ACTION_RE = re.compile(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>', re.I)
_INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.I)


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).hostname == urlparse(b).hostname


class ReconTool:
    def __init__(self, http: HttpTool) -> None:
        self.http = http

    def crawl(self, base_url: str, max_pages: int = 20) -> list[dict]:
        """Return a list of discovered endpoints: {url, method, params}."""
        seen: set[str] = set()
        queue: list[str] = [base_url]
        endpoints: list[dict] = []

        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                resp = self.http.get(url)
            except Exception:
                continue

            params = list(parse_qs(urlparse(url).query).keys())
            endpoints.append({"url": url, "method": "GET", "params": params})

            html = resp.text
            for href in _LINK_RE.findall(html):
                nxt = urljoin(url, href)
                if nxt.startswith(("http://", "https://")) and _same_host(base_url, nxt):
                    if nxt not in seen:
                        queue.append(nxt)

            for action in _ACTION_RE.findall(html):
                form_url = urljoin(url, action)
                if _same_host(base_url, form_url):
                    inputs = _INPUT_RE.findall(html)
                    endpoints.append({"url": form_url, "method": "POST", "params": inputs})

        # dedupe by (method, url)
        uniq: dict[tuple, dict] = {}
        for e in endpoints:
            uniq[(e["method"], e["url"])] = e
        return list(uniq.values())
