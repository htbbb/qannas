"""Technology fingerprinting (recon skill).

Infers server, framework, language and CMS from response headers and body
markers — the kind of context Strix's reconnaissance/technologies skills give
the agent. Cheap, passive, and useful for steering which vuln classes matter.
"""
from __future__ import annotations

import re

_HEADER_HINTS = {
    "server": "server",
    "x-powered-by": "powered-by",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "generator",
    "via": "proxy",
}

_BODY_MARKERS = [
    ("Angular", r"ng-version|_nghost|angular"),
    ("React", r"data-reactroot|__REACT_DEVTOOLS|react-dom"),
    ("Vue.js", r"data-v-[0-9a-f]{8}|__vue__"),
    ("WordPress", r"/wp-content/|wp-json|wordpress"),
    ("Drupal", r"Drupal\.settings|/sites/default/files"),
    ("Laravel", r"laravel_session|csrf-token"),
    ("Django", r"csrfmiddlewaretoken|__admin_media_prefix__"),
    ("Express", r"powered-by.?express"),
    ("jQuery", r"jquery[.-]"),
]


def fingerprint(headers: dict, body: str) -> list[str]:
    found: list[str] = []
    for h, label in _HEADER_HINTS.items():
        if h in headers and headers[h]:
            found.append(f"{label}: {headers[h]}")
    low = (body or "")[:200000]
    for name, pat in _BODY_MARKERS:
        if re.search(pat, low, re.I):
            found.append(name)
    # dedupe, preserve order
    seen, out = set(), []
    for f in found:
        if f.lower() not in seen:
            seen.add(f.lower())
            out.append(f)
    return out
