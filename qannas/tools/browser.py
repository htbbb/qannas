"""Headless-browser engine (Playwright) — SPA recon + DOM XSS oracle.

This is the coverage leap for JavaScript apps. A regex crawler sees only the
HTML the server returns; a real browser renders the SPA, follows client-side
routes, and — crucially — we hook the network layer to capture every XHR/fetch
the app makes, which reveals the REST surface automatically (no hand-written
endpoint list needed).

Scope is enforced inside the browser too: a request interceptor aborts any
request whose host is not authorized, so rendering a page can never cause
traffic to go off-scope. That is stronger than a plain headless crawler.

Playwright is an optional dependency. If it (or its Chromium) is missing,
`available()` returns False and callers fall back to the HTTP crawler.
"""
from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..scope import ScopeGuard


def available() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        return False
    return True


class Browser:
    def __init__(self, guard: ScopeGuard, headless: bool = True) -> None:
        self.guard = guard
        self._pw = None
        self._browser = None
        self.headless = headless

    def __enter__(self) -> "Browser":
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        except Exception:
            pass

    def _new_context(self):
        ctx = self._browser.new_context(ignore_https_errors=True,
                                        user_agent="Qannas/0.5 (authorized-security-testing)")
        # Scope gate: abort any request to a host we are not authorized to touch.
        def route(r):
            try:
                if self.guard.is_authorized(r.request.url):
                    r.continue_()
                else:
                    r.abort()
            except Exception:
                r.abort()
        ctx.route("**/*", route)
        return ctx

    # ---- SPA recon -------------------------------------------------------
    def crawl(self, base_url: str, max_pages: int = 15, settle_ms: int = 1500) -> list[dict]:
        """Render the app and return endpoints: rendered links/forms PLUS every
        XHR/fetch the app issued (the real API surface)."""
        self.guard.check(base_url)
        found: dict[tuple, dict] = {}
        api_hits: set[tuple] = set()
        ctx = self._new_context()
        page = ctx.new_page()

        def on_request(req):
            if req.resource_type in ("xhr", "fetch") and self.guard.is_authorized(req.url):
                params = list(parse_qs(urlparse(req.url).query).keys())
                api_hits.add((req.method, req.url))
                found[(req.method, req.url)] = {"url": req.url, "method": req.method, "params": params}
        page.on("request", on_request)

        seen: set[str] = set()
        queue = [base_url]
        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            try:
                page.goto(url, wait_until="networkidle", timeout=15000)
                page.wait_for_timeout(settle_ms)
            except Exception:
                continue
            # record the page itself
            params = list(parse_qs(urlparse(url).query).keys())
            found[("GET", url)] = {"url": url, "method": "GET", "params": params}
            # rendered links (same host)
            try:
                hrefs = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)")
            except Exception:
                hrefs = []
            for h in hrefs:
                if self.guard.is_authorized(h) and urlparse(h).hostname == urlparse(base_url).hostname:
                    if h not in seen and len(seen) + len(queue) < max_pages:
                        queue.append(h)
            # forms -> endpoints with input names
            try:
                forms = page.eval_on_selector_all(
                    "form", "els => els.map(f => ({action: f.action, method: (f.method||'GET').toUpperCase(),"
                    " inputs: Array.from(f.querySelectorAll('[name]')).map(i=>i.name)}))")
            except Exception:
                forms = []
            for fm in forms:
                a = fm.get("action") or url
                if self.guard.is_authorized(a):
                    found[(fm.get("method", "GET"), a)] = {
                        "url": a, "method": fm.get("method", "GET"), "params": fm.get("inputs", [])}

        ctx.close()
        return list(found.values())

    # ---- DOM XSS oracle --------------------------------------------------
    def check_executes(self, poc_url: str) -> tuple[bool, str]:
        """Independent replay: navigate a single PoC URL in a fresh context and
        report whether script executed. Used by the validator."""
        self.guard.check(poc_url)
        ctx = self._new_context()
        page = ctx.new_page()
        fired = {"v": False, "via": ""}
        page.on("dialog", lambda d: (fired.update(v=True, via="dialog"), d.dismiss()))
        try:
            page.add_init_script("window.__QXSS__=null")
            page.goto(poc_url, wait_until="networkidle", timeout=15000)
            page.wait_for_timeout(800)
            flag = page.evaluate("window.__QXSS__")
        except Exception:
            flag = None
        finally:
            try:
                ctx.close()
            except Exception:
                pass
        if flag == "qnx" or fired["v"]:
            return True, "JS executed on replay (" + (fired["via"] or "marker") + ")"
        return False, "no execution on replay"

    def probe_dom_xss(self, url: str, param: str, payloads: list[str]) -> tuple[bool, str, str]:
        """Inject marker payloads into `param`, render, and detect actual
        execution (onerror/onload/dialog), not mere reflection. Returns
        (hit, evidence, poc_url)."""
        self.guard.check(url)
        ctx = self._new_context()
        page = ctx.new_page()
        fired = {"v": False, "via": ""}
        page.on("dialog", lambda d: (fired.update(v=True, via="dialog:" + d.message), d.dismiss()))
        hit_url = ""
        try:
            for pl in payloads:
                test_url = _with_param(url, param, pl)
                try:
                    page.add_init_script("window.__QXSS__=null")
                    page.goto(test_url, wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(800)
                    flag = page.evaluate("window.__QXSS__")
                except Exception:
                    continue
                if flag == "qnx" or fired["v"]:
                    ctx.close()
                    ev = "JS executed in DOM (" + (fired["via"] or "onerror/onload marker") + ")"
                    return True, ev, f"GET {test_url}"
                hit_url = test_url
        finally:
            try:
                ctx.close()
            except Exception:
                pass
        return False, "", hit_url


def _with_param(url: str, key: str, value: str) -> str:
    parts = urlparse(url)
    q = parse_qs(parts.query)
    q[key] = [value]
    return urlunparse(parts._replace(query=urlencode(q, doseq=True)))
