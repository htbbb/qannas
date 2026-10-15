"""Local web dashboard — `qannas view`.

Modelled on Strix's local viewer: every scan writes its results to disk, and
this serves them in a browser dashboard. It binds to 127.0.0.1 only and mints a
random token in the URL, so results never leave the machine. Zero external
dependencies — stdlib http.server plus one embedded HTML page.

Routes:
  GET /?t=<token>            -> the dashboard page
  GET /api/runs?t=<token>    -> list of runs (name, target, counts)
  GET /api/run/<name>?t=...  -> a run's report.json
"""
from __future__ import annotations

import json
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs


def _runs(runs_dir: Path) -> list[dict]:
    out = []
    if not runs_dir.exists():
        return out
    for d in sorted(runs_dir.iterdir(), reverse=True):
        rp = d / "report.json"
        if not rp.exists():
            continue
        try:
            rep = json.loads(rp.read_text())
        except Exception:
            continue
        s = rep.get("summary", {})
        out.append({"name": d.name, "target": rep.get("target", []),
                    "confirmed": s.get("confirmed", 0),
                    "needs_human": s.get("needs_human", 0),
                    "endpoints": s.get("endpoints", 0)})
    return out


def _make_handler(runs_dir: Path, token: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _auth(self, q) -> bool:
            return q.get("t", [""])[0] == token

        def _send(self, code, body, ctype="application/json"):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if not self._auth(q):
                return self._send(403, "forbidden", "text/plain")
            if u.path == "/":
                return self._send(200, PAGE.replace("__TOKEN__", token), "text/html")
            if u.path == "/api/runs":
                return self._send(200, json.dumps(_runs(runs_dir)))
            if u.path.startswith("/api/run/"):
                name = u.path[len("/api/run/"):]
                rp = runs_dir / name / "report.json"
                if rp.exists():
                    return self._send(200, rp.read_text())
                return self._send(404, "{}")
            return self._send(404, "not found", "text/plain")

    return Handler


def serve(runs_dir: Path, host: str = "127.0.0.1", port: int = 8787, open_browser: bool = True) -> None:
    token = secrets.token_urlsafe(16)
    httpd = HTTPServer((host, port), _make_handler(runs_dir, token))
    url = f"http://{host}:{port}/?t={token}"
    print(f"\n  Qannas dashboard: {url}")
    print(f"  Serving runs from: {runs_dir}")
    print("  Bound to localhost; the token in the URL grants access — share carefully.")
    print("  Ctrl-C to stop.\n")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Qannas Dashboard</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--dim:#8b949e;
--crit:#f85149;--high:#ff7b72;--med:#d29922;--low:#58a6ff;--info:#6e7681;--ok:#3fb950}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;
background:var(--bg);color:var(--fg)}
header{padding:16px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:14px}
header h1{font-size:18px;margin:0;letter-spacing:.5px}
header .tag{color:var(--dim);font-size:12px}
.wrap{display:grid;grid-template-columns:260px 1fr;min-height:calc(100vh - 57px)}
.side{border-right:1px solid var(--border);padding:14px;overflow:auto}
.side h2{font-size:12px;text-transform:uppercase;color:var(--dim);margin:6px 4px}
.run{padding:9px 10px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;cursor:pointer;background:var(--panel)}
.run:hover{border-color:var(--low)}.run.active{border-color:var(--ok)}
.run .t{font-weight:600;font-size:13px;word-break:break-all}
.run .m{color:var(--dim);font-size:11px;margin-top:3px}
.main{padding:20px 24px;overflow:auto}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 18px;min-width:120px}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--dim);font-size:12px}
.bar{height:10px;border-radius:5px;background:var(--border);overflow:hidden;display:flex;margin:6px 0 18px}
.bar span{display:block;height:100%}
.f{background:var(--panel);border:1px solid var(--border);border-left-width:4px;border-radius:8px;padding:14px 16px;margin-bottom:12px}
.f h3{margin:0 0 8px;font-size:14px}
.f .row{color:var(--dim);font-size:12px;margin:3px 0}
.f code{background:#0d1117;border:1px solid var(--border);padding:1px 6px;border-radius:4px;color:var(--fg);word-break:break-all}
.pill{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;font-weight:700;margin-right:6px}
.sev-critical{border-left-color:var(--crit)}.sev-high{border-left-color:var(--high)}
.sev-medium{border-left-color:var(--med)}.sev-low{border-left-color:var(--low)}.sev-info{border-left-color:var(--info)}
.p-critical{background:var(--crit);color:#fff}.p-high{background:var(--high);color:#111}
.p-medium{background:var(--med);color:#111}.p-low{background:var(--low);color:#111}.p-info{background:var(--info);color:#fff}
.muted{color:var(--dim)}h2.sec{font-size:13px;text-transform:uppercase;color:var(--dim);margin:22px 0 10px;border-bottom:1px solid var(--border);padding-bottom:6px}
</style></head>
<body>
<header><h1>🎯 QANNAS</h1><span class="tag">local scan dashboard · planner-driven · validator-gated</span></header>
<div class="wrap">
  <div class="side"><h2>Runs</h2><div id="runs"></div></div>
  <div class="main" id="main"><p class="muted">Select a run.</p></div>
</div>
<script>
const T="__TOKEN__";
const sevs=["critical","high","medium","low","info"];
const col={critical:"#f85149",high:"#ff7b72",medium:"#d29922",low:"#58a6ff",info:"#6e7681"};
async function j(u){const r=await fetch(u+(u.includes('?')?'&':'?')+'t='+T);return r.json()}
async function loadRuns(){
  const runs=await j('/api/runs');const box=document.getElementById('runs');
  if(!runs.length){box.innerHTML='<p class="muted">No runs yet.</p>';return}
  box.innerHTML='';
  runs.forEach((r,i)=>{
    const d=document.createElement('div');d.className='run'+(i==0?' active':'');
    d.innerHTML=`<div class="t">${r.name}</div><div class="m">${(r.target||[]).join(', ')}<br>${r.confirmed} confirmed · ${r.needs_human} review · ${r.endpoints} endpoints</div>`;
    d.onclick=()=>{document.querySelectorAll('.run').forEach(e=>e.classList.remove('active'));d.classList.add('active');show(r.name)};
    box.appendChild(d);
  });
  if(runs.length)show(runs[0].name);
}
function esc(s){return(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function fblock(f){
  const s=f.severity||'info';
  return `<div class="f sev-${s}">
    <h3><span class="pill p-${s}">${s.toUpperCase()}</span>${esc(f.title||f.vuln_class)}</h3>
    <div class="row"><code>${esc(f.endpoint)}</code></div>
    <div class="row">Class: ${esc(f.vuln_class)}${f.cwe?' · '+esc(f.cwe):''}${f.owasp?' · '+esc(f.owasp):''} · Confidence: ${esc(f.confidence||'')}</div>
    ${f.evidence?`<div class="row">Evidence: ${esc(f.evidence)}</div>`:''}
    ${f.poc?`<div class="row">PoC: <code>${esc(f.poc)}</code></div>`:''}
    ${f.remediation?`<div class="row">Fix: ${esc(f.remediation)}</div>`:''}
  </div>`;
}
async function show(name){
  const rep=await j('/api/run/'+name);const m=document.getElementById('main');
  const s=rep.summary||{};const bs=s.by_severity||{};
  const total=Object.values(bs).reduce((a,b)=>a+b,0)||1;
  let bar='';sevs.forEach(k=>{if(bs[k])bar+=`<span style="width:${bs[k]/total*100}%;background:${col[k]}"></span>`});
  const conf=rep.confirmed||[],nh=rep.needs_human||[];
  m.innerHTML=`
    <div class="cards">
      <div class="card"><div class="n" style="color:var(--ok)">${s.confirmed||0}</div><div class="l">Confirmed</div></div>
      <div class="card"><div class="n" style="color:var(--med)">${s.needs_human||0}</div><div class="l">Needs review</div></div>
      <div class="card"><div class="n">${s.endpoints||0}</div><div class="l">Endpoints</div></div>
      <div class="card"><div class="n" style="color:var(--dim)">${s.rejected_false_positives||0}</div><div class="l">FP filtered</div></div>
    </div>
    <div class="bar">${bar||'<span style="width:100%;background:var(--border)"></span>'}</div>
    <h2 class="sec">Confirmed findings</h2>
    ${conf.length?conf.map(fblock).join(''):'<p class="muted">None confirmed.</p>'}
    <h2 class="sec">Needs human review</h2>
    ${nh.length?nh.map(fblock).join(''):'<p class="muted">None.</p>'}`;
}
loadRuns();
</script></body></html>"""
