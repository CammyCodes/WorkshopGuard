"""Small read-only dashboard + JSON API. Bound to localhost by docker-compose unless you change the port mapping."""

from __future__ import annotations

import html
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__, games
from .db import DB
from .pipeline import details_json

log = logging.getLogger(__name__)
E = html.escape

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1c1c1a;--mut:#6b6b66;--line:#e4e4df;--mal:#d93d42;--sus:#c77c00;--ok:#2f8f5b;
--chip:#efefea;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--card:#1d1d1b;--fg:#ececea;--mut:#9d9d97;--line:#2e2e2b;
--mal:#ff6b6f;--sus:#f0a73a;--ok:#4cc38a;--chip:#2a2a27;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,
"Segoe UI",sans-serif}main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}a{color:inherit}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}.mut{color:var(--mut)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin-top:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.num{font-size:26px;font-weight:650;font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;
overflow:hidden}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);font-weight:600}
tr:last-child td{border-bottom:0}.v{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;
font-weight:650;background:var(--chip)}.v.malicious{color:#fff;background:var(--mal)}.v.suspicious{color:#1c1c1a;
background:var(--sus)}.v.clean{color:var(--ok)}.sev{font-size:11px;font-weight:700;text-transform:uppercase}
.sev.critical{color:var(--mal)}.sev.high{color:var(--mal)}.sev.medium{color:var(--sus)}.sev.low,.sev.info{color:var(--mut)}
code{font:12px/1.4 ui-monospace,Consolas,monospace;background:var(--chip);padding:1px 5px;border-radius:5px;
word-break:break-all}nav a{margin-right:12px;font-size:14px}.wrap{overflow-x:auto}
"""


def _page(title: str, body: str) -> bytes:
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport "
            f"content='width=device-width,initial-scale=1'><title>{E(title)}</title><style>{CSS}</style>"
            f"<meta http-equiv=refresh content=120></head><body><main>{body}"
            f"<p class=mut style='margin-top:40px;font-size:13px'>WorkshopGuard {__version__}. Files are scanned, "
            f"never run. A flag is a reason to look closer, not proof.</p></main></body></html>").encode()


def _ago(ts) -> str:
    if not ts:
        return "-"
    s = int(time.time() - ts)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return f"{s // n}{unit} ago"
    return "just now"


def _game(appid: int) -> str:
    return games.profile_for(appid).name


class Dashboard:
    def __init__(self, db: DB, host: str, port: int):
        self.db, self.host, self.port = db, host, port

    def start(self) -> threading.Thread:
        db = self.db

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src https:")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                u = urlparse(self.path)
                qs = {k: v[0] for k, v in parse_qs(u.query).items()}
                try:
                    if u.path == "/healthz":
                        return self._send(200, b"ok", "text/plain")
                    if u.path == "/api/stats":
                        return self._json({"stats": db.stats(), "last_poll": db.get("last_poll")})
                    if u.path == "/api/items":
                        return self._json([details_json(r) for r in _items(db, qs)])
                    if u.path.startswith("/item/"):
                        _, _, appid, id_ = u.path.split("/")[:4]
                        row = db.item(int(appid), id_)
                        return self._send(200 if row else 404, _item_page(row) if row else _page("Not found", "<h1>Not found</h1>"))
                    if u.path == "/":
                        return self._send(200, _index(db, qs))
                    return self._send(404, _page("Not found", "<h1>Not found</h1>"))
                except Exception as e:  # noqa: BLE001
                    log.exception("dashboard error")
                    return self._send(500, _page("Error", f"<h1>Error</h1><p>{E(str(e))}</p>"))

            def _json(self, obj):
                self._send(200, json.dumps(obj, default=str).encode(), "application/json")

        srv = ThreadingHTTPServer((self.host, self.port), H)
        t = threading.Thread(target=srv.serve_forever, daemon=True, name="dashboard")
        t.start()
        log.info("Dashboard on http://%s:%s", self.host, self.port)
        return t


def _items(db: DB, qs: dict):
    where, args = ["1=1"], []
    if qs.get("verdict"):
        where.append("verdict=? AND status='scanned'")
        args.append(qs["verdict"])
    if qs.get("status"):
        where.append("status=?")
        args.append(qs["status"])
    if qs.get("appid", "").isdigit():
        where.append("appid=?")
        args.append(int(qs["appid"]))
    limit = min(int(qs.get("limit", "200") or 200), 2000)
    return db.q(f"SELECT * FROM items WHERE {' AND '.join(where)} ORDER BY COALESCE(scanned_at,first_seen) DESC LIMIT ?",
                *args, limit)


def _row(r) -> str:
    v = r["verdict"] if r["status"] == "scanned" else r["status"]
    tag = " <span class=v>TEST</span>" if r["is_test"] else ""
    err = f"<div class=mut style='font-size:13px'>{E((r['error'] or '')[:160])}</div>" if r["error"] else ""
    return (f"<tr><td><span class='v {E(v or '')}'>{E(v or '')}</span>{tag}</td>"
            f"<td><a href='/item/{r['appid']}/{E(r['id'])}'>{E(r['title'] or r['id'])}</a>{err}</td>"
            f"<td>{E(_game(r['appid']))}</td><td>{r['score'] if r['score'] is not None else '-'}</td>"
            f"<td class=mut>{_ago(r['scanned_at'])}</td></tr>")


def _table(rows) -> str:
    if not rows:
        return "<p class=mut>Nothing here yet.</p>"
    return ("<div class=wrap><table><tr><th>Verdict</th><th>Item</th><th>Game</th><th>Score</th><th>When</th></tr>"
            + "".join(_row(r) for r in rows) + "</table></div>")


def _index(db: DB, qs: dict) -> bytes:
    stats = db.stats()
    cards = []
    for appid, s in sorted(stats.items()):
        cards.append(
            f"<div class=card><div class=mut>{E(_game(appid))}</div><div class=num>{s.get('clean', 0)} "
            f"<span class=mut style='font-size:14px;font-weight:400'>clean</span></div>"
            f"<div><a href='/?appid={appid}&verdict=malicious'>{s.get('malicious', 0)} malicious</a> · "
            f"<a href='/?appid={appid}&verdict=suspicious'>{s.get('suspicious', 0)} suspicious</a></div>"
            f"<div class=mut style='font-size:13px'>{s.get('queued', 0) + s.get('scanning', 0)} waiting · "
            f"{s.get('error', 0)} errors · {s.get('skipped', 0)} skipped"
            + (f" · {s['test']} test" if s.get("test") else "") + "</div></div>")
    flagged = db.q("""SELECT * FROM items WHERE status='scanned' AND verdict IN ('malicious','suspicious')
                      ORDER BY CASE verdict WHEN 'malicious' THEN 0 ELSE 1 END, scanned_at DESC LIMIT 100""")
    filtered = bool(qs)
    body = (f"<h1>WorkshopGuard</h1><div class=mut>Last check {_ago(db.get('last_poll'))}</div>"
            f"<nav style='margin-top:8px'><a href='/'>Overview</a><a href='/?status=error'>Errors</a>"
            f"<a href='/?status=skipped'>Skipped</a><a href='/api/items?verdict=malicious'>JSON</a></nav>"
            f"<div class=grid>{''.join(cards) or '<div class=card>No items yet. The first check runs at start-up.</div>'}</div>")
    if filtered:
        body += f"<h2>Filtered</h2>{_table(_items(db, qs))}"
    else:
        body += f"<h2>Flagged</h2>{_table(flagged)}<h2>Recent activity</h2>{_table(_items(db, {'limit': '60'}))}"
    return _page("WorkshopGuard", body)


def _item_page(r) -> bytes:
    d = details_json(r)
    f_rows = "".join(
        f"<tr><td><span class='sev {E(f['severity'])}'>{E(f['severity'])}</span></td><td>{E(f['description'])}"
        f"<div class=mut style='font-size:12px'>{E(f['rule'])}</div>"
        + "".join(f"<div><code>{E(str(e))}</code></div>" for e in f.get("evidence", [])[:6])
        + f"</td><td><code>{E(f.get('file') or '')}</code></td></tr>"
        for f in sorted(d["findings"], key=lambda f: ["critical", "high", "medium", "low", "info"].index(f["severity"])))
    eng_rows = ""
    for e in d["details"].get("engines", {}).values():
        res = ("<span class='sev critical'>flagged</span>" if e["detections"] else
               f"<span class=mut>{e['errors']} error(s)</span>" if e["errors"] else
               "<span class=mut>nothing to check</span>" if not e["files"] else
               "<span class=mut>never seen these files</span>" if e["unknown"] == e["files"] else
               f"clean <span class=mut>({e['notes']} worth a look)</span>" if e.get("notes") else "clean")
        eng_rows += f"<tr><td>{E(e['label'])}</td><td>{e['files']}</td><td>{res}</td></tr>"
    hashes = "".join(f"<tr><td><code>{E(k)}</code></td><td><code>{E(v)}</code></td></tr>"
                     for k, v in list(d["details"].get("sha256", {}).items())[:300])
    v = r["verdict"] if r["status"] == "scanned" else r["status"]
    url = f"https://steamcommunity.com/sharedfiles/filedetails/?id={r['id']}"
    body = (f"<p><a href='/'>&larr; Overview</a></p><h1>{E(r['title'] or r['id'])}</h1>"
            f"<p><span class='v {E(v or '')}'>{E(v or '')}</span> score {r['score'] if r['score'] is not None else '-'}"
            f"{' · <b>TEST (fake detection planted)</b>' if r['is_test'] else ''}</p>"
            f"<p class=mut>{E(_game(r['appid']))} · <a href='{E(url)}'>Workshop page</a> · "
            f"<a href='https://steamcommunity.com/profiles/{E(r['creator'] or '')}'>uploader</a> · "
            f"version {r['scanned_version'] or r['time_updated']} · scanned {_ago(r['scanned_at'])} · "
            f"{d['details'].get('files', '?')} files</p>"
            + (f"<p class=mut>{E(r['error'])}</p>" if r["error"] else "")
            + (f"<h2>Engines</h2><div class=wrap><table><tr><th>Engine</th><th>Files</th><th>Result</th></tr>"
               f"{eng_rows}</table></div>" if eng_rows else "")
            + f"<h2>Findings</h2>" + (f"<div class=wrap><table><tr><th>Severity</th><th>What</th><th>File</th></tr>"
                                       f"{f_rows}</table></div>" if f_rows else "<p class=mut>None.</p>")
            + (f"<h2>Files (SHA-256)</h2><div class=wrap><table>{hashes}</table></div>" if hashes else ""))
    return _page(r["title"] or r["id"], body)
