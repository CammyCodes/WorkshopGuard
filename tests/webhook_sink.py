"""Test receiver: logs every alert WorkshopGuard posts (GET / lists them), and pretends to be Valve's publisher
Web API (IPublishedFileService/*) so ban buttons and auto-bans can be tested without touching real Steam."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

received = []


class H(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.startswith("/IPublishedFileService/"):
            form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
            form["key"] = "***"
            received.append({"path": self.path, "steam_api": form})
            print(f"STEAM {self.path} {json.dumps(form)}", flush=True)
            out = b'{"response":{}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        body = json.loads(raw)
        received.append({"path": self.path, "body": body})
        kind = "discord" if "embeds" in body else "json"
        title = body["embeds"][0]["title"] if kind == "discord" else body.get("text")
        print(f"ALERT {self.path} [{kind}] {title}", flush=True)
        self.send_response(204)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        out = json.dumps(received, indent=1).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


HTTPServer(("0.0.0.0", 9000), H).serve_forever()
