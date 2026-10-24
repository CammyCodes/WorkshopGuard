"""Test webhook receiver: logs every alert WorkshopGuard posts, and lists them at GET /."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

received = []


class H(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
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
