"""Web dashboard: a small JSON API plus a static single-page UI, standard library only."""

import json
import mimetypes
import re
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from security.events import SEVERITY_RANK

STATIC_DIR = Path(__file__).resolve().parent / "static"
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
}


def make_handler(engine):
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "CyberShield"

        def log_message(self, fmt, *args):
            pass  # keep the terminal quiet; security events have their own log

        def _send(self, status, body, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload, status=HTTPStatus.OK):
            self._send(status, json.dumps(payload, default=str).encode(), "application/json")

        def _static(self, rel_path):
            target = (STATIC_DIR / rel_path).resolve()
            if STATIC_DIR not in target.parents or not target.is_file():
                return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self._send(HTTPStatus.OK, target.read_bytes(), ctype)

        def do_GET(self):
            url = urlparse(self.path)
            query = parse_qs(url.query)
            if url.path in ("/", "/index.html"):
                return self._static("index.html")
            if url.path.startswith("/static/"):
                return self._static(url.path[len("/static/"):])
            if url.path == "/api/state":
                return self._json(engine.get_state())
            if url.path == "/api/alerts":
                severity = query.get("severity", ["LOW"])[0].upper()
                if severity not in SEVERITY_RANK:
                    return self._json({"error": "invalid severity"}, HTTPStatus.BAD_REQUEST)
                try:
                    limit = max(1, min(500, int(query.get("limit", ["100"])[0])))
                except ValueError:
                    return self._json({"error": "invalid limit"}, HTTPStatus.BAD_REQUEST)
                module = query.get("module", [None])[0]
                return self._json(engine.db.recent_events(limit=limit, min_severity=severity, module=module))
            if url.path == "/api/approvals":
                return self._json({"pending": engine.approvals.pending(), "recent": engine.approvals.recent()})
            if url.path == "/api/health":
                return self._json({"ok": True})
            return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self):
            # A custom header cannot be sent cross-site without a CORS preflight, which we never
            # approve, so other websites open in the browser cannot trigger actions here.
            if self.headers.get("X-CyberShield") != "1":
                return self._json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
            path = urlparse(self.path).path
            if path == "/api/files/rebaseline":
                ok = engine.rebaseline_files()
                return self._json({"ok": ok}, HTTPStatus.OK if ok else HTTPStatus.CONFLICT)
            match = re.fullmatch(r"/api/approvals/(\d+)", path)
            if match:
                return self._decide(int(match.group(1)))
            return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def _decide(self, req_id):
            try:
                length = min(int(self.headers.get("Content-Length") or 0), 1024)
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._json({"error": "invalid JSON"}, HTTPStatus.BAD_REQUEST)
            decision = body.get("decision") if isinstance(body, dict) else None
            if decision not in ("allow", "rewind"):
                return self._json({"error": "decision must be 'allow' or 'rewind'"}, HTTPStatus.BAD_REQUEST)
            result = engine.approvals.decide(req_id, decision == "allow", source="dashboard")
            if result is None:
                return self._json({"error": "unknown request"}, HTTPStatus.NOT_FOUND)
            return self._json(result)

    return DashboardHandler


def create_server(engine, host="127.0.0.1", port=8080):
    server = ThreadingHTTPServer((host, port), make_handler(engine))
    server.daemon_threads = True
    return server


def serve_in_background(engine, host="127.0.0.1", port=8080):
    server = create_server(engine, host, port)
    thread = threading.Thread(target=server.serve_forever, name="dashboard", daemon=True)
    thread.start()
    return server, thread
