"""Minimal demo server: a portal plus a small API, so there is normal traffic too.
:8080 is deliberately without TLS (clear text), :8443 uses TLS (self-signed certificate).

Endpoints:
  GET  /                  portal page
  GET  /api/health        {"status":"ok"}
  GET  /api/schedule      schedule (public)
  GET  /api/courses       courses (public)
  GET  /api/grades        grades, needs Authorization: Bearer <token> (or weak demo ?token=<token>), otherwise 401
  POST /login             200 with a token for any non-empty username and password, 401 if empty
Anything else: 404.
"""
import json
import ssl
import threading
from urllib.parse import parse_qs, urlsplit
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX = (Path(__file__).parent / "index.html").read_bytes()

DEMO_TOKEN = "demo-token-123"

SCHEDULE = [
    {"day": "Mon", "time": "13:30", "course": "Emerging Trends in Communication Technologies", "room": "A204"},
    {"day": "Tue", "time": "09:00", "course": "Computer Networks", "room": "B101"},
    {"day": "Thu", "time": "11:00", "course": "Network Security", "room": "B203"},
]
COURSES = [
    {"code": "ETC", "name": "Emerging Trends in Communication Technologies", "credits": 4},
    {"code": "CN", "name": "Computer Networks", "credits": 6},
    {"code": "NS", "name": "Network Security", "credits": 5},
]
GRADES = [{"code": "ETC", "grade": "A"}, {"code": "CN", "grade": "B"}, {"code": "NS", "grade": "A"}]


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        payload = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        # Deliberately weak demo cookie (no Secure/HttpOnly/SameSite): sniffable and replayable by a MITM.
        if code == 200 and isinstance(obj, dict) and obj.get("token"):
            self.send_header("Set-Cookie", f"session={obj['token']}; Path=/")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(INDEX)))
            self.end_headers()
            self.wfile.write(INDEX)
        elif path == "/api/health":
            self._json(200, {"status": "ok"})
        elif path == "/api/schedule":
            self._json(200, SCHEDULE)
        elif path == "/api/courses":
            self._json(200, COURSES)
        elif path == "/api/grades":
            # Deliberately weak: token also accepted in the URL (logged, cached, sniffable).
            in_url = DEMO_TOKEN in parse_qs(urlsplit(self.path).query).get("token", [])
            if in_url or self.headers.get("Authorization") == f"Bearer {DEMO_TOKEN}":
                self._json(200, GRADES)
            else:
                self._json(401, {"status": "error", "message": "missing or invalid token"})
        else:
            self._json(404, {"status": "error", "message": "not found"})

    def do_POST(self):
        if self.path != "/login":
            self._json(404, {"status": "error", "message": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"status": "error", "message": "invalid JSON"})
            return
        user, password = body.get("username"), body.get("password")
        print(f"login attempt: user={user}", flush=True)
        # Demo: accept any non-empty username and password. 401 only if a field is empty.
        if user and password:
            self._json(200, {"status": "ok", "token": DEMO_TOKEN})
        else:
            self._json(401, {"status": "error", "message": "invalid credentials"})

    def log_message(self, *args):
        pass


def serve_https():
    """HTTPS on :8443 with a self-signed certificate, if one is mounted at /certs."""
    cert, key = Path("/certs/server.crt"), Path("/certs/server.key")
    if not (cert.exists() and key.exists()):
        print("HTTPS disabled: /certs/server.crt not found", flush=True)
        return
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    httpd = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("HTTPS on :8443", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=serve_https, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
