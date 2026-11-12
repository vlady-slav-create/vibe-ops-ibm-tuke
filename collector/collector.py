"""Stub for the real endpoint: accepts POST /ingest, prints the JSON to the log and answers 200.
Later replaced by the real AWS endpoint (the ENDPOINT_URL variable in mitmproxy)."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            print(json.dumps(json.loads(body), indent=2, ensure_ascii=False), flush=True)
        except ValueError:
            print("not JSON:", body[:200], flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"received"}')

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("collector listening on :9000", flush=True)
    HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
