#!/usr/bin/env python3
"""
ssrf_oob_listener.py — Out-of-band SSRF callback listener
Listens on 127.0.0.1:9999. Any HTTP request logs to listener/callbacks.log.
Run in a separate terminal.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import os

LOG_DIR = "listener"
LOG_FILE = os.path.join(LOG_DIR, "callbacks.log")
os.makedirs(LOG_DIR, exist_ok=True)

class CallbackHandler(BaseHTTPRequestHandler):
    def _log(self, method):
        ts = datetime.utcnow().isoformat()
        line = f"{ts} | {method} {self.path} | UA={self.headers.get('User-Agent','?')}\n"
        with open(LOG_FILE, "a") as f:
            f.write(line)
        print(f"[CALLBACK] {line.strip()}")

    def do_GET(self):
        self._log("GET")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK - callback received")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self._log(f"POST (body={len(body)}B)")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):
        pass  # silence default Apache-style logging

if __name__ == "__main__":
    port = 9999
    server = HTTPServer(("127.0.0.1", port), CallbackHandler)
    print(f"[*] OOB listener on http://127.0.0.1:{port}")
    print(f"[*] Callbacks logged to {LOG_FILE}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Listener stopped")
