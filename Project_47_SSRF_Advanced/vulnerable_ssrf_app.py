#!/usr/bin/env python3
"""
vulnerable_ssrf_app.py — Enhanced SSRF target for Project #47
FOR LOCAL TESTING ONLY.

Endpoints:
  GET  /fetch?url=...        — fetch any URL (VULNERABLE)
  POST /fetch                — same, body={"url": ...}
  GET  /redirect?to=...      — 302 redirect (for redirect bypass test)
  GET  /internal/secret      — internal-only data
  GET  /                     — info page

Run: python vulnerable_ssrf_app.py
"""
from flask import Flask, request, jsonify, redirect, Response
import requests
import logging

app = Flask(__name__)

logging.basicConfig(
    filename="ssrf_attempts.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
)

INTERNAL_SECRET = "INTERNAL_SECRET_DATA: admin_token=abc123xyz\n"

@app.route("/")
def home():
    return """<html><body>
    <h1>Vulnerable SSRF Lab (Project #47)</h1>
    <h2>GET /fetch?url=...</h2>
    <pre>curl 'http://127.0.0.1:8000/fetch?url=http://127.0.0.1:8000/internal/secret'</pre>
    <h2>POST /fetch  body: {"url": "..."}</h2>
    <h2>GET /redirect?to=...</h2>
    </body></html>"""

@app.route("/internal/secret")
def internal_secret():
    return Response(INTERNAL_SECRET, mimetype="text/plain")

@app.route("/redirect")
def redirect_endpoint():
    """Simple open redirect — used to test redirect-based SSRF bypass."""
    target = request.args.get("to", "http://127.0.0.1:8000/internal/secret")
    return redirect(target, code=302)

@app.route("/fetch", methods=["GET", "POST"])
def fetch():
    """
    VULNERABLE: no validation of URL, fetches anything.
    Supports GET (?url=...) and POST ({"url": ...}).
    """
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        url = data.get("url", "")
    else:
        url = request.args.get("url", "")

    if not url:
        return jsonify({"error": "missing url parameter"}), 400

    logging.info(f"SSRF_ATTEMPT url={url} from={request.remote_addr}")

    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
        return Response(
            f"[FETCHED {url}]\nStatus: {r.status_code}\n\n{r.text}",
            mimetype="text/plain",
        )
    except requests.exceptions.Timeout:
        return Response(f"[TIMEOUT] {url} took too long\n",
                        mimetype="text/plain", status=504)
    except requests.exceptions.ConnectionError as e:
        return Response(f"[CONN_ERROR] {e}\n",
                        mimetype="text/plain", status=502)
    except Exception as e:
        return Response(f"[ERROR] {type(e).__name__}: {e}\n",
                        mimetype="text/plain", status=500)

if __name__ == "__main__":
    print("[*] Vulnerable SSRF app on http://127.0.0.1:8000")
    print("[*]   GET  /fetch?url=...")
    print("[*]   POST /fetch  (body: {\"url\": ...})")
    print("[*]   GET  /redirect?to=...")
    print("[*]   GET  /internal/secret")
    app.run(host="127.0.0.1", port=8000, debug=False, threaded=True)
