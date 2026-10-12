#!/usr/bin/env python3
"""
vulnerable_app.py — Deliberately vulnerable SSRF target
FOR LOCAL TESTING ONLY. Do NOT expose to the internet.
Run: python vulnerable_app.py
Then attack: http://127.0.0.1:8000/fetch?url=http://example.com
"""

from flask import Flask, request, Response
import requests

app = Flask(__name__)

# Simulated internal service (only reachable from this host)
@app.route("/internal/secret")
def internal_secret():
    return "INTERNAL_SECRET_DATA: admin_token=abc123xyz\n"

@app.route("/internal/admin")
def internal_admin():
    return "ADMIN PANEL - top secret\n"

@app.route("/fetch")
def fetch():
    """
    VULNERABLE ENDPOINT — takes a URL, fetches it, returns response.
    Classic SSRF: no validation of the URL.
    """
    url = request.args.get("url", "")
    if not url:
        return "Usage: /fetch?url=http://example.com"

    try:
        # The vulnerability: blindly fetching whatever URL is given
        r = requests.get(url, timeout=5, allow_redirects=True)
        return Response(
            f"[FETCHED {url}]\n\n{r.text}",
            mimetype="text/plain"
        )
    except requests.exceptions.Timeout:
        return f"[TIMEOUT] {url} took too long\n"
    except Exception as e:
        return f"[ERROR] {type(e).__name__}: {e}\n"

if __name__ == "__main__":
    print("[*] Vulnerable app running on http://127.0.0.1:8000")
    print("[*] Try: http://127.0.0.1:8000/fetch?url=http://127.0.0.1:8000/internal/secret")
    app.run(host="127.0.0.1", port=8000, debug=False)