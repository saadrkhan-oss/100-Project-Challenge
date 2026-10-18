#!/usr/bin/env python3
"""
vulnerable_pickle_app.py — Vulnerable Flask pickle deserialization target
FOR LOCAL TESTING ONLY.
"""
from flask import Flask, request, Response
import pickle
import base64
import logging

app = Flask(__name__)
logging.basicConfig(filename="pickle_attempts.log", level=logging.INFO,
                    format="%(asctime)s | %(message)s")

@app.route("/")
def home():
    return "<h1>Vulnerable Pickle App</h1><p>POST base64-encoded pickle to /deserialize</p>"

@app.route("/deserialize", methods=["POST"])
def deserialize():
    raw = request.data
    logging.info(f"PICKLE_ATTEMPT received {len(raw)} bytes")

    try:
        decoded = base64.b64decode(raw)
        obj = pickle.loads(decoded)   # <-- VULNERABLE
        return Response(f"Deserialized: {type(obj).__name__}\n", mimetype="text/plain")
    except Exception as e:
        return Response(f"Error: {type(e).__name__}: {e}\n",
                        mimetype="text/plain", status=500)

if __name__ == "__main__":
    print("[*] Vulnerable Pickle app on http://127.0.0.1:5001/deserialize")
    app.run(host="127.0.0.1", port=5001, debug=False)
