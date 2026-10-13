#!/usr/bin/env python3
"""
vulnerable_xxe_app.py — Deliberately vulnerable XXE target
FOR LOCAL TESTING ONLY.
"""
from flask import Flask, request, Response
from lxml import etree
import defusedxml.ElementTree as defused_et
import logging

app = Flask(__name__)

logging.basicConfig(
    filename="xxe_attempts.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
)

@app.route("/")
def home():
    return """<html><body>
    <h1>XXE Test Target</h1>
    <p>POST XML to:</p>
    <ul>
      <li><code>/api/xml-vulnerable</code> - XXE vulnerable (lxml)</li>
      <li><code>/api/xml-safe</code> - safe (defusedxml)</li>
    </ul>
    </body></html>"""

@app.route("/api/xml-vulnerable", methods=["POST"])
def xml_vulnerable():
    data = request.data
    logging.info(f"VULN_ENDPOINT received {len(data)} bytes")
    try:
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
            no_network=False,
        )
        tree = etree.fromstring(data, parser)
        text = tree.text or ""
        return Response(f"[PARSED OK]\n{text}\n", mimetype="text/plain")
    except etree.XMLSyntaxError as e:
        return Response(f"[XML ERROR] {e}\n", mimetype="text/plain", status=400)
    except Exception as e:
        return Response(f"[ERROR] {type(e).__name__}: {e}\n",
                        mimetype="text/plain", status=500)

@app.route("/api/xml-safe", methods=["POST"])
def xml_safe():
    data = request.data
    try:
        root = defused_et.fromstring(data)
        return Response(f"[SAFE PARSE OK]\n{root.text or ''}\n",
                        mimetype="text/plain")
    except Exception as e:
        return Response(f"[DEFUSED BLOCKED] {type(e).__name__}: {e}\n",
                        mimetype="text/plain", status=400)

if __name__ == "__main__":
    print("[*] Vulnerable XXE app on http://127.0.0.1:5000")
    print("[*]   POST /api/xml-vulnerable   (XXE vulnerable)")
    print("[*]   POST /api/xml-safe         (defusedxml)")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
