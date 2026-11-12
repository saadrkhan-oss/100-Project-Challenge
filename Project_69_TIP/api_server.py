#!/usr/bin/env python3
"""
api_server.py — TIP REST API (Project #69)
Endpoints: /iocs, /iocs/<id>, /campaigns, /actors, /stats
"""
import os, json
from flask import Flask, jsonify, abort

app = Flask(__name__)
MOCK_DIR = "mock"

def load_iocs():
    with open(os.path.join(MOCK_DIR, "iocs.json")) as f:
        return json.load(f)["iocs"]

@app.route("/")
def home():
    return jsonify({
        "service": "TIP API",
        "version": "1.0",
        "endpoints": ["/iocs", "/iocs/<id>", "/campaigns", "/actors", "/stats"],
    })

@app.route("/iocs")
def list_iocs():
    iocs = load_iocs()
    return jsonify({"count": len(iocs), "iocs": iocs})

@app.route("/iocs/<ioc_id>")
def get_ioc(ioc_id):
    iocs = load_iocs()
    for i in iocs:
        if i["id"] == ioc_id:
            return jsonify(i)
    abort(404)

@app.route("/campaigns")
def list_campaigns():
    iocs = load_iocs()
    campaigns = {}
    for i in iocs:
        c = i["campaign"]
        campaigns.setdefault(c, []).append(i["value"])
    return jsonify({"count": len(campaigns), "campaigns": campaigns})

@app.route("/actors")
def list_actors():
    iocs = load_iocs()
    actors = {}
    for i in iocs:
        a = i["actor"]
        actors.setdefault(a, []).append(i["value"])
    return jsonify({"count": len(actors), "actors": actors})

@app.route("/stats")
def stats():
    iocs = load_iocs()
    by_type = {}
    by_risk = {}
    for i in iocs:
        by_type[i["type"]] = by_type.get(i["type"], 0) + 1
        sev = "CRITICAL" if i["cvss"] >= 9.0 else "HIGH" if i["cvss"] >= 7.0 else "MEDIUM"
        by_risk[sev] = by_risk.get(sev, 0) + 1
    return jsonify({
        "total_iocs": len(iocs),
        "by_type": by_type,
        "by_risk": by_risk,
    })

if __name__ == "__main__":
    print("[*] TIP API on http://127.0.0.1:5003")
    print("[*] Endpoints: /iocs, /iocs/<id>, /campaigns, /actors, /stats")
    app.run(host="127.0.0.1", port=5003, debug=False)
