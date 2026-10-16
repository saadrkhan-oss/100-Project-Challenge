#!/usr/bin/env python3
"""
vulnerable_nosql_app.py — Deliberately vulnerable NoSQL-injection Flask target
FOR LOCAL TESTING ONLY.

Endpoints:
  POST /api/login   — JSON body {username, password}  (VULNERABLE)
  GET  /api/users   — ?filter=<json>                  (VULNERABLE)
  GET  /api/search  — ?q=<json>                       (VULNERABLE)
  GET  /            — info page

Run: python vulnerable_nosql_app.py
"""
from flask import Flask, request, jsonify, render_template_string
import re
import time
import json as _json

app = Flask(__name__)

# ---- Mock MongoDB collection ----
USERS = [
    {"_id": 1, "username": "admin", "password": "admin123",
     "email": "admin@example.com", "role": "admin"},
    {"_id": 2, "username": "alice", "password": "alice123",
     "email": "alice@example.com", "role": "user"},
    {"_id": 3, "username": "bob",   "password": "bob123",
     "email": "bob@example.com",   "role": "user"},
]

# ---------------------------------------------------------------------------
# Mock MongoDB query evaluator
# ---------------------------------------------------------------------------
def matches(doc, query):
    """
    Evaluate a MongoDB-style query against a document.
    Supports: {field: value}, {field: {$op: ...}}, $and, $or, $where.
    """
    if not isinstance(query, dict):
        return False

    for key, val in query.items():
        if key == "$or":
            if not isinstance(val, list):
                return False
            if not any(matches(doc, sub) for sub in val):
                return False
        elif key == "$and":
            if not isinstance(val, list):
                return False
            if not all(matches(doc, sub) for sub in val):
                return False
        elif key == "$where":
            # Evaluate JS-like condition
            if not _eval_where(val, doc):
                return False
        elif key.startswith("$"):
            # unknown top-level operator
            continue
        else:
            # field-level match
            if not _field_match(doc, key, val):
                return False
    return True

def _field_match(doc, field, val):
    if field not in doc:
        # missing field: only matches with $ne, $exists
        if isinstance(val, dict):
            if "$exists" in val:
                return val["$exists"] is False
            if "$ne" in val:
                return True
        return False

    actual = doc[field]

    if not isinstance(val, dict):
        # direct equality
        return actual == val

    for op, arg in val.items():
        if op == "$ne":
            if actual == arg:
                return False
        elif op == "$eq":
            if actual != arg:
                return False
        elif op == "$gt":
            if not (actual > arg):
                return False
        elif op == "$gte":
            if not (actual >= arg):
                return False
        elif op == "$lt":
            if not (actual < arg):
                return False
        elif op == "$lte":
            if not (actual <= arg):
                return False
        elif op == "$in":
            if actual not in arg:
                return False
        elif op == "$nin":
            if actual in arg:
                return False
        elif op == "$regex":
            flags = re.I if (isinstance(val.get("$options", ""), str)
                             and "i" in val.get("$options", "")) else 0
            try:
                if not re.search(arg, str(actual), flags):
                    return False
            except re.error:
                return False
        elif op == "$exists":
            exists = field in doc
            if exists != bool(arg):
                return False
        elif op == "$not":
            if matches(doc, {field: arg}):
                return False
        elif op == "$options":
            # already handled with $regex
            continue
        else:
            # unknown operator → be strict (fail)
            return False
    return True

def _eval_where(js, doc):
    """
    Extremely narrow JS-like evaluator for $where.
    Handles:
      '1==1'         → True
      '1==2'         → False
      'this.username == "admin"'
      'this.username != null'
      'this.password != null'
      'function(){...}'  → treat body
      'sleep(5000)' or 'function(){ return sleep(5000) }' → sleep
    """
    if not isinstance(js, str):
        return False
    s = js.strip()

    # Strip "function(){ return X }" wrapper
    m = re.match(r"^function\s*\(\s*\)\s*\{\s*return\s+(.*?)\s*\}\s*$", s)
    if m:
        s = m.group(1)

    # sleep() → real sleep for time-based
    m = re.search(r"sleep\s*\(\s*(\d+)\s*\)", s)
    if m:
        time.sleep(min(int(m.group(1)) / 1000.0, 5.0))
        return True

    # Constant comparisons
    s = s.replace("true", "True").replace("false", "False")

    # Substitute this.<field> with the actual value
    def repl(match):
        field = match.group(1)
        v = doc.get(field)
        if isinstance(v, str):
            return repr(v)
        if v is None:
            return "None"
        return repr(v)

    js = re.sub(r"this\.(\w+)", repl, s)

    try:
        return bool(eval(js, {"__builtins__": {}}, {}))
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template_string("""<html><body>
    <h1>Vulnerable NoSQL Login (Mock MongoDB)</h1>
    <h2>POST /api/login</h2>
    <pre>curl -X POST http://127.0.0.1:5000/api/login -H 'Content-Type: application/json' \\
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'</pre>
    <h2>GET /api/users?filter=&lt;json&gt;</h2>
    <h2>GET /api/search?q=&lt;json&gt;</h2>
    </body></html>""")

@app.route("/api/login", methods=["POST"])
def api_login():
    """
    VULNERABLE: accepts JSON body directly and queries with it.
    No type validation — if you pass {"$ne": null}, it becomes a real query.
    """
    data = request.get_json(silent=True) or {}
    username_q = data.get("username")
    password_q = data.get("password")

    # <-- VULNERABILITY: no type check -->
    query = {}
    if username_q is not None:
        query["username"] = username_q
    if password_q is not None:
        query["password"] = password_q

    matches_list = [u for u in USERS if matches(u, query)]

    if matches_list:
        u = dict(matches_list[0])
        return jsonify({
            "status": "ok",
            "message": f"Logged in as {u['username']} (role={u['role']})",
            "user": u,
            "query": query,
            "count": len(matches_list),
        })
    return jsonify({
        "status": "fail",
        "message": "Invalid credentials",
        "query": query,
    }), 401

@app.route("/api/users")
def api_users():
    """VULNERABLE: filter parsed from JSON string, no validation."""
    raw = request.args.get("filter", "{}")
    try:
        query = _json.loads(raw)
    except Exception as e:
        return jsonify({"error": f"invalid json: {e}"}), 400

    results = [u for u in USERS if matches(u, query)]
    # Strip passwords from "safe" responses to look realistic
    return jsonify({
        "query": query,
        "count": len(results),
        "results": results,
    })

@app.route("/api/search")
def api_search():
    """VULNERABLE: query JSON in ?q=..."""
    raw = request.args.get("q", "{}")
    try:
        query = _json.loads(raw)
    except Exception as e:
        return jsonify({"error": f"invalid json: {e}"}), 400
    results = [u for u in USERS if matches(u, query)]
    return jsonify({
        "query": query,
        "count": len(results),
        "results": results,
    })

if __name__ == "__main__":
    print("[*] Vulnerable NoSQL app on http://127.0.0.1:5000")
    print("[*]   POST /api/login   (JSON body)")
    print("[*]   GET  /api/users?filter=<json>")
    print("[*]   GET  /api/search?q=<json>")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
