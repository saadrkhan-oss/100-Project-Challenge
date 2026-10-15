#!/usr/bin/env python3
"""
vulnerable_ldap_app.py — Deliberately vulnerable LDAP-injection Flask target
FOR LOCAL TESTING ONLY.
"""
from flask import Flask, request, jsonify, render_template_string
import re

app = Flask(__name__)

USERS = [
    {"uid": "admin", "cn": "Administrator", "sn": "Admin",
     "mail": "admin@example.com", "password": "admin123",
     "role": "admin", "department": "IT"},
    {"uid": "alice", "cn": "Alice Anderson", "sn": "Anderson",
     "mail": "alice@example.com", "password": "alicepw",
     "role": "user", "department": "Sales"},
    {"uid": "bob", "cn": "Bob Brown", "sn": "Brown",
     "mail": "bob@example.com", "password": "bobpw",
     "role": "user", "department": "Support"},
]

GROUPS = {"admins": ["admin"], "users": ["alice", "bob"]}

# ---------------------------------------------------------------------------
# Proper LDAP filter evaluator
# ---------------------------------------------------------------------------
def parse_filter(f):
    """
    Parse an LDAP filter string into a tree.
    Returns:  ('&', [child1, child2, ...])
              ('|', [child1, child2, ...])
              ('attr', 'value')
              ('raw', 'text')  — fallback
    """
    f = f.strip()
    if not f.startswith("("):
        return ("raw", f)
    # strip outer parens if they wrap the whole thing
    if _balanced(f):
        inner = f[1:-1].strip()
    else:
        return ("raw", f)

    if inner.startswith("&"):
        children, rest = _parse_many(inner[1:])
        return ("&", children)
    if inner.startswith("|"):
        children, rest = _parse_many(inner[1:])
        return ("|", children)

    # simple attr=value
    m = re.match(r"^([^=()]+)=([^()]*)$", inner)
    if m:
        return ("attr", (m.group(1).strip(), m.group(2).strip()))

    return ("raw", inner)

def _parse_many(s):
    """Parse `(child1)(child2)...` and return [children], leftover."""
    children = []
    i = 0
    while i < len(s):
        if s[i] != "(":
            i += 1
            continue
        # find matching close paren
        depth = 0
        j = i
        while j < len(s):
            if s[j] == "(":
                depth += 1
            elif s[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= len(s):
            break
        children.append(parse_filter(s[i:j+1]))
        i = j + 1
    return children, s[i:]

def _balanced(f):
    depth = 0
    for c in f:
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0

def eval_filter(tree, entry):
    """Evaluate a parsed filter tree against an entry dict."""
    kind = tree[0]
    if kind == "&":
        return all(eval_filter(c, entry) for c in tree[1])
    if kind == "|":
        return any(eval_filter(c, entry) for c in tree[1])
    if kind == "attr":
        attr, value = tree[1]
        if attr not in entry:
            return False
        actual = str(entry[attr])
        if "*" in value:
            pattern = "^" + re.escape(value).replace(r"\*", ".*") + "$"
            return re.match(pattern, actual) is not None
        return actual == value
    # raw -> unevaluatable
    return False

def ldap_match(filter_str, entry):
    """Top-level: parse the WHOLE string. If it doesn't parse cleanly, try
    to look for an always-true subexpression (mimicking a real LDAP quirk
    where trailing garbage after the first matching filter is ignored)."""
    try:
        tree = parse_filter(filter_str)
        if eval_filter(tree, entry):
            return True
    except Exception:
        pass

    # Real LDAP servers sometimes parse the FIRST valid top-level
    # expression and ignore trailing content. Mimic that:
    # extract first balanced (...) expression at top level
    s = filter_str.strip()
    if s.startswith("("):
        depth = 0
        for i, c in enumerate(s):
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    first = s[:i+1]
                    try:
                        tree = parse_filter(first)
                        if eval_filter(tree, entry):
                            return True
                    except Exception:
                        pass
                    break
    return False

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template_string("""<html><body>
    <h1>Vulnerable LDAP Login (Mock)</h1>
    <h2>POST /login</h2>
    <form method="POST" action="/login">
      <input name="username" placeholder="username"><br>
      <input name="password" placeholder="password"><br>
      <button type="submit">Login</button>
    </form>
    </body></html>""")

@app.route("/login", methods=["GET", "POST"])
def login():
    username = request.form.get("username") or request.args.get("username", "")
    password = request.form.get("password") or request.args.get("password", "")
    filter_str = f"(&(uid={username})(password={password}))"
    matches = [u for u in USERS if ldap_match(filter_str, u)]
    if matches:
        user = matches[0]
        return jsonify({
            "status": "ok",
            "message": f"Logged in as {user['uid']} (role={user['role']})",
            "user": user,
            "filter": filter_str,
            "all_matches": len(matches),
        })
    return jsonify({
        "status": "fail",
        "message": "Invalid credentials",
        "filter": filter_str,
    }), 401

@app.route("/search")
def search():
    q = request.args.get("q", "")
    filter_str = f"(&(cn=*{q}*))"
    matches = [u for u in USERS if ldap_match(filter_str, u)]
    return jsonify({
        "filter": filter_str,
        "count": len(matches),
        "results": [{"uid": u["uid"], "cn": u["cn"], "mail": u["mail"]}
                    for u in matches],
    })

@app.route("/admin")
def admin():
    uid = request.args.get("uid", "")
    filter_str = f"(&(uid={uid})(role=admin))"
    matches = [u for u in USERS if ldap_match(filter_str, u)]
    return jsonify({
        "filter": filter_str,
        "count": len(matches),
        "admins": [u["uid"] for u in matches],
    })

if __name__ == "__main__":
    print("[*] Vulnerable LDAP app on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
