#!/usr/bin/env python3
"""
vulnerable_api.py — Intentionally vulnerable API (Project #62)
FOR LOCAL TESTING ONLY. Do NOT expose to internet.

Vulnerabilities:
- No auth on /api/users (PII disclosure)
- Weak JWT secret "secret123"
- Accepts alg: none
- IDOR on /api/users/<id>
- SQL injection in /api/login
- NoSQL injection in /api/search
- Command injection in /api/ping
- No rate limiting
"""
from flask import Flask, request, jsonify
import sqlite3, subprocess, os
import jwt  # pip install PyJWT
import base64, json

app = Flask(__name__)

JWT_SECRET = "secret123"  # WEAK!

# In-memory DB
DB = {
    1: {"id": 1, "username": "admin", "email": "admin@corp.local", "phone": "+1-555-0100", "ssn": "123-45-6789", "role": "admin", "password": "admin123", "api_key": "AKIAIOSFODNN7EXAMPLE"},
    2: {"id": 2, "username": "alice", "email": "alice@corp.local", "phone": "+1-555-0101", "ssn": "234-56-7890", "role": "user", "password": "alicepw", "api_key": "AKIA234567890EXAMPLE"},
    3: {"id": 3, "username": "bob", "email": "bob@corp.local", "phone": "+1-555-0102", "ssn": "345-67-8901", "role": "user", "password": "bobpw", "api_key": "AKIA345678901EXAMPLE"},
}

def make_jwt(payload):
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_jwt(token):
    """VULNERABLE: accepts alg=none"""
    try:
        # Decode header to check algorithm
        header_b64 = token.split(".")[0]
        # Pad base64
        header_b64 += "=" * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        if header.get("alg") == "none":
            # VULN: accepts unsigned tokens
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            return json.loads(base64.urlsafe_b64decode(payload_b64))
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception as e:
        return None

# --- Endpoints ---

@app.route("/")
def home():
    return jsonify({"service": "vulnerable-api", "version": "1.0", "endpoints": ["/api/users", "/api/login", "/api/search", "/api/ping", "/api/admin", "/api/docs"]})

@app.route("/api/docs")
def docs():
    """Fake swagger to trigger discovery."""
    return jsonify({"openapi": "3.0.0", "info": {"title": "Vulnerable API", "version": "1.0"}, "paths": {"/api/users": {}, "/api/login": {}, "/api/search": {}, "/api/ping": {}, "/api/admin": {}}})

@app.route("/api/users")
def users_no_auth():
    """VULN: No auth, returns ALL users with PII and secrets."""
    return jsonify({"users": list(DB.values())})

@app.route("/api/users/<int:user_id>")
def user_by_id(user_id):
    """VULN: IDOR — no auth check."""
    user = DB.get(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)

@app.route("/api/login", methods=["POST"])
def login():
    """VULN: SQL injection + no rate limiting."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # VULN: SQL injection via string concat
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    # Simulate injection
    if "' OR '" in username or "' OR '" in password:
        return jsonify({"status": "ok", "user": DB[1], "note": "SQL injection worked!", "query": query})

    # Normal auth
    for u in DB.values():
        if u["username"] == username and u["password"] == password:
            token = make_jwt({"sub": u["id"], "role": u["role"]})
            return jsonify({"status": "ok", "token": token, "user": u})

    return jsonify({"status": "fail", "query": query}), 401

@app.route("/api/search", methods=["POST"])
def search():
    """VULN: NoSQL injection via $ne."""
    data = request.get_json() or {}
    query = data.get("query", {})

    # VULN: if query is a dict with $ne, return all users
    if isinstance(query, dict) and "$ne" in query:
        return jsonify({"results": list(DB.values()), "note": "NoSQL injection worked!"})

    # Normal search
    q = str(query).lower()
    results = [u for u in DB.values() if q in u["username"].lower()]
    return jsonify({"results": results})

@app.route("/api/ping")
def ping():
    """VULN: Command injection via host param."""
    host = request.args.get("host", "127.0.0.1")
    # VULN: shell=True with user input
    try:
        result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=5)
        return jsonify({"host": host, "output": result.stdout[:500], "error": result.stderr[:200]})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/api/admin/users")
def admin_users():
    """VULN: No auth, admin endpoint."""
    return jsonify({"admin_endpoint": True, "users": list(DB.values())})

if __name__ == "__main__":
    print("[*] Vulnerable API on http://127.0.0.1:5001")
    print("[*] Endpoints: /api/users, /api/login, /api/search, /api/ping, /api/admin/users")
    app.run(host="127.0.0.1", port=5001, debug=False)
