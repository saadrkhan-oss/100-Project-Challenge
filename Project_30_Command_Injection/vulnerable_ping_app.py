#!/usr/bin/env python3
"""
Vulnerable Ping App (Project #30 — LEARNING ONLY)
Deliberately insecure. Never deploy.
"""
from flask import Flask, request
import subprocess
import os

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <html><body>
    <h1>Vulnerable Ping</h1>
    <form action="/ping" method="get">
        <label>IP:</label>
        <input type="text" name="ip" value="127.0.0.1">
        <input type="submit" value="Ping">
    </form>
    </body></html>
    '''

@app.route('/ping')
def ping():
    ip = request.args.get('ip', '127.0.0.1')

    # VULNERABLE: user input passed directly to shell
    cmd = f"ping -c 1 {ip}"

    try:
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=15
        ).decode('utf-8', errors='ignore')
        return f"<html><body><h2>Command:</h2><pre>{cmd}</pre>" \
               f"<h2>Output:</h2><pre>{out}</pre></body></html>"
    except subprocess.TimeoutExpired:
        return f"<html><body><pre>Timeout: {cmd}</pre></body></html>", 504
    except Exception as e:
        return f"<html><body><pre>Error: {e}</pre></body></html>", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5555, debug=False)