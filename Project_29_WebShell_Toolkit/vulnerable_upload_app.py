#!/usr/bin/env python3
"""
Vulnerable File Upload App (Project #29 — LEARNING ONLY)
Deliberately insecure. Never deploy.
"""
from flask import Flask, request, Response
import os
import subprocess

app = Flask(__name__)

UPLOAD_DIR = '/tmp/vulnerable_uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route('/')
def home():
    return '''
    <html><body>
    <h1>Vulnerable Upload Demo</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    </body></html>
    '''

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file", 400

    f = request.files['file']
    filename = f.filename

    # VULNERABLE: no extension validation, no content check
    filepath = os.path.join(UPLOAD_DIR, filename)
    f.save(filepath)

    return f"Uploaded: {filepath}"

@app.route('/execute/<filename>')
def execute_uploaded(filename):
    """
    VULNERABLE: executes Python files in upload dir (simulates PHP shell execution).
    In real world, this is a webshell executed by the server.
    """
    filepath = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(filepath):
        return f"Not found: {filename}", 404

    # If the file is a Python script, execute it as a shell
    if filename.endswith('.py'):
        try:
            # Simulate webshell execution: run the file and return output
            # (In real world, uploading a .php file to a PHP server would make it a shell)
            with open(filepath, 'r') as f:
                code = f.read()
            # Execute in a controlled way
            return f"<html><body><pre>Uploaded Python code:\n\n{code[:500]}</pre></body></html>"
        except Exception as e:
            return f"Execution error: {e}", 500

    return f"File: {filepath}"

@app.route('/shell')
def shell():
    """
    Simulates the "shell" endpoint after upload.
    In a real attack, this would be the .php file's endpoint.
    """
    cmd = request.args.get('cmd', 'id')
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return f"<html><body><pre>{out.decode()}</pre></body></html>"
    except Exception as e:
        return f"<html><body><pre>Error: {e}</pre></body></html>", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6666, debug=False)