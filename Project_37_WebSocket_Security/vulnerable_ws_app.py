#!/usr/bin/env python3
"""
Vulnerable WebSocket App (Project #37 — LEARNING ONLY)
Deliberately insecure. Never deploy.

Uses flask-socketio. Multiple intentional flaws:
- No Origin validation (CSWSH)
- No auth on WebSocket handshake
- No input sanitization (SQLi, XSS, CMDi)
- No rate limiting
- No message size limit
- Admin channel accessible without auth
"""
from flask import Flask, request, jsonify, render_template_string
from flask_socketio import SocketIO, emit, send

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insecure_ws_secret'

# Enable CORS for all origins — VULNERABLE
socketio = SocketIO(
    app,
    cors_allowed_origins='*',      # VULNERABLE: allows any origin
    async_mode='threading',
    logger=False,
    engineio_logger=False,
)

# ==================================================================== #
# HTTP landing page
# ==================================================================== #
@app.route('/')
def home():
    return '''
    <html><body>
    <h1>Vulnerable WebSocket App</h1>
    <p>WebSocket endpoint: <code>ws://localhost:5001/socket.io/</code></p>
    <p>Try connecting with a WebSocket client</p>
    </body></html>
    '''

# ==================================================================== #
# WebSocket handlers
# ==================================================================== #
@socketio.on('connect')
def on_connect():
    print(f"[WS] Client connected: {request.sid}")
    emit('welcome', {'message': 'Connected', 'sid': request.sid})

@socketio.on('disconnect')
def on_disconnect():
    print(f"[WS] Client disconnected: {request.sid}")

@socketio.on('message')
def on_message(data):
    """Generic message handler — VULNERABLE"""
    print(f"[WS] Message from {request.sid}: {data}")

    if isinstance(data, str):
        # VULNERABLE: reflects raw content
        emit('message', data, broadcast=True)

    elif isinstance(data, dict):
        msg_type = data.get('type', '')

        if msg_type == 'ping':
            emit('pong', {'pong': True})

        elif msg_type == 'auth':
            # VULNERABLE: accepts any credentials
            emit('auth', {'success': True, 'token': 'fake-token-12345'})

        elif msg_type == 'join_room':
            # VULNERABLE: no auth check on room name
            room = data.get('room', '')
            emit('room_joined', {'room': room, 'success': True})

        elif msg_type == 'admin_list':
            # VULNERABLE: returns admin data without auth
            emit('admin_list', {
                'users': [
                    {'id': 1, 'username': 'admin', 'email': 'admin@example.com', 'password': '5f4dcc3b5aa765d61d8327deb882cf99'},
                    {'id': 2, 'username': 'alice', 'email': 'alice@example.com', 'password': 'e10adc3949ba59abbe56e057f20f883e'},
                ],
                'admin': True
            })

        elif 'id' in data:
            # VULNERABLE: no SQLi protection — reflects user input
            uid = data['id']
            if isinstance(uid, str) and ("'" in uid or "union" in uid.lower() or "or" in uid.lower()):
                emit('error', {'error': f"SQL syntax error near '{uid}'"})
            else:
                emit('user', {'id': uid, 'username': f'user{uid}'})

        elif 'cmd' in data:
            # VULNERABLE: simulates command injection
            cmd = data['cmd']
            if ';' in cmd or '|' in cmd or '`' in cmd or '$(' in cmd:
                # Simulated output
                emit('result', {'output': 'www-data\nuid=33(www-data) gid=33(www-data) groups=33(www-data)'})
            else:
                emit('result', {'output': f'(no injection)'})

        elif 'url' in data:
            # VULNERABLE: SSRF simulation
            url = data['url']
            if '169.254.169.254' in url:
                emit('result', {'body': 'ami-id\ninstance-id\nhostname\n'})
            elif '127.0.0.1' in url:
                emit('result', {'body': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu\n'})
            else:
                emit('result', {'body': f'(fetched {url})'})

        elif 'path' in data or 'file' in data:
            # VULNERABLE: path traversal simulation
            p = data.get('path') or data.get('file', '')
            if '../' in p or '%2f' in p:
                emit('result', {'content': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin'})
            else:
                emit('result', {'content': '(no traversal)'})

        elif 'message' in data or 'text' in data:
            # VULNERABLE: reflects XSS payloads
            content = data.get('message') or data.get('text', '')
            emit('message', {'message': content, 'from': 'server'}, broadcast=True)

        else:
            emit('message', {'echo': data}, broadcast=True)

if __name__ == '__main__':
    print("[!] Vulnerable WebSocket app starting")
    print("[!] Endpoint: http://localhost:5001/socket.io/")
    print("[!] For local learning only")
    socketio.run(app, host='0.0.0.0', port=5001, allow_unsafe_werkzeug=True)