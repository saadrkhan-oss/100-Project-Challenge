#!/usr/bin/env python3
"""
Vulnerable Cache App (Project #34 — LEARNING ONLY)
Deliberately insecure. Never deploy.
"""
from flask import Flask, request, Response, jsonify
import time
import hashlib

app = Flask(__name__)

# In-memory cache (simulates Varnish/Nginx cache)
CACHE = {}
CACHE_TTL = 60   # 60 seconds

# ==================================================================== #
# MOCK CACHE LAYER
# ==================================================================== #
def cache_key(method, path, query):
    """Cache key only includes method + path + query — NOT headers."""
    return hashlib.md5(f"{method}:{path}:{query}".encode()).hexdigest()

def get_cached(key):
    if key in CACHE:
        entry = CACHE[key]
        if time.time() - entry['time'] < CACHE_TTL:
            return entry['response'], entry['headers']
        else:
            del CACHE[key]
    return None, None

def set_cache(key, response, headers):
    CACHE[key] = {
        'response': response,
        'headers': headers,
        'time': time.time(),
    }

def cache_headers(hit=False):
    return {
        'X-Cache': 'HIT' if hit else 'MISS',
        'X-Cache-Status': 'HIT' if hit else 'MISS',
        'Cache-Control': f'public, max-age={CACHE_TTL}',
        'Age': '0',
    }

# ==================================================================== #
# ENDPOINTS
# ==================================================================== #
@app.route('/')
def home():
    # VULNERABLE: X-Forwarded-Host is reflected into the page
    host = request.headers.get('X-Forwarded-Host', request.host)

    key = cache_key(request.method, request.path, '')
    cached_resp, cached_hdrs = get_cached(key)

    if cached_resp:
        headers = cache_headers(hit=True)
        return Response(cached_resp, mimetype='text/html', headers=headers)

    html = f'''<html>
<head>
<title>Vulnerable Cache App</title>
<meta property="og:url" content="http://{host}/">
<link rel="canonical" href="http://{host}/">
</head>
<body>
<h1>Vulnerable Cache App</h1>
<p>Host: <a href="http://{host}/">{host}</a></p>
<p>Loading script from: <script src="http://{host}/static/app.js"></script></p>
<p>Current time: {time.time()}</p>
</body>
</html>'''

    set_cache(key, html, {})
    return Response(html, mimetype='text/html', headers=cache_headers(hit=False))

@app.route('/admin')
def admin():
    # VULNERABLE: X-Original-URL bypass
    override = request.headers.get('X-Original-URL', '')
    if override == '/admin':
        return jsonify({'admin': True, 'flag': 'ADMIN_ACCESS_GRANTED'}), 200

    return jsonify({'error': 'forbidden'}), 403

@app.route('/api/user/<user_id>')
def user_profile(user_id):
    # VULNERABLE: returns user data + sets cache headers based on request
    path = request.path

    # Cache deception: if path ends in .css/.js, cache as static
    if path.endswith(('.css', '.js', '.png', '.jpg')):
        cache_hdrs = {
            'X-Cache': 'MISS',
            'Cache-Control': 'public, max-age=3600',
            'Content-Type': 'text/css',
        }
    else:
        cache_hdrs = {
            'X-Cache': 'MISS',
            'Cache-Control': 'private, no-store',
            'Content-Type': 'application/json',
        }

    return Response(
        f'{{"user_id": "{user_id}", "email": "user{user_id}@example.com", '
        f'"token": "secret-{user_id}"}}',
        mimetype=cache_hdrs['Content-Type'],
        headers=cache_hdrs,
    )

@app.route('/api/user/<path:path>')
def user_path(path):
    # Catch-all for path confusion attacks
    return user_profile(path.split('/')[0] if '/' in path else path)

@app.route('/cache-stats')
def cache_stats():
    return jsonify({'size': len(CACHE), 'keys': list(CACHE.keys())})

@app.route('/cache-reset')
def cache_reset():
    CACHE.clear()
    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6000, debug=False, threaded=True)