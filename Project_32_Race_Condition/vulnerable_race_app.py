#!/usr/bin/env python3
"""
Vulnerable Race Condition App (Project #32)
Deliberately insecure. Never deploy.
"""
from flask import Flask, request, jsonify
import time

app = Flask(__name__)

STATE = {
    'coupon_used': False,
    'balance': 100,
    'votes': 0,
    'login_attempts': 0,
}

@app.route('/')
def home():
    return '''<html><body>
<h1>Vulnerable Race Condition Demo</h1>
<ul>
<li><a href="/apply-coupon?code=SAVE50">Apply Coupon (SAVE50)</a></li>
<li><a href="/transfer?amount=100&to=attacker">Transfer $100</a></li>
<li><a href="/vote?id=123">Vote</a></li>
<li><a href="/login?username=admin&password=wrong">Login</a></li>
<li><a href="/state">View State</a></li>
<li><a href="/reset-state">Reset State</a></li>
</ul>
</body></html>'''

@app.route('/state')
def state():
    return jsonify(STATE)

@app.route('/reset-state')
def reset_state():
    STATE['coupon_used'] = False
    STATE['balance'] = 100
    STATE['votes'] = 0
    STATE['login_attempts'] = 0
    return jsonify({'ok': True, 'state': STATE})

@app.route('/apply-coupon')
def apply_coupon():
    code = request.args.get('code', '') or request.form.get('code', '')
    if not code:
        return jsonify({'error': 'no code'}), 400
    if STATE['coupon_used']:
        return jsonify({'error': 'already used'}), 400
    time.sleep(0.05)
    STATE['coupon_used'] = True
    return jsonify({'success': True, 'code': code, 'discount': 50})

@app.route('/transfer')
def transfer():
    try:
        amount = int(request.args.get('amount', 0))
    except ValueError:
        return jsonify({'error': 'bad amount'}), 400
    to = request.args.get('to', 'unknown')
    if STATE['balance'] < amount:
        return jsonify({'error': 'insufficient funds',
                        'balance': STATE['balance']}), 400
    time.sleep(0.05)
    STATE['balance'] -= amount
    return jsonify({'success': True, 'amount': amount,
                    'to': to, 'balance': STATE['balance']})

@app.route('/vote')
def vote():
    vid = request.args.get('id', '')
    if not vid:
        return jsonify({'error': 'no id'}), 400
    time.sleep(0.02)
    STATE['votes'] += 1
    return jsonify({'success': True, 'votes': STATE['votes']})

@app.route('/login')
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    if STATE['login_attempts'] >= 5:
        return jsonify({'error': 'too many attempts'}), 429
    time.sleep(0.05)
    STATE['login_attempts'] += 1
    if username == 'admin' and password == 'correct':
        return jsonify({'success': True})
    return jsonify({'error': 'invalid credentials',
                    'attempts': STATE['login_attempts']}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000, debug=False, threaded=True)