#!/usr/bin/env python3
"""
Vulnerable Shop App (Project #33 — LEARNING ONLY)
Deliberately insecure. Never deploy.
"""
from flask import Flask, request, jsonify, session
from decimal import Decimal, getcontext
import threading

app = Flask(__name__)
app.secret_key = 'insecure'

getcontext().prec = 5   # for rounding abuse

# In-memory state
CARTS = {}              # user_id -> {'items': [...], 'total': float}
ORDERS = []
USERS = {'admin': {'role': 'admin', 'balance': 0}}
COUPONS_USED = set()

@app.route('/')
def home():
    return '''<html><body>
<h1>Vulnerable Shop</h1>
<ul>
<li><a href="/api/products">Products</a></li>
<li><a href="/api/cart/1">Cart 1</a></li>
<li><a href="/api/cart/1/add?product_id=1&qty=1">Add to Cart</a></li>
<li><a href="/api/checkout">Checkout</a></li>
<li><a href="/api/admin/users">Admin Users</a></li>
</ul></body></html>'''

@app.route('/api/products')
def products():
    return jsonify([
        {'id': 1, 'name': 'Laptop', 'price': 999},
        {'id': 2, 'name': 'Phone',  'price': 499},
        {'id': 3, 'name': 'Tablet', 'price': 299},
    ])

# ------------------------------------------------------------------ #
# VULNERABLE: accepts any qty (negative, decimal, huge)
# ------------------------------------------------------------------ #
@app.route('/api/cart/1/add')
def cart_add():
    product_id = request.args.get('product_id', '1')
    qty = request.args.get('qty', '1')

    # VULNERABLE: no validation on qty or price
    try:
        qty_f = float(qty)
    except ValueError:
        return jsonify({'error': 'bad qty'}), 400

    # Lookup product price (also attacker-controllable in real bug)
    price = float(request.args.get('price', '999'))

    subtotal = qty_f * price

    cart = CARTS.setdefault(1, {'items': [], 'total': 0.0})
    cart['items'].append({
        'product_id': product_id,
        'qty': qty_f,
        'price': price,
        'subtotal': subtotal,
    })
    cart['total'] += subtotal

    return jsonify({
        'success': True,
        'item': cart['items'][-1],
        'cart_total': cart['total'],
    })

@app.route('/api/cart/1')
def cart_view():
    cart = CARTS.get(1, {'items': [], 'total': 0.0})
    return jsonify(cart)

@app.route('/api/cart/1/reset')
def cart_reset():
    CARTS[1] = {'items': [], 'total': 0.0}
    return jsonify({'ok': True})

# ------------------------------------------------------------------ #
# VULNERABLE: accepts coupon code with no uniqueness check
# ------------------------------------------------------------------ #
@app.route('/api/apply-coupon')
def apply_coupon():
    code = request.args.get('code', '')
    cart = CARTS.setdefault(1, {'items': [], 'total': 0.0})

    discounts = {
        'SAVE10': 10, 'SAVE20': 20, 'SAVE50': 50, 'ADMIN100': 100,
        'EXPIRED2020': 30, 'REFER_SELF': 10,
    }

    # VULNERABLE: no expiry, no single-use, no ownership check
    discount = discounts.get(code, 0)
    if discount <= 0:
        return jsonify({'error': 'invalid coupon'}), 400

    # Stacking allowed — each call subtracts more
    cart['total'] -= discount
    return jsonify({
        'success': True,
        'coupon': code,
        'discount_applied': discount,
        'cart_total': cart['total'],
    })

# ------------------------------------------------------------------ #
# VULNERABLE: checkout without payment
# ------------------------------------------------------------------ #
@app.route('/api/checkout', methods=['GET', 'POST'])
def checkout():
    cart = CARTS.get(1, {'items': [], 'total': 0.0})

    # VULNERABLE: no payment check
    order = {
        'order_id': len(ORDERS) + 1,
        'total': cart['total'],
        'status': 'placed',
        'paid': False,
    }
    ORDERS.append(order)

    return jsonify({'success': True, 'order': order})

# ------------------------------------------------------------------ #
# VULNERABLE: admin endpoint with no auth
# ------------------------------------------------------------------ #
@app.route('/api/admin/users')
def admin_users():
    # VULNERABLE: no auth check
    return jsonify({'users': list(USERS.keys()), 'admin_access': True})

# ------------------------------------------------------------------ #
# VULNERABLE: currency conversion with wrong math
# ------------------------------------------------------------------ #
@app.route('/api/convert')
def convert():
    amount = float(request.args.get('amount', '100'))
    currency = request.args.get('currency', 'USD')
    rate = float(request.args.get('rate', '1'))

    # VULNERABLE: rate is attacker-controlled
    converted = amount * rate

    return jsonify({
        'amount': amount,
        'currency': currency,
        'rate': rate,
        'converted': converted,
    })

# ------------------------------------------------------------------ #
# VULNERABLE: hidden param tampering — price comes from request
# ------------------------------------------------------------------ #
@app.route('/api/buy', methods=['GET', 'POST'])
def buy():
    # VULNERABLE: price taken from request body
    price = float(request.args.get('price', '999'))
    qty = int(request.args.get('qty', '1'))

    total = price * qty
    return jsonify({
        'success': True,
        'price_each': price,
        'qty': qty,
        'total': total,
    })

# ------------------------------------------------------------------ #
@app.route('/reset')
def reset():
    CARTS.clear()
    ORDERS.clear()
    COUPONS_USED.clear()
    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7000, debug=False, threaded=True)