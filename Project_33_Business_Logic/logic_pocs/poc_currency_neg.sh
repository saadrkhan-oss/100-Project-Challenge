#!/bin/bash
# PoC: Negative currency rate
curl -s "http://localhost:7000/api/convert?amount=100&currency=USD&rate=-1"
echo ""
