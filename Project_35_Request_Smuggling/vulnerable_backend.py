#!/usr/bin/env python3
"""
Vulnerable Backend (Project #35 — LEARNING ONLY)
Deliberately processes smuggled requests via CL.TE ambiguity.
"""
import socket
import threading
import time

HOST = '0.0.0.0'
PORT = 8080

RESPONSES = {
    '/':       (200, "<html><body><h1>Home Page</h1></body></html>"),
    '/admin':  (200, "<html><body><h1>ADMIN PANEL - RESTRICTED</h1></body></html>"),
    '/login':  (200, "<html><body><h1>Login Page</h1></body></html>"),
    '/log':    (200, "<html><body><h1>Logged: %s</h1></body></html>"),
}

# Simple flag: toggle whether the backend is vulnerable
VULNERABLE = True


def make_response(code, body, extra_headers=''):
    body_bytes = body.encode()
    resp = (
        f"HTTP/1.1 {code} OK\r\n"
        f"Content-Type: text/html\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"{extra_headers}"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode() + body_bytes
    return resp


def handle_client(conn, addr):
    try:
        conn.settimeout(3)
        buffer = b''

        # Read up to 64KB of pipelined data
        while len(buffer) < 65536:
            try:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                # Stop early if we have at least 2 request delimiters
                if buffer.count(b'\r\n\r\n') >= 2:
                    break
                time.sleep(0.05)
            except socket.timeout:
                break

        if not buffer:
            return

        print(f"\n[{addr}] Received {len(buffer)} bytes")
        if VULNERABLE:
            print(f"[{addr}] Buffer preview: {buffer[:200]!r}")

        # Process requests one at a time
        while buffer:
            text = buffer.decode('utf-8', errors='ignore')
            header_end = text.find('\r\n\r\n')
            if header_end == -1:
                break

            headers_raw = text[:header_end]
            lines = headers_raw.split('\r\n')
            if not lines or not lines[0]:
                break

            method_line = lines[0].split()
            if len(method_line) < 2:
                break
            path = method_line[1]

            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip().lower()] = v.strip()

            body_start = header_end + 4
            content_length = int(headers.get('content-length', '0'))
            transfer_encoding = headers.get('transfer-encoding', '').lower()

            consumed = 0

            # ---- PARSING LOGIC ----
            if 'chunked' in transfer_encoding:
                # Parse chunks
                pos = body_start
                while pos < len(text):
                    line_end = text.find('\r\n', pos)
                    if line_end == -1:
                        break
                    chunk_line = text[pos:line_end].strip()
                    if not chunk_line:
                        pos = line_end + 2
                        continue
                    try:
                        chunk_size = int(chunk_line, 16)
                    except ValueError:
                        break
                    pos = line_end + 2

                    if chunk_size == 0:
                        # End of chunked body
                        pos += 2  # skip trailing \r\n
                        # Consumed everything up to pos
                        consumed = pos
                        break
                    pos += chunk_size + 2

                if consumed == 0:
                    # Could not parse — treat as complete
                    break

            elif content_length > 0:
                # Use Content-Length
                consumed = body_start + content_length
            else:
                # No body
                consumed = body_start

            # ---- VULNERABLE: process ALL remaining bytes as new requests ----
            # In real smuggling, this is where the attacker smuggles a request
            # that the frontend thinks is part of the body.

            # Send response for THIS request
            path_key = path
            if path_key in RESPONSES:
                code, body = RESPONSES[path_key]
                resp = make_response(code, body)
                conn.sendall(resp)
                print(f"[{addr}] -> {code} {path}")
            else:
                resp = make_response(404, f"Not found: {path}")
                conn.sendall(resp)
                print(f"[{addr}] -> 404 {path}")

            # Advance buffer
            remaining = text[consumed:]
            if not remaining.strip():
                break
            buffer = remaining.encode()

            if not VULNERABLE:
                break

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    print(f"[*] Backend listening on {HOST}:{PORT}")
    print(f"[*] VULNERABLE mode: {VULNERABLE}")
    print(f"[*] Endpoints: {list(RESPONSES.keys())}")
    print(f"[!] Intentionally insecure — educational only")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.daemon = True
        t.start()


if __name__ == '__main__':
    main()