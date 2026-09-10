#!/usr/bin/env python3
"""
WAF Detection & Evasion Tool - FAST VERSION
Project #13: Web Application Firewall (WAF) Detection & Bypass
Optimized with threading and smart payload sampling
"""

import requests
import sys
import time
import re
import argparse
import threading
import urllib3
from urllib.parse import quote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import payloads
from waf_bypass_payloads import (
    WAF_SIGNATURES, BYPASS_PAYLOADS, WAF_BLOCK_PATTERNS,
    WAF_BLOCK_CODES, get_all_payloads
)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class FastWAFDetector:
    def __init__(self, target, timeout=5, output_file="waf_bypass_report.txt",
                 verbose=False, threads=10, delay=0.05, full=False):
        """
        FAST WAF Detector

        Args:
            target: Target URL
            timeout: Request timeout (default 5s)
            output_file: Output file name
            verbose: Enable verbose output
            threads: Number of concurrent threads (default 10)
            delay: Delay between requests per thread (default 0.05s)
            full: Test ALL payloads instead of sample (default False)
        """
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        self.target = target.rstrip('/')
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        self.threads = threads
        self.delay = delay
        self.full = full

        # Shared session with connection pooling
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=threads,
            pool_maxsize=threads * 2,
            max_retries=0
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })

        self.results = {
            'url': self.target,
            'waf_detected': False,
            'waf_name': None,
            'waf_confidence': 'LOW',
            'waf_evidence': [],
            'bypass_results': [],
            'successful_bypasses': [],
            'failed_bypasses': [],
            'bypass_rate': 0,
            'waf_strength': 'UNKNOWN',
            'recommendations': []
        }

        self.baseline_length = 0
        self.baseline_status = None
        self.lock = threading.Lock()
        self.completed = 0
        self.total_payloads = 0

    # ------------------------------------------------------------------ #
    # CONNECTION / WAF DETECTION
    # ------------------------------------------------------------------ #
    def test_connection(self):
        print(f"{Colors.BOLD}[*] Testing connection to {self.target}...{Colors.RESET}")
        try:
            r = self.session.get(self.target, timeout=self.timeout,
                                 verify=False, allow_redirects=True)
            self.baseline_length = len(r.text)
            self.baseline_status = r.status_code
            print(f"{Colors.GREEN}[✓] Reachable — Status: {r.status_code} "
                  f"({self.baseline_length} bytes){Colors.RESET}")
            return True, r
        except Exception as e:
            print(f"{Colors.RED}[!] Cannot reach target: {str(e)[:60]}{Colors.RESET}")
            return False, None

    def detect_waf(self, response):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Detecting WAF...{Colors.RESET}")
        detections = []
        headers_lower = {k.lower(): str(v).lower() for k, v in response.headers.items()}

        for waf_name, sig in WAF_SIGNATURES.items():
            evidence = []
            for hp in sig.get('headers', []):
                hp_l = hp.lower()
                for hn, hv in headers_lower.items():
                    if hp_l in hn or hp_l in hv:
                        evidence.append(f"Header: {hn}={hv[:40]}")
            for cp in sig.get('cookies', []):
                for c in response.cookies:
                    if cp.lower() in c.name.lower():
                        evidence.append(f"Cookie: {c.name}")
            for bp in sig.get('body_patterns', []):
                if bp.lower() in response.text.lower():
                    evidence.append(f"Body: {bp}")

            if evidence:
                detections.append({
                    'waf': waf_name,
                    'evidence': evidence,
                    'confidence': 'HIGH' if len(evidence) >= 2 else 'MEDIUM'
                })

        if detections:
            best = max(detections, key=lambda x:
                       {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[x['confidence']])
            self.results['waf_detected'] = True
            self.results['waf_name'] = best['waf']
            self.results['waf_confidence'] = best['confidence']
            self.results['waf_evidence'] = best['evidence']

            print(f"{Colors.RED}[!] WAF Detected: {best['waf']}{Colors.RESET}")
            print(f"    Confidence: {best['confidence']}")
            for ev in best['evidence']:
                print(f"      • {ev}")
        else:
            print(f"{Colors.GREEN}[✓] No WAF detected{Colors.RESET}")

        return detections

    # ------------------------------------------------------------------ #
    # PAYLOAD TESTING
    # ------------------------------------------------------------------ #
    def _smart_sample(self, payloads, per_category=3):
        """
        Return a small representative subset of payloads per category.
        This is the biggest speed win.
        """
        if self.full:
            return payloads

        sampled = []
        seen = {}
        for p in payloads:
            cat = p['category']
            seen[cat] = seen.get(cat, 0)
            if seen[cat] < per_category:
                sampled.append(p)
                seen[cat] += 1
        return sampled

    def _test_one(self, payload_data):
        """Test one payload. Returns result dict."""
        category = payload_data['category']
        payload = payload_data['payload']

        try:
            time.sleep(self.delay)  # small throttle per thread

            if '?' in self.target:
                url = f"{self.target}&waf={quote(payload)}"
            else:
                url = f"{self.target}?waf={quote(payload)}"

            r = self.session.get(url, timeout=self.timeout,
                                 verify=False, allow_redirects=False)

            blocked = False
            reason = None

            # 1) Blocking status code
            if r.status_code in WAF_BLOCK_CODES:
                blocked = True
                reason = f"HTTP {r.status_code}"

            # 2) Blocking body pattern
            if not blocked:
                body_low = r.text.lower()
                for pat in WAF_BLOCK_PATTERNS:
                    if re.search(pat, body_low, re.IGNORECASE):
                        blocked = True
                        reason = f"Body: {pat}"
                        break

            # 3) Huge size delta
            if not blocked and self.baseline_length:
                diff = abs(len(r.text) - self.baseline_length)
                if diff > self.baseline_length * 0.5:
                    blocked = True
                    reason = f"Size delta {diff}"

            return {
                'payload': payload,
                'category': category,
                'blocked': blocked,
                'reason': reason,
                'status_code': r.status_code,
                'response_length': len(r.text),
                'success': not blocked
            }

        except requests.exceptions.Timeout:
            return {
                'payload': payload, 'category': category,
                'blocked': True, 'reason': 'Timeout',
                'status_code': None, 'response_length': 0, 'success': False
            }
        except Exception as e:
            return {
                'payload': payload, 'category': category,
                'blocked': True, 'reason': str(e)[:40],
                'status_code': None, 'response_length': 0, 'success': False
            }

    def test_bypasses(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Testing bypass techniques "
              f"(threads={self.threads}, delay={self.delay}s)...{Colors.RESET}")

        all_payloads = get_all_payloads()
        payloads = self._smart_sample(all_payloads, per_category=3)
        self.total_payloads = len(payloads)

        print(f"{Colors.CYAN}[*] Total payloads available: {len(all_payloads)}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Testing sample: {self.total_payloads} "
              f"(use --full for all){Colors.RESET}\n")

        successful = 0
        failed = 0
        start = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_one, p): p for p in payloads}

            for future in as_completed(futures):
                res = future.result()
                with self.lock:
                    self.completed += 1
                    self.results['bypass_results'].append(res)

                    if res['success']:
                        successful += 1
                        self.results['successful_bypasses'].append(res)
                        tag = f"{Colors.GREEN}PASSED{Colors.RESET}"
                    else:
                        failed += 1
                        self.results['failed_bypasses'].append(res)
                        tag = f"{Colors.RED}BLOCKED{Colors.RESET}"

                    # Print only interesting results (or all in verbose)
                    if res['success'] or self.verbose:
                        short = res['payload'][:55] + ('...' if len(res['payload']) > 55 else '')
                        print(f"  [{self.completed}/{self.total_payloads}] "
                              f"{tag} [{res['category']}] {short}")
                        if not res['success'] and res['reason']:
                            print(f"           Reason: {res['reason']}")

                    # Progress every 10
                    if self.completed % 10 == 0 and not self.verbose:
                        pct = self.completed / self.total_payloads * 100
                        print(f"\r{Colors.YELLOW}[*] Progress: "
                              f"{self.completed}/{self.total_payloads} ({pct:.0f}%)  "
                              f"PASS={successful} BLOCK={failed}{Colors.RESET}",
                              end='', flush=True)

        elapsed = time.time() - start
        print()  # newline

        if self.total_payloads:
            self.results['bypass_rate'] = successful / self.total_payloads * 100

        print(f"\n{Colors.BOLD}[*] Bypass Testing Complete "
              f"({elapsed:.1f}s){Colors.RESET}")
        print(f"    Total tested:       {self.total_payloads}")
        print(f"    {Colors.GREEN}Successful bypasses: {successful}{Colors.RESET}")
        print(f"    {Colors.RED}Blocked payloads:    {failed}{Colors.RESET}")
        print(f"    Bypass rate:        {self.results['bypass_rate']:.1f}%")
        print(f"    Throughput:         {self.total_payloads/elapsed:.1f} req/s")

        return successful, failed

    # ------------------------------------------------------------------ #
    # ASSESSMENT / REPORT
    # ------------------------------------------------------------------ #
    def assess_waf_strength(self):
        rate = self.results['bypass_rate']
        if rate >= 70:
            strength, color, desc = 'WEAK', Colors.RED, 'easily bypassed'
        elif rate >= 40:
            strength, color, desc = 'MODERATE', Colors.YELLOW, 'some protection'
        elif rate >= 20:
            strength, color, desc = 'STRONG', Colors.GREEN, 'good protection'
        else:
            strength, color, desc = 'VERY STRONG', Colors.GREEN, 'excellent protection'

        self.results['waf_strength'] = strength

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] WAF Strength Assessment:{Colors.RESET}")
        print(f"    WAF: {self.results['waf_name'] or 'Unknown'}")
        print(f"    Bypass Rate: {rate:.1f}%")
        print(f"    Rating: {color}{strength}{Colors.RESET} ({desc})")

    def generate_recommendations(self):
        recs = []
        if self.results['waf_detected']:
            recs.append(f"WAF detected: {self.results['waf_name']}")
            recs.append("Ensure WAF rules are regularly updated")
            if self.results['bypass_rate'] > 50:
                recs.append("High bypass rate — strengthen WAF rules")
            elif self.results['bypass_rate'] > 20:
                recs.append("Some bypasses — review specific rules")
            else:
                recs.append("WAF performing well — maintain config")
        else:
            recs.append("No WAF detected — consider deploying one")
            recs.append("Recommended: Cloudflare, AWS WAF, ModSecurity")

        cats = {}
        for b in self.results['successful_bypasses']:
            cats[b['category']] = cats.get(b['category'], 0) + 1
        if cats:
            recs.append("Successful bypass categories:")
            for c, n in sorted(cats.items(), key=lambda x: -x[1]):
                recs.append(f"  - {c.replace('_', ' ').title()}: {n}")

        self.results['recommendations'] = recs

    def generate_report(self):
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("WAF DETECTION & BYPASS REPORT (FAST MODE)\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:    {self.target}\n")
            f.write(f"Scan Date: {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"Threads:   {self.threads}\n")
            f.write("=" * 80 + "\n\n")

            f.write("WAF DETECTION\n" + "-" * 50 + "\n")
            if self.results['waf_detected']:
                f.write(f"WAF:        {self.results['waf_name']}\n")
                f.write(f"Confidence: {self.results['waf_confidence']}\n")
                for ev in self.results['waf_evidence']:
                    f.write(f"  • {ev}\n")
            else:
                f.write("No WAF detected\n")
            f.write("\n")

            f.write("BYPASS RESULTS\n" + "-" * 50 + "\n")
            f.write(f"Total tested:  {len(self.results['bypass_results'])}\n")
            f.write(f"Successful:    {len(self.results['successful_bypasses'])}\n")
            f.write(f"Blocked:       {len(self.results['failed_bypasses'])}\n")
            f.write(f"Bypass rate:   {self.results['bypass_rate']:.1f}%\n\n")

            if self.results['successful_bypasses']:
                f.write("SUCCESSFUL BYPASSES\n" + "-" * 50 + "\n")
                for b in self.results['successful_bypasses']:
                    f.write(f"  [{b['category']}] {b['payload'][:80]}\n")
                    f.write(f"     HTTP {b['status_code']} — {b['response_length']} bytes\n")
                f.write("\n")

            f.write("WAF STRENGTH\n" + "-" * 50 + "\n")
            f.write(f"Rating:      {self.results['waf_strength']}\n")
            f.write(f"Bypass rate: {self.results['bypass_rate']:.1f}%\n\n")

            f.write("RECOMMENDATIONS\n" + "-" * 50 + "\n")
            for r in self.results['recommendations']:
                f.write(f"  • {r}\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("Generated by Fast WAF Detector — Project #13\n")
            f.write("=" * 80 + "\n")

        print(f"\n{Colors.GREEN}[✓] Report saved to: {self.output_file}{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # MAIN
    # ------------------------------------------------------------------ #
    def scan(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] WAF Detection (FAST MODE){Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Target: {self.target}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Threads: {self.threads} | "
              f"Delay: {self.delay}s | Timeout: {self.timeout}s{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Started: {datetime.now():%Y-%m-%d %H:%M:%S}{Colors.RESET}\n")

        start = time.time()
        ok, response = self.test_connection()
        if not ok:
            return

        self.detect_waf(response)
        self.test_bypasses()
        self.assess_waf_strength()
        self.generate_recommendations()

        print(f"\n{Colors.BOLD}{Colors.GREEN}[📋] RECOMMENDATIONS:{Colors.RESET}")
        for r in self.results['recommendations']:
            print(f"  {Colors.CYAN}•{Colors.RESET} {r}")

        self.generate_report()

        print(f"\n{Colors.GREEN}[✓] Total time: {time.time() - start:.2f}s{Colors.RESET}")

def main():
    p = argparse.ArgumentParser(
        description="Fast WAF Detection & Evasion Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default (fast sample, 10 threads)
  python waf_detector_fast.py https://www.cloudflare.com

  # More threads, no delay (max speed)
  python waf_detector_fast.py https://www.cloudflare.com -T 20 --delay 0

  # Test EVERY payload (slower, complete)
  python waf_detector_fast.py https://www.cloudflare.com --full

  # Verbose output
  python waf_detector_fast.py https://www.cloudflare.com -v
        """
    )
    p.add_argument('target', help='Target URL')
    p.add_argument('-t', '--timeout', type=int, default=5,
                   help='Request timeout (default: 5s)')
    p.add_argument('-T', '--threads', type=int, default=10,
                   help='Concurrent threads (default: 10)')
    p.add_argument('--delay', type=float, default=0.05,
                   help='Delay between requests per thread (default: 0.05s)')
    p.add_argument('--full', action='store_true',
                   help='Test ALL payloads instead of smart sample')
    p.add_argument('-o', '--output', default='waf_bypass_report.txt',
                   help='Output file name')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='Verbose output')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    WAF DETECTION & EVASION TOOL (FAST MODE)")
    print("    Project #13: Web Application Firewall Detection & Bypass")
    print("=" * 70 + f"{Colors.RESET}\n")

    detector = FastWAFDetector(
        target=args.target,
        timeout=args.timeout,
        output_file=args.output,
        verbose=args.verbose,
        threads=args.threads,
        delay=args.delay,
        full=args.full
    )
    detector.scan()

if __name__ == "__main__":
    main()