#!/usr/bin/env python3
"""
REST API Security Scanner
Project #14: API Security Testing Tool
"""

import requests
import sys
import json
import time
import re
import threading
import argparse
import urllib3
from urllib.parse import urljoin, urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes
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

class APISecurityScanner:
    def __init__(self, target, timeout=10, output_file="api_security_report.txt",
                 verbose=False, threads=10):
        """
        Initialize the API Security Scanner

        Args:
            target: Base URL of the API
            timeout: Request timeout
            output_file: Output file name
            verbose: Enable verbose output
            threads: Number of threads
        """
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target

        self.target = target.rstrip('/')
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        self.threads = threads

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Content-Type': 'application/json',
        })

        # Results storage
        self.results = {
            'target': self.target,
            'swagger_found': False,
            'swagger_url': None,
            'discovered_endpoints': [],
            'tested_endpoints': [],
            'vulnerabilities': [],
            'sensitive_data': [],
            'rate_limit_test': {},
            'auth_tests': []
        }

        # Common API endpoints to test
        self.common_endpoints = [
            '/api/v1/users',
            '/api/v1/user',
            '/api/v1/user/1',
            '/api/v1/admin',
            '/api/v1/login',
            '/api/v1/register',
            '/api/v1/health',
            '/api/v1/status',
            '/api/v1/config',
            '/api/v1/debug',
            '/api/v1/metrics',
            '/api/v1/accounts',
            '/api/v1/profile',
            '/api/v1/me',
            '/api/v1/auth',
            '/api/v1/token',
            '/api/v1/orders',
            '/api/v1/products',
            '/api/v1/items',
            '/api/v1/posts',
            '/api/v1/comments',
            '/api/v1/settings',
            '/api/v1/info',
            '/api/v1/version',
            '/api/users',
            '/api/user/1',
            '/api/admin',
            '/api/login',
            '/users',
            '/user/1',
            '/admin',
            '/login',
            '/health',
            '/status',
            '/metrics',
        ]

        # Swagger/OpenAPI paths
        self.swagger_paths = [
            '/swagger.json',
            '/swagger.yaml',
            '/swagger/v1/swagger.json',
            '/api-docs',
            '/api-docs.json',
            '/openapi.json',
            '/openapi.yaml',
            '/v1/swagger.json',
            '/v2/swagger.json',
            '/api/swagger.json',
            '/api/openapi.json',
            '/docs',
            '/redoc',
        ]

        # Common weak credentials
        self.weak_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('test', 'test'),
            ('test', 'password'),
            ('user', 'user'),
            ('user', 'password'),
            ('root', 'root'),
            ('root', 'password'),
            ('guest', 'guest'),
        ]

        # Sensitive data patterns
        self.sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'api_key': r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})',
            'password': r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s,}]{3,})',
            'token': r'(?i)(token|bearer|jwt)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{16,})',
            'aws_key': r'(?i)(AKIA[0-9A-Z]{16})',
            'private_key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        }

        self.baseline_response = None
        self.baseline_status = None
        self.found_swagger = None

    # ------------------------------------------------------------------ #
    # DISCOVERY
    # ------------------------------------------------------------------ #
    def test_connection(self):
        """Test if target is reachable"""
        print(f"{Colors.BOLD}[*] Testing connection to {self.target}...{Colors.RESET}")
        try:
            r = self.session.get(self.target, timeout=self.timeout, verify=False)
            self.baseline_response = r
            self.baseline_status = r.status_code
            print(f"{Colors.GREEN}[✓] Reachable — Status: {r.status_code}{Colors.RESET}")
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Cannot reach target: {str(e)[:60]}{Colors.RESET}")
            return False

    def discover_swagger(self):
        """Discover Swagger/OpenAPI documentation"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Looking for Swagger/OpenAPI docs...{Colors.RESET}")

        for path in self.swagger_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.get(url, timeout=self.timeout, verify=False)
                if r.status_code == 200:
                    content_type = r.headers.get('Content-Type', '').lower()
                    if 'json' in content_type or 'yaml' in content_type or r.text.strip().startswith('{'):
                        try:
                            data = r.json()
                            if 'swagger' in data or 'openapi' in data or 'paths' in data:
                                self.results['swagger_found'] = True
                                self.results['swagger_url'] = url
                                self.found_swagger = data
                                print(f"{Colors.GREEN}[✓] Swagger found: {url}{Colors.RESET}")

                                # Extract endpoints from swagger
                                paths = data.get('paths', {})
                                for ep_path in paths:
                                    self.results['discovered_endpoints'].append(ep_path)
                                    print(f"    {Colors.CYAN}•{Colors.RESET} {ep_path}")
                                return True
                        except json.JSONDecodeError:
                            pass
            except Exception:
                continue

        print(f"{Colors.YELLOW}[!] No Swagger/OpenAPI found{Colors.RESET}")
        return False

    def discover_endpoints(self):
        """Discover common API endpoints"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Discovering API endpoints...{Colors.RESET}")

        found = set(self.results['discovered_endpoints'])
        lock = threading.Lock()

        def check_endpoint(path):
            url = urljoin(self.target, path)
            try:
                r = self.session.get(url, timeout=self.timeout, verify=False,
                                     allow_redirects=False)
                if r.status_code in [200, 201, 204, 301, 302, 401, 403, 405]:
                    return {
                        'path': path,
                        'url': url,
                        'status': r.status_code,
                        'length': len(r.content),
                        'content_type': r.headers.get('Content-Type', '')
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_endpoint, p): p for p in self.common_endpoints}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    with lock:
                        found.add(result['path'])
                        self.results['tested_endpoints'].append(result)
                        color = Colors.GREEN if result['status'] == 200 else Colors.YELLOW
                        print(f"  {color}[{result['status']}]{Colors.RESET} {result['path']} "
                              f"({result['length']} bytes)")

        self.results['discovered_endpoints'] = list(found)
        print(f"\n{Colors.GREEN}[✓] Total endpoints found: {len(found)}{Colors.RESET}")
        return found

    # ------------------------------------------------------------------ #
    # AUTH TESTS
    # ------------------------------------------------------------------ #
    def test_authentication(self, endpoint):
        """Test authentication on an endpoint"""
        url = urljoin(self.target, endpoint)
        result = {
            'endpoint': endpoint,
            'url': url,
            'no_auth': None,
            'weak_creds': [],
            'auth_required': None
        }

        # Test 1: No authentication
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            result['no_auth'] = {
                'status': r.status_code,
                'length': len(r.content),
                'accessible': r.status_code in [200, 201, 204]
            }

            if r.status_code in [200, 201, 204]:
                print(f"  {Colors.RED}[!] No auth required: {endpoint}{Colors.RESET}")
                self.results['vulnerabilities'].append({
                    'type': 'Missing Authentication',
                    'endpoint': endpoint,
                    'severity': 'HIGH',
                    'description': f'Endpoint accessible without authentication (HTTP {r.status_code})'
                })
            elif r.status_code in [401, 403]:
                result['auth_required'] = True
                print(f"  {Colors.GREEN}[✓] Auth required: {endpoint} ({r.status_code}){Colors.RESET}")

        except Exception as e:
            result['no_auth'] = {'error': str(e)[:50]}

        # Test 2: Weak credentials on login endpoints
        if any(kw in endpoint.lower() for kw in ['login', 'auth', 'token', 'signin']):
            print(f"  {Colors.YELLOW}[*] Testing weak credentials...{Colors.RESET}")
            for username, password in self.weak_credentials[:5]:
                try:
                    r = self.session.post(
                        url,
                        json={'username': username, 'password': password},
                        timeout=self.timeout,
                        verify=False
                    )
                    if r.status_code in [200, 201]:
                        result['weak_creds'].append({
                            'username': username,
                            'password': password,
                            'status': r.status_code
                        })
                        print(f"    {Colors.RED}[!] WEAK CREDS: {username}/{password} "
                              f"-> {r.status_code}{Colors.RESET}")
                        self.results['vulnerabilities'].append({
                            'type': 'Weak Credentials',
                            'endpoint': endpoint,
                            'severity': 'CRITICAL',
                            'description': f'Weak credentials accepted: {username}/{password}'
                        })
                        break
                    else:
                        if self.verbose:
                            print(f"    {Colors.GREEN}✓{Colors.RESET} {username}/{password} -> {r.status_code}")
                except Exception:
                    continue

        self.results['auth_tests'].append(result)
        return result

    # ------------------------------------------------------------------ #
    # IDOR
    # ------------------------------------------------------------------ #
    def test_idor(self, endpoint):
        """Test for IDOR vulnerabilities"""
        if '{id}' not in endpoint and not re.search(r'/\d+', endpoint):
            return None

        print(f"  {Colors.YELLOW}[*] Testing IDOR on {endpoint}{Colors.RESET}")

        # Extract base path and ID
        match = re.search(r'^(.*?)(\d+)(.*)$', endpoint)
        if not match:
            return None

        base, original_id, suffix = match.groups()

        vulnerable_ids = []
        tested = 0

        # Test different IDs
        for test_id in [1, 2, 3, 10, 100, 999]:
            if str(test_id) == original_id:
                continue

            test_path = f"{base}{test_id}{suffix}"
            url = urljoin(self.target, test_path)

            try:
                r = self.session.get(url, timeout=self.timeout, verify=False)
                tested += 1
                if r.status_code == 200 and len(r.content) > 10:
                    vulnerable_ids.append({
                        'id': test_id,
                        'status': r.status_code,
                        'length': len(r.content)
                    })
                    print(f"    {Colors.RED}[!] ID {test_id} accessible ({len(r.content)} bytes){Colors.RESET}")
            except Exception:
                pass

        if len(vulnerable_ids) >= 2:
            self.results['vulnerabilities'].append({
                'type': 'IDOR',
                'endpoint': endpoint,
                'severity': 'HIGH',
                'description': f'Accessible IDs: {[v["id"] for v in vulnerable_ids]}',
                'details': vulnerable_ids
            })
            print(f"  {Colors.RED}[!] IDOR VULNERABLE: {endpoint}{Colors.RESET}")
            return vulnerable_ids

        print(f"  {Colors.GREEN}[✓] No IDOR detected on {endpoint}{Colors.RESET}")
        return None

    # ------------------------------------------------------------------ #
    # RATE LIMIT
    # ------------------------------------------------------------------ #
    def test_rate_limit(self, endpoint, num_requests=50):
        """Test rate limiting"""
        print(f"\n  {Colors.YELLOW}[*] Testing rate limit on {endpoint} "
              f"({num_requests} requests)...{Colors.RESET}")

        url = urljoin(self.target, endpoint)
        statuses = defaultdict(int)
        start = time.time()
        blocked_at = None

        for i in range(num_requests):
            try:
                r = self.session.get(url, timeout=self.timeout, verify=False)
                statuses[r.status_code] += 1
                if r.status_code == 429 and blocked_at is None:
                    blocked_at = i + 1
                    print(f"    {Colors.GREEN}[✓] Rate limit hit at request {i+1}{Colors.RESET}")
                    break
            except Exception:
                pass

        elapsed = time.time() - start
        rate = num_requests / elapsed if elapsed > 0 else 0

        result = {
            'endpoint': endpoint,
            'total_requests': num_requests,
            'completed_in': round(elapsed, 2),
            'rate_per_second': round(rate, 2),
            'status_codes': dict(statuses),
            'rate_limited': blocked_at is not None,
            'blocked_at': blocked_at
        }

        if not blocked_at:
            print(f"    {Colors.RED}[!] NO RATE LIMITING detected{Colors.RESET}")
            self.results['vulnerabilities'].append({
                'type': 'No Rate Limiting',
                'endpoint': endpoint,
                'severity': 'MEDIUM',
                'description': f'{num_requests} requests completed without rate limiting'
            })
        else:
            print(f"    {Colors.GREEN}✓ Rate limiting active{Colors.RESET}")

        self.results['rate_limit_test'] = result
        return result

    # ------------------------------------------------------------------ #
    # DATA EXPOSURE
    # ------------------------------------------------------------------ #
    def check_sensitive_data(self, endpoint):
        """Check for sensitive data in response"""
        url = urljoin(self.target, endpoint)
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            if r.status_code != 200:
                return None

            text = r.text
            findings = []

            for data_type, pattern in self.sensitive_patterns.items():
                matches = re.findall(pattern, text)
                if matches:
                    # Limit and clean matches
                    unique_matches = list(set(str(m)[:50] for m in matches[:5]))
                    findings.append({
                        'type': data_type,
                        'count': len(matches),
                        'samples': unique_matches
                    })

            if findings:
                print(f"  {Colors.YELLOW}[!] Sensitive data in {endpoint}:{Colors.RESET}")
                for f in findings:
                    print(f"    {Colors.YELLOW}•{Colors.RESET} {f['type']}: "
                          f"{f['count']} occurrences")

                self.results['sensitive_data'].append({
                    'endpoint': endpoint,
                    'findings': findings
                })

                # Add vuln for important findings
                for f in findings:
                    if f['type'] in ['email', 'credit_card', 'ssn', 'password', 'api_key']:
                        self.results['vulnerabilities'].append({
                            'type': 'Sensitive Data Exposure',
                            'endpoint': endpoint,
                            'severity': 'HIGH' if f['type'] in ['credit_card', 'ssn', 'password'] else 'MEDIUM',
                            'description': f'{f["type"]} exposed ({f["count"]} occurrences)'
                        })

            return findings
        except Exception as e:
            if self.verbose:
                print(f"  {Colors.YELLOW}[!] Error checking {endpoint}: {str(e)[:40]}{Colors.RESET}")
            return None

    # ------------------------------------------------------------------ #
    # MAIN SCAN
    # ------------------------------------------------------------------ #
    def scan(self):
        """Main scan method"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] REST API Security Scanner{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Target: {self.target}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Started: {datetime.now():%Y-%m-%d %H:%M:%S}{Colors.RESET}\n")

        start = time.time()

        if not self.test_connection():
            print(f"{Colors.RED}[!] Cannot proceed — target unreachable{Colors.RESET}")
            return

        # Phase 1: Discovery
        self.discover_swagger()
        self.discover_endpoints()

        if not self.results['discovered_endpoints']:
            print(f"\n{Colors.YELLOW}[!] No endpoints discovered. Try a different target.{Colors.RESET}")
            return

        # Phase 2: Authentication tests
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Testing authentication...{Colors.RESET}")
        auth_endpoints = [e for e in self.results['discovered_endpoints']
                         if any(kw in e.lower() for kw in ['user', 'admin', 'auth', 'login', 'me', 'profile'])]
        for ep in auth_endpoints[:5]:
            self.test_authentication(ep)

        # Phase 3: IDOR tests
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Testing IDOR...{Colors.RESET}")
        idor_endpoints = [e for e in self.results['discovered_endpoints']
                         if re.search(r'/\d+', e)]
        if not idor_endpoints:
            # Add a test endpoint with ID
            idor_endpoints = ['/api/v1/user/1']
        for ep in idor_endpoints[:3]:
            self.test_idor(ep)

        # Phase 4: Rate limiting
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Testing rate limiting...{Colors.RESET}")
        # Choose a simple endpoint
        test_ep = next((e for e in self.results['discovered_endpoints']
                       if 'health' in e.lower() or 'status' in e.lower()), None)
        if not test_ep:
            test_ep = self.results['discovered_endpoints'][0]
        self.test_rate_limit(test_ep, num_requests=30)

        # Phase 5: Sensitive data
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Checking for sensitive data...{Colors.RESET}")
        for ep in self.results['discovered_endpoints'][:5]:
            self.check_sensitive_data(ep)

        # Summary
        self.print_summary()

        # Save report
        self.save_report()

        print(f"\n{Colors.GREEN}[✓] Scan completed in {time.time() - start:.2f} seconds{Colors.RESET}")
        print(f"{Colors.GREEN}[✓] Report saved to: {self.output_file}{Colors.RESET}")

    def print_summary(self):
        """Print summary"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.GREEN}[📊] SCAN SUMMARY{Colors.RESET}")
        print("=" * 70)

        print(f"{Colors.BOLD}Swagger found: {self.results['swagger_found']}{Colors.RESET}")
        print(f"{Colors.BOLD}Endpoints found: {len(self.results['discovered_endpoints'])}{Colors.RESET}")
        print(f"{Colors.BOLD}Vulnerabilities: {len(self.results['vulnerabilities'])}{Colors.RESET}")
        print(f"{Colors.BOLD}Sensitive data findings: {len(self.results['sensitive_data'])}{Colors.RESET}")

        if self.results['vulnerabilities']:
            print(f"\n{Colors.RED}{Colors.BOLD}[⚠️] VULNERABILITIES:{Colors.RESET}")

            # Group by severity
            by_severity = defaultdict(list)
            for v in self.results['vulnerabilities']:
                by_severity[v['severity']].append(v)

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity in by_severity:
                    sev_color = Colors.RED if severity in ['CRITICAL', 'HIGH'] else Colors.YELLOW
                    print(f"\n  {sev_color}[{severity}]{Colors.RESET}")
                    for v in by_severity[severity]:
                        print(f"    • {v['type']}: {v['endpoint']}")
                        print(f"      {v['description']}")

    def save_report(self):
        """Save report to file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("REST API SECURITY SCAN REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:      {self.target}\n")
            f.write(f"Scan Date:   {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write("=" * 80 + "\n\n")

            # Discovery
            f.write("API DISCOVERY\n")
            f.write("-" * 50 + "\n")
            f.write(f"Swagger/OpenAPI: {'Yes — ' + str(self.results['swagger_url']) if self.results['swagger_found'] else 'No'}\n")
            f.write(f"Endpoints found: {len(self.results['discovered_endpoints'])}\n")
            for ep in self.results['discovered_endpoints']:
                f.write(f"  • {ep}\n")
            f.write("\n")

            # Endpoint status
            if self.results['tested_endpoints']:
                f.write("ENDPOINT STATUS\n")
                f.write("-" * 50 + "\n")
                for ep in self.results['tested_endpoints']:
                    f.write(f"  [{ep['status']}] {ep['path']} — {ep['length']} bytes\n")
                f.write("\n")

            # Vulnerabilities
            f.write("VULNERABILITIES\n")
            f.write("-" * 50 + "\n")
            if self.results['vulnerabilities']:
                for i, v in enumerate(self.results['vulnerabilities'], 1):
                    f.write(f"{i}. [{v['severity']}] {v['type']}\n")
                    f.write(f"   Endpoint: {v['endpoint']}\n")
                    f.write(f"   Description: {v['description']}\n\n")
            else:
                f.write("  None detected\n\n")

            # Sensitive data
            f.write("SENSITIVE DATA EXPOSURE\n")
            f.write("-" * 50 + "\n")
            if self.results['sensitive_data']:
                for sd in self.results['sensitive_data']:
                    f.write(f"  Endpoint: {sd['endpoint']}\n")
                    for finding in sd['findings']:
                        f.write(f"    • {finding['type']}: {finding['count']} occurrences\n")
                    f.write("\n")
            else:
                f.write("  None detected\n\n")

            # Rate limit
            if self.results['rate_limit_test']:
                rl = self.results['rate_limit_test']
                f.write("RATE LIMIT TEST\n")
                f.write("-" * 50 + "\n")
                f.write(f"  Endpoint: {rl['endpoint']}\n")
                f.write(f"  Requests: {rl['total_requests']}\n")
                f.write(f"  Completed in: {rl['completed_in']}s\n")
                f.write(f"  Rate: {rl['rate_per_second']} req/s\n")
                f.write(f"  Rate Limited: {rl['rate_limited']}\n")
                f.write("\n")

            f.write("=" * 80 + "\n")
            f.write("Generated by API Security Scanner — Project #14\n")
            f.write("=" * 80 + "\n")

        print(f"\n{Colors.GREEN}[✓] Report saved to: {self.output_file}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="REST API Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a public test API
  python api_security_scanner.py https://jsonplaceholder.typicode.com

  # Scan with verbose output
  python api_security_scanner.py https://jsonplaceholder.typicode.com -v

  # Custom output file
  python api_security_scanner.py https://jsonplaceholder.typicode.com -o my_report.txt
        """
    )

    parser.add_argument('target', help='Target API base URL')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('-o', '--output', default='api_security_report.txt', help='Output file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-T', '--threads', type=int, default=10, help='Threads (default 10)')

    args = parser.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    REST API SECURITY SCANNER")
    print("    Project #14: API Security Testing Tool")
    print("=" * 70 + f"{Colors.RESET}\n")

    scanner = APISecurityScanner(
        target=args.target,
        timeout=args.timeout,
        output_file=args.output,
        verbose=args.verbose,
        threads=args.threads
    )
    scanner.scan()

if __name__ == "__main__":
    main()