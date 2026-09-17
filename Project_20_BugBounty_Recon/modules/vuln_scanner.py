"""
Phase 4: Basic Vulnerability Scanner
XSS, SQLi, Open Redirect — light, non-invasive checks
"""

import re
import time
import requests
import urllib3
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class VulnScanner:
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        "'\"><svg/onload=alert(1)>",
    ]

    SQLI_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "1' AND SLEEP(0)--",
    ]

    SQLI_ERRORS = [
        r'SQL syntax.*MySQL', r'Warning.*MySQL', r'PostgreSQL.*ERROR',
        r'ORA-[0-9]{5}', r'Microsoft OLE DB Provider',
        r'Unclosed quotation mark', r'You have an error in your SQL syntax',
        r'SQLSTATE', r'PDOException',
    ]

    REDIRECT_PARAMS = ['url', 'redirect', 'next', 'return', 'returnUrl',
                       'return_url', 'dest', 'destination', 'go', 'target',
                       'redir', 'view', 'link', 'goto']

    def __init__(self, urls, timeout=5, verbose=False):
        self.urls = urls
        self.timeout = timeout
        self.verbose = verbose

        self.findings = {
            'xss': [],
            'sqli': [],
            'open_redirect': [],
            'sensitive_params': [],
        }

    # ------------------------------------------------------------------ #
    # XSS
    # ------------------------------------------------------------------ #
    def test_xss(self, url, param):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for payload in self.XSS_PAYLOADS:
            qs[param] = payload
            new_qs = urlencode(qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_qs))
            try:
                r = requests.get(test_url, timeout=self.timeout, verify=False,
                                 headers={'User-Agent': 'Mozilla/5.0'})
                if payload in r.text:
                    return {
                        'type': 'Reflected XSS',
                        'url': url,
                        'param': param,
                        'payload': payload,
                    }
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------ #
    # SQLi
    # ------------------------------------------------------------------ #
    def test_sqli(self, url, param):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for payload in self.SQLI_PAYLOADS:
            qs[param] = payload
            new_qs = urlencode(qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_qs))
            try:
                r = requests.get(test_url, timeout=self.timeout, verify=False,
                                 headers={'User-Agent': 'Mozilla/5.0'})
                for pattern in self.SQLI_ERRORS:
                    if re.search(pattern, r.text, re.IGNORECASE):
                        return {
                            'type': 'SQL Injection (error-based)',
                            'url': url,
                            'param': param,
                            'payload': payload,
                            'evidence': pattern,
                        }
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------ #
    # OPEN REDIRECT
    # ------------------------------------------------------------------ #
    def test_open_redirect(self, url, param):
        if param.lower() not in self.REDIRECT_PARAMS:
            return None
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        test_payload = 'https://example.org/evil'
        qs[param] = test_payload
        new_qs = urlencode(qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_qs))
        try:
            r = requests.get(test_url, timeout=self.timeout, verify=False,
                             allow_redirects=False,
                             headers={'User-Agent': 'Mozilla/5.0'})
            location = r.headers.get('Location', '')
            if test_payload in location:
                return {
                    'type': 'Open Redirect',
                    'url': url,
                    'param': param,
                    'payload': test_payload,
                    'location': location,
                }
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    # MAIN
    # ------------------------------------------------------------------ #
    def run(self, parameters):
        print(f"\n{Colors.BOLD}{Colors.CYAN}===== PHASE 4: VULNERABILITY SCAN ====={Colors.RESET}")
        print(f"    Testing {len(self.urls)} URLs for {len(parameters)} params")

        tested = 0
        # Cap URLs to keep runtime reasonable
        for url in list(self.urls)[:200]:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            params = [p for p in parse_qs(parsed.query).keys()]
            for param in params:
                tested += 1

                # XSS
                xss = self.test_xss(url, param)
                if xss:
                    self.findings['xss'].append(xss)
                    print(f"    {Colors.RED}[XSS]{Colors.RESET} {url[:80]} "
                          f"({param})")

                # SQLi
                sqli = self.test_sqli(url, param)
                if sqli:
                    self.findings['sqli'].append(sqli)
                    print(f"    {Colors.RED}[SQLi]{Colors.RESET} {url[:80]} "
                          f"({param})")

                # Open Redirect
                redir = self.test_open_redirect(url, param)
                if redir:
                    self.findings['open_redirect'].append(redir)
                    print(f"    {Colors.RED}[REDIR]{Colors.RESET} {url[:80]} "
                          f"({param})")

        print(f"\n    Tested: {tested} URL+param combinations")
        print(f"    XSS: {len(self.findings['xss'])}")
        print(f"    SQLi: {len(self.findings['sqli'])}")
        print(f"    Open Redirect: {len(self.findings['open_redirect'])}")

        return self.findings