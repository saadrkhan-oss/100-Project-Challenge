"""
Phase 3: Content Discovery
Wayback URLs + basic crawling + interesting path extraction
"""

import re
import time
import requests
import urllib3
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class ContentDiscovery:
    INTERESTING_KEYWORDS = [
        'admin', 'login', 'signin', 'auth', 'api', 'v1', 'v2',
        'backup', 'config', 'settings', 'debug', 'test', 'dev',
        'staging', 'internal', 'private', 'upload', 'download',
        'file', 'doc', 'docs', 'swagger', 'openapi', 'graphql',
        'phpmyadmin', 'cpanel', 'wp-admin', 'dashboard',
        'console', 'manage', 'manager', 'portal', 'token',
        'key', 'secret', 'password', 'passwd', '.env', '.git',
    ]

    def __init__(self, domain, live_hosts=None, timeout=10,
                 threads=10, verbose=False):
        self.domain = domain
        self.live_hosts = live_hosts or []
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose

        self.urls = set()
        self.interesting = set()
        self.parameters = set()

    # ------------------------------------------------------------------ #
    # WAYBACK MACHINE
    # ------------------------------------------------------------------ #
    def from_wayback(self):
        """Get URLs from Wayback Machine CDX API."""
        print(f"    Querying Wayback Machine...")
        found = set()
        try:
            url = (f"http://web.archive.org/cdx/search/cdx?"
                   f"url=*.{self.domain}/*&output=json&"
                   f"fl=original&collapse=urlkey&limit=5000")
            r = requests.get(url, timeout=60, verify=False,
                             headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                try:
                    data = r.json()
                    # First row is headers
                    for row in data[1:]:
                        if row and row[0]:
                            found.add(row[0])
                except Exception:
                    pass
            print(f"      Wayback: {len(found)} URLs")
        except Exception as e:
            print(f"      Wayback error: {str(e)[:60]}")
        return found

    # ------------------------------------------------------------------ #
    # CRAWLING (light)
    # ------------------------------------------------------------------ #
    def crawl_site(self, base_url, max_pages=30):
        """Crawl a single base URL (limited)."""
        if BeautifulSoup is None:
            return set()

        found = set()
        to_visit = [base_url]
        visited = set()

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                r = requests.get(url, timeout=self.timeout, verify=False,
                                 allow_redirects=True,
                                 headers={'User-Agent': 'Mozilla/5.0'})
                if 'text/html' not in r.headers.get('Content-Type', ''):
                    continue
                soup = BeautifulSoup(r.text, 'html.parser')
                for a in soup.find_all('a', href=True):
                    link = urljoin(url, a['href'])
                    if urlparse(link).netloc == urlparse(base_url).netloc:
                        if link not in visited:
                            to_visit.append(link)
                        found.add(link)
            except Exception:
                continue
        return found

    # ------------------------------------------------------------------ #
    # PARAMETER EXTRACTION
    # ------------------------------------------------------------------ #
    def extract_parameters(self, urls):
        """Extract query parameters from URLs."""
        params = set()
        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                for pair in parsed.query.split('&'):
                    if '=' in pair:
                        params.add(pair.split('=')[0])
        return params

    def is_interesting(self, url):
        low = url.lower()
        return any(kw in low for kw in self.INTERESTING_KEYWORDS)

    # ------------------------------------------------------------------ #
    # MAIN
    # ------------------------------------------------------------------ #
    def run(self):
        print(f"\n{Colors.BOLD}{Colors.CYAN}===== PHASE 3: CONTENT DISCOVERY ====={Colors.RESET}")

        # Wayback
        wb = self.from_wayback()
        self.urls.update(wb)

        # Crawl live hosts (max 5 to keep it fast)
        crawl_targets = []
        for host_info in self.live_hosts[:5]:
            host = host_info['host']
            for p in host_info.get('ports', []):
                if p['port'] == 443:
                    crawl_targets.append(f"https://{host}")
                elif p['port'] == 80:
                    crawl_targets.append(f"http://{host}")
                elif p['port'] == 8080:
                    crawl_targets.append(f"http://{host}:8080")
                elif p['port'] == 8443:
                    crawl_targets.append(f"https://{host}:8443")

        print(f"    Crawling {len(crawl_targets)} live URL(s)...")
        for target in crawl_targets:
            try:
                found = self.crawl_site(target, max_pages=20)
                self.urls.update(found)
            except Exception:
                pass

        print(f"    Total URLs: {len(self.urls)}")

        # Extract interesting
        for u in self.urls:
            if self.is_interesting(u):
                self.interesting.add(u)

        # Extract parameters
        self.parameters = self.extract_parameters(self.urls)
        print(f"    Interesting URLs: {len(self.interesting)}")
        print(f"    Unique parameters: {len(self.parameters)}")

        return {
            'urls': sorted(self.urls),
            'interesting': sorted(self.interesting),
            'parameters': sorted(self.parameters),
        }