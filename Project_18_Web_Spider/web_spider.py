#!/usr/bin/env python3
"""
Advanced Web Spider & Content Discovery (FIXED)
Project #18: Web Application Crawler & Spider

LEGAL: Only crawl sites you own or have explicit permission to test.
       Respect robots.txt and rate limits.
"""

import requests
import sys
import re
import json
import csv
import time
import argparse
import urllib3
import threading
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
from urllib.robotparser import RobotFileParser
from datetime import datetime
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing beautifulsoup4. Install: pip install beautifulsoup4")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------- #
# COLORS
# ---------------------------------------------------------------------- #
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/17.1 Safari/605.1.15',
]

# ---------------------------------------------------------------------- #
# MAIN SPIDER
# ---------------------------------------------------------------------- #
class WebSpider:
    def __init__(self, target, max_depth=3, max_pages=200,
                 domain_restriction=True, delay=0.5, threads=5,
                 respect_robots=True, output_prefix='spider',
                 verbose=False):
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        self.target = target.rstrip('/')

        parsed = urlparse(self.target)
        self.base_domain = parsed.netloc
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

        self.max_depth = max_depth
        self.max_pages = max_pages
        self.domain_restriction = domain_restriction
        self.delay = delay
        self.threads = threads
        self.respect_robots = respect_robots
        self.output_prefix = output_prefix
        self.verbose = verbose

        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=threads * 2, pool_maxsize=threads * 2
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.robots = RobotFileParser()

        self.visited = set()
        self.queued = set()
        self.lock = threading.Lock()

        self.pages = []
        self.internal_urls = set()
        self.external_urls = set()
        self.forms = []
        self.js_files = set()
        self.css_files = set()
        self.images = set()
        self.api_endpoints = set()
        self.sensitive_found = []
        self.technologies = {}
        self.errors = []
        self.ua_index = 0

        # FIX: always initialize so attribute exists
        self.crawl_time = 0.0

        # Sensitive paths
        self.sensitive_paths = [
            'robots.txt', 'sitemap.xml', 'sitemap.xml.gz',
            '.git/config', '.git/HEAD', '.env', '.env.bak',
            '.htaccess', '.htpasswd', 'web.config',
            'admin/', 'administrator/', 'admin.php',
            'login/', 'login.php', 'wp-login.php',
            'backup/', 'backups/', 'backup.zip', 'backup.tar.gz',
            'backup.sql', 'db.sql', 'dump.sql', 'database.sql',
            'config/', 'config.php', 'config.inc.php',
            'configuration.php', 'settings.php',
            'logs/', 'log/', 'error.log', 'access.log',
            'debug.log', 'phpinfo.php', 'info.php', 'test.php',
            'phpmyadmin/', 'pma/', 'adminer.php',
            'api/', 'api/v1/', 'api/v2/', 'api-docs/',
            'swagger/', 'swagger.json', 'swagger.yaml',
            'openapi.json', 'graphql', 'graphiql',
            'wp-admin/', 'wp-content/', 'wp-includes/',
            'server-status', 'server-info', '.DS_Store',
            'crossdomain.xml', 'clientaccesspolicy.xml',
            'package.json', 'composer.json', 'yarn.lock',
            'readme.md', 'README.md', 'CHANGELOG.md',
            'install/', 'setup/', 'test/', 'dev/', 'staging/',
            'console/', 'shell/', 'cmd.php', 'upload.php',
            'shared/', 'shared/css/', 'shared/img/',
            'images/', 'img/', 'css/', 'js/',
        ]

    # ------------------------------------------------------------------ #
    # HELPERS
    # ------------------------------------------------------------------ #
    def next_ua(self):
        with self.lock:
            ua = USER_AGENTS[self.ua_index % len(USER_AGENTS)]
            self.ua_index += 1
            return ua

    def normalize_url(self, url):
        parsed = urlparse(url)
        parsed = parsed._replace(fragment='')
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_q = '&'.join(f"{k}={v[0]}" for k, v in sorted(params.items()))
            parsed = parsed._replace(query=sorted_q)
        path = parsed.path.rstrip('/') or '/'
        parsed = parsed._replace(path=path)
        return urlunparse(parsed)

    def is_same_domain(self, url):
        try:
            return urlparse(url).netloc == self.base_domain
        except Exception:
            return False

    def should_crawl(self, url):
        if self.domain_restriction and not self.is_same_domain(url):
            return False
        norm = self.normalize_url(url)
        if norm in self.visited or norm in self.queued:
            return False

        # Skip non-HTML resources (but we still record them)
        skip_ext = ('.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
                    '.pdf', '.zip', '.tar', '.gz', '.mp4', '.mp3',
                    '.avi', '.mov', '.woff', '.woff2', '.ttf', '.eot',
                    '.css', '.js', '.xml', '.rss', '.webp', '.bmp',
                    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx')
        if any(norm.lower().endswith(ext) for ext in skip_ext):
            return False

        if self.respect_robots and self.robots:
            try:
                if not self.robots.can_fetch('*', url):
                    return False
            except Exception:
                pass
        return True

    # ------------------------------------------------------------------ #
    # ROBOTS.TXT
    # ------------------------------------------------------------------ #
    def load_robots(self):
        robots_url = f"{self.base_url}/robots.txt"
        try:
            r = self.session.get(
                robots_url,
                headers={'User-Agent': self.next_ua()},
                timeout=10, verify=False
            )
            if r.status_code == 200:
                self.robots.parse(r.text.splitlines())
                print(f"{Colors.GREEN}[✓] robots.txt loaded{Colors.RESET}")
                return True
        except Exception:
            pass

        print(f"{Colors.YELLOW}[!] No robots.txt — crawling all{Colors.RESET}")
        self.robots = None
        return False

    # ------------------------------------------------------------------ #
    # FETCH
    # ------------------------------------------------------------------ #
    def fetch(self, url):
        time.sleep(self.delay)
        headers = {
            'User-Agent': self.next_ua(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        try:
            return self.session.get(
                url, headers=headers, timeout=10,
                verify=False, allow_redirects=True
            )
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Fetch error {url}: {str(e)[:50]}{Colors.RESET}")
            return None

    # ------------------------------------------------------------------ #
    # PARSE PAGE
    # ------------------------------------------------------------------ #
    def parse_page(self, url, response, depth):
        page_info = {
            'url': url,
            'status': response.status_code,
            'content_type': response.headers.get('Content-Type', ''),
            'title': '',
            'depth': depth,
            'size': len(response.content),
            'links': [],
            'forms': [],
            'scripts': [],
        }

        if 'text/html' not in page_info['content_type']:
            return page_info

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception:
            return page_info

        if soup.title and soup.title.string:
            page_info['title'] = soup.title.string.strip()[:100]

        # Extract links
        new_urls = []
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue
            absolute = urljoin(url, href)
            if not absolute.startswith(('http://', 'https://')):
                continue

            if self.is_same_domain(absolute):
                norm = self.normalize_url(absolute)
                self.internal_urls.add(norm)
                page_info['links'].append(norm)
                new_urls.append((norm, depth + 1))
            else:
                self.external_urls.add(absolute)
                page_info['links'].append(absolute)

        # Extract forms
        for form in soup.find_all('form'):
            form_info = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'page': url,
            }
            for inp in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': inp.get('name', ''),
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', '')[:50],
                }
                if input_info['name']:
                    form_info['inputs'].append(input_info)
            if form_info['inputs']:
                # Deduplicate forms by action+method
                key = (form_info['action'], form_info['method'])
                if not any((f['action'], f['method']) == key for f in self.forms):
                    self.forms.append(form_info)
                page_info['forms'].append(form_info)

        # Extract scripts
        for script in soup.find_all('script', src=True):
            src = urljoin(url, script['src'])
            self.js_files.add(src)
            page_info['scripts'].append(src)

        # Extract CSS
        for link in soup.find_all('link', rel='stylesheet'):
            if link.get('href'):
                css = urljoin(url, link['href'])
                self.css_files.add(css)

        # Extract images
        for img in soup.find_all('img', src=True):
            self.images.add(urljoin(url, img['src']))

        # Detect API endpoints
        for pattern in [r'/api/', r'/v\d+/', r'/graphql', r'/rest/']:
            for link in page_info['links']:
                if re.search(pattern, link, re.IGNORECASE):
                    self.api_endpoints.add(link)

        return page_info

    # ------------------------------------------------------------------ #
    # CRAWL WORKER
    # ------------------------------------------------------------------ #
    def crawl_url(self, url, depth):
        norm = self.normalize_url(url)

        with self.lock:
            if norm in self.visited:
                return None
            self.visited.add(norm)
            self.queued.discard(norm)

        response = self.fetch(norm)
        if not response:
            with self.lock:
                self.errors.append({'url': norm, 'error': 'fetch failed'})
            return None

        page_info = self.parse_page(norm, response, depth)

        with self.lock:
            self.pages.append(page_info)
            n = len(self.pages)
            print(f"    {Colors.CYAN}[{n}/{self.max_pages}]{Colors.RESET} "
                  f"[{response.status_code}] {norm[:80]}")

        return page_info

    # ------------------------------------------------------------------ #
    # SENSITIVE PATHS
    # ------------------------------------------------------------------ #
    def check_sensitive_paths(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Checking sensitive paths "
              f"({len(self.sensitive_paths)} paths)...{Colors.RESET}")

        def check(path):
            url = urljoin(self.base_url + '/', path)
            try:
                time.sleep(self.delay)
                r = self.session.get(
                    url,
                    headers={'User-Agent': self.next_ua()},
                    timeout=8, verify=False, allow_redirects=False
                )
                # Only report interesting statuses
                if r.status_code in [200, 301, 302, 401, 403]:
                    # Filter out identical generic 403 pages
                    if r.status_code == 403 and len(r.content) < 100:
                        return None
                    return {
                        'url': url,
                        'path': path,
                        'status': r.status_code,
                        'size': len(r.content),
                    }
            except Exception:
                return None
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(check, p): p for p in self.sensitive_paths}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    self.sensitive_found.append(result)
                    color = (Colors.RED if result['status'] == 200
                             else Colors.YELLOW)
                    print(f"    {color}[{result['status']}]{Colors.RESET} "
                          f"{result['path']} ({result['size']} bytes)")

        # Sort by status (200 first, then others)
        self.sensitive_found.sort(key=lambda x: (x['status'] != 200, x['status']))

    # ------------------------------------------------------------------ #
    # TECHNOLOGY DETECTION
    # ------------------------------------------------------------------ #
    def detect_technologies(self, response):
        headers = response.headers
        tech = {}

        if 'Server' in headers:
            tech['server'] = headers['Server']

        if 'X-Powered-By' in headers:
            tech['powered_by'] = headers['X-Powered-By']

        ct = headers.get('Content-Type', '')
        if 'php' in ct.lower() or (headers.get('X-Powered-By', '').lower().find('php') >= 0):
            tech['language'] = 'PHP'
        elif 'asp.net' in headers.get('X-Powered-By', '').lower():
            tech['language'] = 'ASP.NET'
        elif 'express' in headers.get('X-Powered-By', '').lower():
            tech['language'] = 'Node.js (Express)'

        for h, name in [
            ('X-Drupal-Cache', 'Drupal'),
            ('X-Generator', 'Unknown CMS'),
            ('X-Shopify-Stage', 'Shopify'),
            ('X-Varnish', 'Varnish'),
            ('X-Cache', 'CDN'),
        ]:
            if h in headers:
                tech.setdefault('frameworks', []).append(name)

        if response.text:
            if '/wp-content/' in response.text or '/wp-includes/' in response.text:
                tech['cms'] = 'WordPress'
            elif 'sites/default/files' in response.text:
                tech['cms'] = 'Drupal'
            elif 'joomla' in response.text.lower():
                tech['cms'] = 'Joomla'

            js_frameworks = []
            low = response.text.lower()
            if 'jquery' in low:
                js_frameworks.append('jQuery')
            if 'react' in low:
                js_frameworks.append('React')
            if 'angular' in low:
                js_frameworks.append('Angular')
            if 'vue' in low:
                js_frameworks.append('Vue.js')
            if 'bootstrap' in low:
                js_frameworks.append('Bootstrap')
            if js_frameworks:
                tech['js_frameworks'] = list(set(js_frameworks))

        self.technologies = tech
        return tech

    # ------------------------------------------------------------------ #
    # MAIN CRAWL
    # ------------------------------------------------------------------ #
    def crawl(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}Web Spider Starting{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}Target:    {self.target}{Colors.RESET}")
        print(f"{Colors.BOLD}Max depth: {self.max_depth}{Colors.RESET}")
        print(f"{Colors.BOLD}Max pages: {self.max_pages}{Colors.RESET}")
        print(f"{Colors.BOLD}Domain restriction: "
              f"{'ON' if self.domain_restriction else 'OFF'}{Colors.RESET}")
        print(f"{Colors.BOLD}Rate limit: {self.delay}s{Colors.RESET}")
        print(f"{Colors.BOLD}Threads:   {self.threads}{Colors.RESET}\n")

        start = time.time()

        if self.respect_robots:
            self.load_robots()

        # Fetch homepage (with retry)
        first = None
        for attempt in range(3):
            first = self.fetch(self.target)
            if first:
                break
            print(f"{Colors.YELLOW}[!] Retry {attempt+1}/3...{Colors.RESET}")
            time.sleep(1)

        if not first:
            print(f"{Colors.RED}[!] Cannot reach target after 3 attempts"
                  f"{Colors.RESET}")
            self.crawl_time = time.time() - start
            return  # crawl_time now set

        self.detect_technologies(first)

        # Mark homepage as visited + add to pages
        home_norm = self.normalize_url(self.target)
        self.visited.add(home_norm)
        home_page = self.parse_page(home_norm, first, 0)
        self.pages.append(home_page)
        print(f"    {Colors.CYAN}[1/{self.max_pages}]{Colors.RESET} "
              f"[{first.status_code}] {home_norm[:80]}")

        # BFS queue
        queue = deque()
        for link in home_page['links']:
            if link.startswith(('http://', 'https://')) and self.should_crawl(link):
                norm = self.normalize_url(link)
                if norm not in self.visited and norm not in self.queued:
                    queue.append((link, 1))
                    self.queued.add(norm)

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] CRAWLING PROGRESS{Colors.RESET}")

        # BFS loop
        while queue and len(self.visited) < self.max_pages:
            batch = []
            while queue and len(batch) < self.threads * 2:
                url, depth = queue.popleft()
                if depth > self.max_depth:
                    continue
                if self.normalize_url(url) in self.visited:
                    continue
                batch.append((url, depth))

            if not batch:
                break

            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self.crawl_url, url, depth): (url, depth)
                           for url, depth in batch}

                for fut in as_completed(futures):
                    page = fut.result()
                    if not page:
                        continue

                    # Queue new links from this page
                    if page['depth'] < self.max_depth:
                        for link in page['links']:
                            if not link.startswith(('http://', 'https://')):
                                continue
                            if self.should_crawl(link):
                                norm = self.normalize_url(link)
                                with self.lock:
                                    if norm not in self.visited and norm not in self.queued:
                                        queue.append((link, page['depth'] + 1))
                                        self.queued.add(norm)

                    if len(self.visited) >= self.max_pages:
                        break

        # Set crawl_time BEFORE sensitive scan (in case of error)
        self.crawl_time = time.time() - start

        # Check sensitive paths
        self.check_sensitive_paths()

    # ------------------------------------------------------------------ #
    # REPORTING
    # ------------------------------------------------------------------ #
    def print_summary(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[🔍] DISCOVERED URLS{Colors.RESET}")
        print(f"    Internal:      {len(self.internal_urls)}")
        print(f"    External:      {len(self.external_urls)}")
        print(f"    Forms:         {len(self.forms)}")
        print(f"    API endpoints: {len(self.api_endpoints)}")
        print(f"    JS files:      {len(self.js_files)}")
        print(f"    CSS files:     {len(self.css_files)}")
        print(f"    Images:        {len(self.images)}")
        print(f"    Errors:        {len(self.errors)}")
        print(f"    Time:          {self.crawl_time:.1f}s")

    def print_forms(self):
        if not self.forms:
            return
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] FORMS DISCOVERED{Colors.RESET}")
        for i, form in enumerate(self.forms[:20], 1):
            print(f"\n    Form #{i}: {form['action'][:80]}")
            print(f"        Method: {form['method']}")
            print(f"        Inputs: {', '.join(i['name'] for i in form['inputs'])}")

    def print_sensitive(self):
        if not self.sensitive_found:
            print(f"\n{Colors.BOLD}{Colors.BLUE}[⚠️] SENSITIVE FILES{Colors.RESET}")
            print(f"    {Colors.GREEN}✓ None found{Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[⚠️] SENSITIVE FILES FOUND{Colors.RESET}")
        for item in self.sensitive_found[:30]:
            color = Colors.RED if item['status'] == 200 else Colors.YELLOW
            print(f"    {color}[{item['status']}]{Colors.RESET} "
                  f"{item['path']} ({item['size']} bytes)")

    def print_technologies(self):
        if not self.technologies:
            return
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] TECHNOLOGY DETECTION{Colors.RESET}")
        for k, v in self.technologies.items():
            if isinstance(v, list):
                v = ', '.join(v)
            print(f"    {k.capitalize()}: {v}")

    def print_tree(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📁] SITE STRUCTURE{Colors.RESET}")

        tree = defaultdict(list)
        for url in sorted(self.internal_urls):
            parsed = urlparse(url)
            path = parsed.path
            parts = [p for p in path.split('/') if p]
            if not parts:
                tree['/'].append('/')
            else:
                parent = '/' + '/'.join(parts[:-1]) if len(parts) > 1 else '/'
                tree[parent].append(parts[-1])

        print(f"    {self.base_domain}")
        for path in sorted(tree.keys())[:30]:
            if path == '/':
                for leaf in tree[path]:
                    print(f"    ├── {leaf}")
            else:
                print(f"    ├── {path}")
                for leaf in tree[path][:5]:
                    print(f"    │   └── {leaf}")

    def save_sitemap(self):
        sitemap = {
            'target': self.target,
            'crawled_at': datetime.now().isoformat(),
            'base_domain': self.base_domain,
            'stats': {
                'pages_crawled': len(self.pages),
                'internal_urls': len(self.internal_urls),
                'external_urls': len(self.external_urls),
                'forms': len(self.forms),
                'js_files': len(self.js_files),
                'css_files': len(self.css_files),
                'images': len(self.images),
                'api_endpoints': len(self.api_endpoints),
                'sensitive_found': len(self.sensitive_found),
            },
            'internal_urls': sorted(self.internal_urls),
            'external_urls': sorted(self.external_urls),
            'api_endpoints': sorted(self.api_endpoints),
            'js_files': sorted(self.js_files),
            'css_files': sorted(self.css_files),
            'images': sorted(self.images),
            'forms': self.forms,
            'sensitive_files': self.sensitive_found,
            'technologies': self.technologies,
            'pages': self.pages,
            'errors': self.errors,
        }
        fname = f"{self.output_prefix}_sitemap.json"
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(sitemap, f, indent=2)
        print(f"\n{Colors.GREEN}[✓] Sitemap saved: {fname}{Colors.RESET}")

    def save_urls_csv(self):
        fname = f"{self.output_prefix}_urls.csv"
        with open(fname, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Type', 'Status', 'Depth', 'Title'])
            for page in self.pages:
                writer.writerow([
                    page['url'],
                    'internal' if self.is_same_domain(page['url']) else 'external',
                    page['status'],
                    page['depth'],
                    page.get('title', ''),
                ])
        print(f"{Colors.GREEN}[✓] URLs saved: {fname}{Colors.RESET}")

    def save_report(self):
        fname = f"{self.output_prefix}_report.txt"
        with open(fname, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("WEB SPIDER REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:       {self.target}\n")
            f.write(f"Scan Date:    {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"Duration:     {self.crawl_time:.1f}s\n")
            f.write(f"Max Depth:    {self.max_depth}\n")
            f.write(f"Pages Crawled: {len(self.pages)}\n")
            f.write("=" * 80 + "\n\n")

            f.write("TECHNOLOGIES\n" + "-" * 50 + "\n")
            for k, v in self.technologies.items():
                if isinstance(v, list):
                    v = ', '.join(v)
                f.write(f"  {k}: {v}\n")
            f.write("\n")

            f.write("INTERNAL URLS\n" + "-" * 50 + "\n")
            for u in sorted(self.internal_urls):
                f.write(f"  {u}\n")
            f.write("\n")

            if self.external_urls:
                f.write("EXTERNAL URLS\n" + "-" * 50 + "\n")
                for u in sorted(self.external_urls)[:50]:
                    f.write(f"  {u}\n")
                f.write("\n")

            if self.forms:
                f.write("FORMS\n" + "-" * 50 + "\n")
                for i, form in enumerate(self.forms, 1):
                    f.write(f"  Form #{i}: {form['action']}\n")
                    f.write(f"    Method: {form['method']}\n")
                    f.write(f"    Inputs: {', '.join(i['name'] for i in form['inputs'])}\n\n")

            if self.sensitive_found:
                f.write("SENSITIVE FILES\n" + "-" * 50 + "\n")
                for item in self.sensitive_found:
                    f.write(f"  [{item['status']}] {item['url']} "
                            f"({item['size']} bytes)\n")
                f.write("\n")

            if self.errors:
                f.write("ERRORS\n" + "-" * 50 + "\n")
                for e in self.errors[:20]:
                    f.write(f"  {e['url']} — {e.get('error', '?')}\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("Generated by Web Spider — Project #18\n")
            f.write("=" * 80 + "\n")

        print(f"{Colors.GREEN}[✓] Report saved: {fname}{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # RUN
    # ------------------------------------------------------------------ #
    def run(self):
        try:
            self.crawl()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
            if self.crawl_time == 0.0:
                self.crawl_time = 0.0
        except Exception as e:
            print(f"{Colors.RED}[!] Error during crawl: {e}{Colors.RESET}")
            if self.crawl_time == 0.0:
                self.crawl_time = 0.0

        # Always print summary + save
        self.print_summary()
        self.print_forms()
        self.print_sensitive()
        self.print_technologies()
        self.print_tree()

        try:
            self.save_sitemap()
            self.save_urls_csv()
            self.save_report()
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving files: {e}{Colors.RESET}")

        print(f"\n{Colors.GREEN}[✓] Crawl completed in {self.crawl_time:.1f}s"
              f"{Colors.RESET}")

# ---------------------------------------------------------------------- #
# MAIN
# ---------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="Advanced Web Spider & Content Discovery (LEGAL)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web_spider.py example.com
  python web_spider.py http://scanme.nmap.org --max-depth 2 --max-pages 50
  python web_spider.py example.com --delay 1 --threads 3
  python web_spider.py example.com --no-robots
  python web_spider.py example.com -o myscan

LEGAL: Only crawl sites you own or have explicit permission to test.
        """
    )
    p.add_argument('target', help='Target URL or domain')
    p.add_argument('--max-depth', type=int, default=3, help='Max crawl depth (default 3)')
    p.add_argument('--max-pages', type=int, default=200, help='Max pages (default 200)')
    p.add_argument('--delay', type=float, default=0.5, help='Delay per request (default 0.5s)')
    p.add_argument('--threads', type=int, default=5, help='Concurrent threads (default 5)')
    p.add_argument('--no-robots', action='store_true', help='Ignore robots.txt')
    p.add_argument('--no-domain-restrict', action='store_true',
                   help='Allow crawling other domains')
    p.add_argument('-o', '--output', default='spider', help='Output file prefix')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  ADVANCED WEB SPIDER & CONTENT DISCOVERY")
    print("  Project #18: Web Application Crawler & Spider")
    print("=" * 70)
    print(f"{Colors.RESET}")

    print(f"{Colors.YELLOW}Legal notice: Only crawl sites you own or have permission.{Colors.RESET}\n")

    spider = WebSpider(
        target=args.target,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        domain_restriction=not args.no_domain_restrict,
        delay=args.delay,
        threads=args.threads,
        respect_robots=not args.no_robots,
        output_prefix=args.output,
        verbose=args.verbose,
    )
    spider.run()

if __name__ == '__main__':
    main()