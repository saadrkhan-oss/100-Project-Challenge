#!/usr/bin/env python3
"""
Web Application Fingerprinting Tool
Project #3: Web Technology Stack Detector
"""

import requests
import sys
import time
import json
import re
from urllib.parse import urlparse
from datetime import datetime
import ssl
import socket

# Color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    MAGENTA = '\033[95m'

class WebFingerprinter:
    def __init__(self, target, timeout=10, verify_ssl=True):
        """
        Initialize the web fingerprinter
        
        Args:
            target: URL to fingerprint (e.g., http://example.com)
            timeout: Request timeout in seconds
            verify_ssl: Verify SSL certificates
        """
        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self.target = target
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        self.results = {
            'url': target,
            'status_code': None,
            'response_time': None,
            'server': None,
            'powered_by': None,
            'cms': None,
            'language': None,
            'js_framework': None,
            'database': None,
            'os': None,
            'headers': {},
            'cookies': [],
            'meta_tags': {},
            'interesting_paths': [],
            'technologies': [],
            'errors': []
        }
        
        # Detection patterns
        self.cms_patterns = {
            'WordPress': {
                'patterns': [
                    r'wp-content', r'wp-includes', r'/wp-json',
                    r'wp-login', r'wp-admin', r'wordpress'
                ],
                'meta': ['generator', 'WordPress'],
                'headers': []
            },
            'Drupal': {
                'patterns': [
                    r'sites/default/files', r'/core/', 
                    r'Drupal.settings', r'drupal'
                ],
                'meta': ['Generator', 'Drupal'],
                'headers': ['X-Drupal-Cache', 'X-Drupal-Dynamic-Cache']
            },
            'Joomla': {
                'patterns': [
                    r'com_content', r'/media/system',
                    r'Joomla!', r'joomla'
                ],
                'meta': ['generator', 'Joomla'],
                'headers': []
            },
            'Magento': {
                'patterns': [
                    r'skin/frontend', r'Mage.Cookies',
                    r'magento'
                ],
                'meta': [],
                'headers': []
            },
            'Shopify': {
                'patterns': [
                    r'shopify', r'cdn.shopify.com'
                ],
                'meta': [],
                'headers': ['X-Shopify-Stage', 'X-Shopify-Shop']
            },
            'Wix': {
                'patterns': [
                    r'wix.com', r'static.wixstatic.com'
                ],
                'meta': ['generator', 'Wix'],
                'headers': []
            },
            'Squarespace': {
                'patterns': [
                    r'squarespace', r'static1.squarespace.com'
                ],
                'meta': ['generator', 'Squarespace'],
                'headers': []
            }
        }
        
        self.js_frameworks = {
            'React': {
                'patterns': [
                    r'react\.min\.js', r'react-dom\.min\.js',
                    r'ReactDOM', r'React\.createElement'
                ],
                'attributes': ['data-reactroot', 'data-reactid']
            },
            'Angular': {
                'patterns': [
                    r'angular\.min\.js', r'ng-app',
                    r'ng-controller', r'angularjs'
                ],
                'attributes': ['ng-app', 'ng-controller']
            },
            'Vue.js': {
                'patterns': [
                    r'vue\.min\.js', r'v-bind',
                    r'v-for', r'vuejs'
                ],
                'attributes': ['v-bind', 'v-for', 'v-if']
            },
            'jQuery': {
                'patterns': [
                    r'jquery\.min\.js', r'jquery-',
                    r'\$\(document\)\.ready'
                ],
                'attributes': []
            },
            'Bootstrap': {
                'patterns': [
                    r'bootstrap\.min\.css', r'bootstrap\.js',
                    r'bootstrap-', r'data-toggle'
                ],
                'attributes': ['data-toggle', 'data-target']
            },
            'Tailwind CSS': {
                'patterns': [
                    r'tailwind\.css', r'tailwind-'
                ],
                'attributes': ['class=".*?tw-']
            }
        }
        
        self.server_patterns = {
            'Apache': r'apache',
            'Nginx': r'nginx',
            'IIS': r'microsoft-iis',
            'Tomcat': r'tomcat',
            'Node.js': r'node\.js',
            'Express': r'express',
            'Gunicorn': r'gunicorn',
            'Caddy': r'caddy',
            'Lighttpd': r'lighttpd',
            'LiteSpeed': r'litespeed'
        }
        
        self.language_patterns = {
            'PHP': {
                'patterns': [r'\.php', r'PHPSESSID', r'X-Powered-By.*PHP'],
                'headers': ['X-Powered-By', 'Set-Cookie.*PHPSESSID']
            },
            'Python': {
                'patterns': [r'\.py', r'\.wsgi', r'python'],
                'headers': ['X-Powered-By.*Python', 'Set-Cookie.*sessionid']
            },
            'ASP.NET': {
                'patterns': [r'\.aspx', r'\.ashx', r'\.axd'],
                'headers': ['ASP.NET_SessionId', 'X-Powered-By.*ASP.NET']
            },
            'Ruby on Rails': {
                'patterns': [r'\.rb', r'rails'],
                'headers': ['X-Powered-By.*Ruby', 'Set-Cookie.*_session']
            },
            'Node.js': {
                'patterns': [r'\.js', r'node'],
                'headers': ['X-Powered-By.*Express', 'X-Powered-By.*Node']
            },
            'Java/JSP': {
                'patterns': [r'\.jsp', r'\.do'],
                'headers': ['JSESSIONID', 'X-Powered-By.*Java']
            }
        }
    
    def fetch_page(self):
        """Fetch the target webpage and headers"""
        try:
            start_time = time.time()
            
            # Disable SSL verification if requested
            verify = self.verify_ssl if self.verify_ssl else False
            if not self.verify_ssl:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Try with a timeout and retry
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=verify,
                allow_redirects=True,
                stream=True
            )
            
            # Read the content (but limit size)
            content = response.text[:500000]  # Limit to 500KB for performance
            
            self.results['response_time'] = time.time() - start_time
            self.results['status_code'] = response.status_code
            
            # Store headers
            self.results['headers'] = dict(response.headers)
            
            # Parse cookies
            self.results['cookies'] = [c.name for c in response.cookies]
            
            # Parse HTML for meta tags
            if 'text/html' in response.headers.get('Content-Type', ''):
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(content, 'html.parser')
                    self.parse_meta_tags(soup)
                    self.parse_js_frameworks(soup, content)
                    self.check_cms_patterns(content, soup)
                    self.parse_interesting_paths(content)
                except Exception as e:
                    self.results['errors'].append(f'HTML parsing error: {str(e)}')
            
            # Analyze headers
            self.analyze_headers(response.headers)
            
            # Check for technology indicators
            self.detect_cms(content, response.headers, soup if 'soup' in locals() else None)
            self.detect_js_framework(content, soup if 'soup' in locals() else None)
            self.detect_language(content, response.headers)
            
            return response
            
        except requests.exceptions.SSLError:
            self.results['errors'].append('SSL Certificate Error')
            print(f"{Colors.YELLOW}[!] SSL Error, trying without verification...{Colors.RESET}")
            return self.fetch_page_no_ssl()
        except requests.exceptions.ConnectionError as e:
            self.results['errors'].append(f'Connection Error: {str(e)[:50]}')
            print(f"{Colors.YELLOW}[!] Connection Error. Trying with different settings...{Colors.RESET}")
            return self.fetch_page_alternative()
        except requests.exceptions.Timeout:
            self.results['errors'].append('Timeout')
            return None
        except requests.exceptions.TooManyRedirects:
            self.results['errors'].append('Too many redirects')
            return None
        except Exception as e:
            self.results['errors'].append(f'Error: {str(e)[:50]}')
            return None
    
    def fetch_page_no_ssl(self):
        """Try to fetch page without SSL verification"""
        try:
            # Try without SSL verification
            self.verify_ssl = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            self.results['response_time'] = time.time() - time.time()
            self.results['status_code'] = response.status_code
            self.results['headers'] = dict(response.headers)
            self.results['cookies'] = [c.name for c in response.cookies]
            
            return response
            
        except Exception as e:
            self.results['errors'].append(f'SSL Error: {str(e)[:50]}')
            return None
    
    def fetch_page_alternative(self):
        """Try alternative methods to fetch the page"""
        try:
            # Try with different headers
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            self.results['response_time'] = time.time() - time.time()
            self.results['status_code'] = response.status_code
            self.results['headers'] = dict(response.headers)
            self.results['cookies'] = [c.name for c in response.cookies]
            
            return response
            
        except Exception as e:
            self.results['errors'].append(f'Alternative fetch failed: {str(e)[:50]}')
            return None
    
    def parse_meta_tags(self, soup):
        """Extract and analyze meta tags"""
        meta_tags = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name', '').lower()
            content = meta.get('content', '')
            if name:
                meta_tags[name] = content
                self.results['meta_tags'][name] = content
        
        # Check for generator meta tag (CMS detection)
        if 'generator' in meta_tags:
            generator = meta_tags['generator'].lower()
            if 'wordpress' in generator:
                self.results['cms'] = 'WordPress'
            elif 'drupal' in generator:
                self.results['cms'] = 'Drupal'
            elif 'joomla' in generator:
                self.results['cms'] = 'Joomla'
    
    def parse_js_frameworks(self, soup, html):
        """Parse JavaScript framework usage"""
        # Check script tags
        script_srcs = []
        for script in soup.find_all('script'):
            src = script.get('src', '')
            if src:
                script_srcs.append(src)
        
        # Check link tags for CSS frameworks
        css_hrefs = []
        for link in soup.find_all('link'):
            href = link.get('href', '')
            if href and '.css' in href:
                css_hrefs.append(href)
        
        # Check for JS frameworks
        frameworks = []
        for framework, data in self.js_frameworks.items():
            # Check patterns in HTML
            for pattern in data['patterns']:
                if re.search(pattern, html, re.IGNORECASE):
                    frameworks.append(framework)
                    break
            
            # Check attributes in HTML
            if not frameworks or framework not in frameworks:
                for attr in data.get('attributes', []):
                    if attr in html:
                        frameworks.append(framework)
                        break
        
        # Check for framework in script sources
        for src in script_srcs:
            for framework, data in self.js_frameworks.items():
                for pattern in data['patterns']:
                    if re.search(pattern, src, re.IGNORECASE):
                        if framework not in frameworks:
                            frameworks.append(framework)
        
        # Check for CSS frameworks
        for href in css_hrefs:
            if 'bootstrap' in href.lower() and 'Bootstrap' not in frameworks:
                frameworks.append('Bootstrap')
            elif 'tailwind' in href.lower() and 'Tailwind CSS' not in frameworks:
                frameworks.append('Tailwind CSS')
        
        # Store results
        if frameworks:
            self.results['js_framework'] = ', '.join(set(frameworks))
        else:
            self.results['js_framework'] = 'No framework detected'
    
    def check_cms_patterns(self, html, soup):
        """Check for CMS patterns in HTML"""
        # Check patterns first
        html_lower = html.lower()
        
        for cms, data in self.cms_patterns.items():
            found = False
            
            # Check HTML patterns
            for pattern in data['patterns']:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    found = True
                    break
            
            # Check meta tags if not found
            if not found and data.get('meta'):
                meta_tag = data['meta'][0].lower()
                meta_content = data['meta'][1].lower()
                for name, content in self.results['meta_tags'].items():
                    if meta_tag in name and meta_content in content.lower():
                        found = True
                        break
            
            if found and not self.results['cms']:
                self.results['cms'] = cms
                break
    
    def analyze_headers(self, headers):
        """Analyze HTTP headers for technology indicators"""
        # Check server header
        if 'Server' in headers:
            server = headers['Server']
            self.results['server'] = server
            
            # Detect server type
            for server_name, pattern in self.server_patterns.items():
                if re.search(pattern, server, re.IGNORECASE):
                    self.results['technologies'].append({
                        'type': 'Web Server',
                        'name': server_name,
                        'version': server
                    })
                    break
        
        # Check X-Powered-By
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            self.results['powered_by'] = powered_by
            
            # Detect language from X-Powered-By
            if 'PHP' in powered_by:
                self.results['language'] = 'PHP'
                self.results['technologies'].append({
                    'type': 'Programming Language',
                    'name': 'PHP',
                    'version': powered_by
                })
            elif 'ASP.NET' in powered_by or 'ASP' in powered_by:
                self.results['language'] = 'ASP.NET'
                self.results['technologies'].append({
                    'type': 'Programming Language',
                    'name': 'ASP.NET',
                    'version': powered_by
                })
            elif 'Python' in powered_by:
                self.results['language'] = 'Python'
                self.results['technologies'].append({
                    'type': 'Programming Language',
                    'name': 'Python',
                    'version': powered_by
                })
        
        # Check cookies
        if 'Set-Cookie' in headers:
            cookie_str = headers['Set-Cookie']
            if 'PHPSESSID' in cookie_str:
                self.results['language'] = 'PHP'
                self.results['technologies'].append({
                    'type': 'Programming Language',
                    'name': 'PHP (PHPSESSID)',
                    'version': 'Detected'
                })
            elif 'ASP.NET_SessionId' in cookie_str:
                self.results['language'] = 'ASP.NET'
                self.results['technologies'].append({
                    'type': 'Programming Language',
                    'name': 'ASP.NET (ASP.NET_SessionId)',
                    'version': 'Detected'
                })
            elif 'JSESSIONID' in cookie_str:
                self.results['language'] = 'Java/JSP'
                self.results['technologies'].append({
                    'type': 'Programming Language',
                    'name': 'Java/JSP (JSESSIONID)',
                    'version': 'Detected'
                })
    
    def detect_cms(self, html, headers, soup):
        """Detect CMS from all available sources"""
        if self.results['cms']:
            return  # Already detected from meta tags
        
        html_lower = html.lower()
        
        # Check each CMS pattern
        for cms, data in self.cms_patterns.items():
            # Check HTML patterns
            for pattern in data['patterns']:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    self.results['cms'] = cms
                    self.results['technologies'].append({
                        'type': 'CMS',
                        'name': cms,
                        'version': 'Detected'
                    })
                    return
            
            # Check headers
            for header in data.get('headers', []):
                if header in headers:
                    self.results['cms'] = cms
                    self.results['technologies'].append({
                        'type': 'CMS',
                        'name': cms,
                        'version': 'Detected'
                    })
                    return
    
    def detect_js_framework(self, html, soup):
        """Detect JavaScript framework"""
        if self.results['js_framework'] != 'No framework detected':
            return  # Already detected
        
        # Check in HTML
        for framework, data in self.js_frameworks.items():
            for pattern in data['patterns']:
                if re.search(pattern, html, re.IGNORECASE):
                    self.results['js_framework'] = framework
                    self.results['technologies'].append({
                        'type': 'JavaScript Framework',
                        'name': framework,
                        'version': 'Detected'
                    })
                    return
            
            # Check attributes
            for attr in data.get('attributes', []):
                if attr in html:
                    self.results['js_framework'] = framework
                    self.results['technologies'].append({
                        'type': 'JavaScript Framework',
                        'name': framework,
                        'version': 'Detected'
                    })
                    return
    
    def detect_language(self, html, headers):
        """Detect programming language"""
        if self.results['language']:
            return  # Already detected
        
        html_lower = html.lower()
        
        for language, data in self.language_patterns.items():
            # Check patterns in HTML
            for pattern in data['patterns']:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    self.results['language'] = language
                    self.results['technologies'].append({
                        'type': 'Programming Language',
                        'name': language,
                        'version': 'Detected'
                    })
                    return
            
            # Check headers
            for header_pattern in data.get('headers', []):
                for header, value in headers.items():
                    if re.search(header_pattern, f"{header}: {value}", re.IGNORECASE):
                        self.results['language'] = language
                        self.results['technologies'].append({
                            'type': 'Programming Language',
                            'name': language,
                            'version': 'Detected'
                        })
                        return
    
    def parse_interesting_paths(self, html):
        """Parse interesting paths from HTML"""
        interesting = []
        
        # Common CMS paths
        cms_paths = {
            'WordPress': ['/wp-content/', '/wp-includes/', '/wp-json/', '/xmlrpc.php'],
            'Drupal': ['/sites/default/files/', '/core/', '/modules/'],
            'Joomla': ['/media/system/', '/components/', '/administrator/']
        }
        
        for cms, paths in cms_paths.items():
            for path in paths:
                if path in html:
                    interesting.append(f"{path} ({cms})")
        
        # Admin paths
        admin_paths = ['/admin', '/login', '/wp-admin', '/administrator', '/cpanel']
        for path in admin_paths:
            if path in html:
                interesting.append(f"{path} (admin)")
        
        # API paths
        api_paths = ['/api/', '/v1/', '/rest/', '/graphql']
        for path in api_paths:
            if path in html:
                interesting.append(f"{path} (API)")
        
        self.results['interesting_paths'] = list(set(interesting))[:10]
    
    def detect_os(self):
        """Detect OS from server headers and other clues"""
        if self.results['server']:
            server_lower = self.results['server'].lower()
            if 'linux' in server_lower or 'ubuntu' in server_lower:
                self.results['os'] = 'Linux'
            elif 'windows' in server_lower or 'win32' in server_lower:
                self.results['os'] = 'Windows'
            elif 'darwin' in server_lower:
                self.results['os'] = 'macOS'
            elif 'freebsd' in server_lower:
                self.results['os'] = 'FreeBSD'
            else:
                self.results['os'] = 'Unknown'
        else:
            self.results['os'] = 'Unknown'
    
    def detect_database(self):
        """Infer database from other technologies"""
        if self.results['language']:
            lang = self.results['language'].lower()
            if 'php' in lang or 'wordpress' in str(self.results['cms']).lower():
                self.results['database'] = 'MySQL (inferred)'
            elif 'asp.net' in lang:
                self.results['database'] = 'SQL Server (inferred)'
            elif 'python' in lang:
                self.results['database'] = 'PostgreSQL/SQLite (inferred)'
            elif 'java' in lang or 'jsp' in lang:
                self.results['database'] = 'Oracle/MySQL (inferred)'
            else:
                self.results['database'] = 'Unknown'
        else:
            self.results['database'] = 'Unknown'
    
    def generate_report(self):
        """Generate a detailed report"""
        report = []
        report.append("=" * 80)
        report.append("WEB TECHNOLOGY STACK DETECTION REPORT")
        report.append("=" * 80)
        report.append(f"Target:        {self.results['url']}")
        report.append(f"Status:        {self.results['status_code'] if self.results['status_code'] else 'Failed'}")
        if self.results['response_time']:
            report.append(f"Response Time: {self.results['response_time']:.2f}s")
        report.append(f"Date:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 80)
        report.append("")
        
        # Technology Stack
        report.append("📊 TECHNOLOGY STACK:")
        report.append("-" * 40)
        report.append(f"  Web Server:    {self.results['server'] or 'Not detected'}")
        report.append(f"  Language:      {self.results['language'] or 'Not detected'}")
        report.append(f"  CMS:           {self.results['cms'] or 'Not detected'}")
        report.append(f"  JS Framework:  {self.results['js_framework'] or 'Not detected'}")
        report.append(f"  Database:      {self.results['database'] or 'Not detected'}")
        report.append(f"  OS:            {self.results['os'] or 'Not detected'}")
        report.append("")
        
        # Headers
        if self.results['headers']:
            report.append("📋 INTERESTING HEADERS:")
            report.append("-" * 40)
            interesting_headers = ['Server', 'X-Powered-By', 'X-Generator', 'X-Drupal-Cache', 
                                 'X-Varnish', 'X-Cache', 'Set-Cookie']
            for key, value in self.results['headers'].items():
                if any(h in key for h in interesting_headers):
                    report.append(f"  {key}: {value}")
            report.append("")
        
        # Cookies
        if self.results['cookies']:
            report.append("🍪 COOKIES DETECTED:")
            report.append("-" * 40)
            for cookie in self.results['cookies']:
                report.append(f"  {cookie}")
            report.append("")
        
        # Meta Tags
        if self.results['meta_tags']:
            report.append("🏷️  META TAGS:")
            report.append("-" * 40)
            for name, content in list(self.results['meta_tags'].items())[:5]:
                report.append(f"  {name}: {content[:100]}")
            report.append("")
        
        # Interesting Paths
        if self.results['interesting_paths']:
            report.append("📁 INTERESTING PATHS FOUND:")
            report.append("-" * 40)
            for path in self.results['interesting_paths']:
                report.append(f"  {path}")
            report.append("")
        
        # Technologies
        if self.results['technologies']:
            report.append("🔧 DETECTED TECHNOLOGIES:")
            report.append("-" * 40)
            for tech in self.results['technologies']:
                report.append(f"  {tech['type']}: {tech['name']} ({tech['version']})")
            report.append("")
        
        # Errors
        if self.results['errors']:
            report.append("⚠️  ERRORS:")
            report.append("-" * 40)
            for error in self.results['errors']:
                report.append(f"  {error}")
            report.append("")
        
        report.append("=" * 80)
        report.append("Report generated by Web Technology Stack Detector")
        report.append("Project #3: Web Application Fingerprinting")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def print_results(self):
        """Print results to console with colors"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Target: {self.results['url']}{Colors.RESET}")
        
        if self.results['status_code']:
            status_color = Colors.GREEN if self.results['status_code'] == 200 else Colors.YELLOW
            print(f"{Colors.BOLD}[+] Status Code: {status_color}{self.results['status_code']}{Colors.RESET}")
        
        if self.results['response_time']:
            print(f"{Colors.BOLD}[+] Response Time: {Colors.CYAN}{self.results['response_time']:.2f}s{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}[+] TECHNOLOGY STACK:{Colors.RESET}")
        print(f"  {Colors.YELLOW}Web Server:{Colors.RESET} {self.results['server'] or 'Not detected'}")
        print(f"  {Colors.YELLOW}Language:{Colors.RESET} {self.results['language'] or 'Not detected'}")
        print(f"  {Colors.YELLOW}CMS:{Colors.RESET} {self.results['cms'] or 'Not detected'}")
        print(f"  {Colors.YELLOW}JS Framework:{Colors.RESET} {self.results['js_framework'] or 'Not detected'}")
        print(f"  {Colors.YELLOW}Database:{Colors.RESET} {self.results['database'] or 'Not detected'}")
        print(f"  {Colors.YELLOW}OS:{Colors.RESET} {self.results['os'] or 'Not detected'}")
        
        if self.results['headers']:
            print(f"\n{Colors.BOLD}{Colors.BLUE}[+] INTERESTING HEADERS:{Colors.RESET}")
            interesting_headers = ['Server', 'X-Powered-By', 'X-Generator', 'Set-Cookie']
            for key, value in self.results['headers'].items():
                if any(h in key for h in interesting_headers):
                    print(f"  {Colors.CYAN}{key}:{Colors.RESET} {value}")
        
        if self.results['cookies']:
            print(f"\n{Colors.BOLD}{Colors.BLUE}[+] COOKIES:{Colors.RESET}")
            for cookie in self.results['cookies']:
                print(f"  {Colors.CYAN}•{Colors.RESET} {cookie}")
        
        if self.results['interesting_paths']:
            print(f"\n{Colors.BOLD}{Colors.BLUE}[+] INTERESTING PATHS:{Colors.RESET}")
            for path in self.results['interesting_paths']:
                print(f"  {Colors.CYAN}•{Colors.RESET} {path}")
        
        if self.results['technologies']:
            print(f"\n{Colors.BOLD}{Colors.BLUE}[+] DETECTED TECHNOLOGIES:{Colors.RESET}")
            for tech in self.results['technologies']:
                print(f"  {Colors.CYAN}•{Colors.RESET} {tech['type']}: {tech['name']}")
        
        if self.results['errors']:
            print(f"\n{Colors.BOLD}{Colors.RED}[!] ERRORS:{Colors.RESET}")
            for error in self.results['errors']:
                print(f"  {Colors.RED}•{Colors.RESET} {error}")
        
        print("\n" + "=" * 70)
    
    def save_report(self, filename=None):
        """Save report to file"""
        if not filename:
            domain = urlparse(self.target).netloc
            filename = f"results_{domain}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(self.generate_report())
        
        print(f"{Colors.GREEN}[✓] Report saved to: {filename}{Colors.RESET}")
        return filename
    
    def run(self):
        """Main execution method"""
        print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
        print("    WEB TECHNOLOGY STACK DETECTOR")
        print("    Project #3: Web Application Fingerprinting")
        print("=" * 70 + f"{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}[*] Fingerprinting: {self.target}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Timeout: {self.timeout}s{Colors.RESET}")
        print("")
        
        # Fetch the page
        response = self.fetch_page()
        
        if response:
            # Detect OS and database
            self.detect_os()
            self.detect_database()
            
            # Print results
            self.print_results()
            
            # Save report
            filename = self.save_report()
            
            return {
                'success': True,
                'results': self.results,
                'report_file': filename
            }
        else:
            print(f"{Colors.RED}[!] Failed to fingerprint {self.target}{Colors.RESET}")
            if self.results['errors']:
                for error in self.results['errors']:
                    print(f"{Colors.RED}  - {error}{Colors.RESET}")
            
            # Save error report
            filename = self.save_report()
            
            return {
                'success': False,
                'results': self.results,
                'report_file': filename
            }

def compare_targets(targets):
    """Compare multiple targets and generate comparison table"""
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}" + "=" * 80)
    print("    TARGET COMPARISON TABLE")
    print("=" * 80 + f"{Colors.RESET}\n")
    
    results = []
    for target in targets:
        print(f"{Colors.BOLD}[*] Analyzing: {target}{Colors.RESET}")
        fingerprinter = WebFingerprinter(target)
        result = fingerprinter.run()
        results.append(result)
        print("")
    
    # Generate comparison table
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}" + "=" * 80)
    print("    COMPARISON TABLE")
    print("=" * 80 + f"{Colors.RESET}\n")
    
    # Table header
    print(f"{Colors.BOLD}{'Target':<30} {'Server':<15} {'Language':<15} {'CMS':<15} {'JS Framework':<15}{Colors.RESET}")
    print("-" * 90)
    
    for result in results:
        if result['success']:
            r = result['results']
            target_short = r['url'][:30]
            server = r['server'] or 'N/A'
            language = r['language'] or 'N/A'
            cms = r['cms'] or 'N/A'
            js = r['js_framework'] or 'N/A'
            
            print(f"{target_short:<30} {server:<15} {language:<15} {cms:<15} {js:<15}")
        else:
            print(f"{result['results']['url'][:30]:<30} {'ERROR':<15} {'ERROR':<15} {'ERROR':<15} {'ERROR':<15}")
    
    print("-" * 90)
    
    # Save comparison table
    with open('comparison_table.txt', 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("TARGET COMPARISON TABLE\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"{'Target':<30} {'Server':<15} {'Language':<15} {'CMS':<15} {'JS Framework':<15}\n")
        f.write("-" * 90 + "\n")
        
        for result in results:
            if result['success']:
                r = result['results']
                target_short = r['url'][:30]
                server = r['server'] or 'N/A'
                language = r['language'] or 'N/A'
                cms = r['cms'] or 'N/A'
                js = r['js_framework'] or 'N/A'
                
                f.write(f"{target_short:<30} {server:<15} {language:<15} {cms:<15} {js:<15}\n")
            else:
                f.write(f"{result['results']['url'][:30]:<30} {'ERROR':<15} {'ERROR':<15} {'ERROR':<15} {'ERROR':<15}\n")
        
        f.write("-" * 90 + "\n")
        f.write(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    print(f"\n{Colors.GREEN}[✓] Comparison table saved to: comparison_table.txt{Colors.RESET}")

def main():
    # Check if BeautifulSoup is installed
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print(f"{Colors.RED}[!] BeautifulSoup not installed. Installing...{Colors.RESET}")
        print(f"{Colors.YELLOW}Run: pip install beautifulsoup4{Colors.RESET}")
        sys.exit(1)
    
    if len(sys.argv) < 2:
        print(f"{Colors.RED}Usage: python web_fingerprinter.py <url> [url2] [url3] ...{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python web_fingerprinter.py http://scanme.nmap.org{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python web_fingerprinter.py https://example.com{Colors.RESET}")
        print(f"{Colors.YELLOW}Example: python web_fingerprinter.py http://scanme.nmap.org https://example.com{Colors.RESET}")
        sys.exit(1)
    
    targets = sys.argv[1:]
    
    if len(targets) == 1:
        # Single target
        fingerprinter = WebFingerprinter(targets[0])
        fingerprinter.run()
    else:
        # Multiple targets - compare
        compare_targets(targets)

if __name__ == "__main__":
    main()