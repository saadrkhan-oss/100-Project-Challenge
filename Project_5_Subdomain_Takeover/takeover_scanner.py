#!/usr/bin/env python3
"""
Subdomain Takeover Detection Scanner
Project #5: Subdomain Takeover Vulnerability Scanner
"""

import socket
import sys
import time
import dns.resolver
import dns.reversename
import requests
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import argparse

# Color codes for terminal output
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

class SubdomainTakeoverScanner:
    def __init__(self, domain, subdomains=None, threads=10, timeout=5, 
                 output_file="takeover_results.txt", verbose=False):
        """
        Initialize the subdomain takeover scanner
        
        Args:
            domain: Main domain (e.g., example.com)
            subdomains: List of subdomains to test
            threads: Number of threads
            timeout: Request timeout
            output_file: Output file name
            verbose: Enable verbose output
        """
        self.domain = domain
        self.subdomains = subdomains or []
        self.threads = threads
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        
        self.results = []
        self.vulnerable = []
        self.active = []
        self.errors = []
        
        # Define takeover patterns
        self.takeover_patterns = {
            'github.io': {
                'service': 'GitHub Pages',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    'There isn\'t a GitHub Pages site here',
                    '404 Not Found',
                    'Page not found'
                ]
            },
            's3.amazonaws.com': {
                'service': 'AWS S3 Bucket',
                'check_url': 'http://{subdomain}',
                'fingerprints': [
                    'NoSuchBucket',
                    'The specified bucket does not exist',
                    '404 Not Found'
                ]
            },
            'herokuapp.com': {
                'service': 'Heroku',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    'No such app',
                    'Heroku | No such app',
                    'Application not found'
                ]
            },
            'azurewebsites.net': {
                'service': 'Azure App Service',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    '404 Web Site not found',
                    'No web site found',
                    'The resource you are looking for has been removed'
                ]
            },
            'readthedocs.io': {
                'service': 'ReadTheDocs',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    'This site does not exist on Read the Docs',
                    '404 Not Found'
                ]
            },
            'vercel-dns.com': {
                'service': 'Vercel',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    'This domain is not configured on Vercel',
                    '404 Not Found'
                ]
            },
            'vercel.app': {
                'service': 'Vercel',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    'This domain is not configured on Vercel',
                    '404 Not Found'
                ]
            },
            'netlify.app': {
                'service': 'Netlify',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    'This site is not yet published',
                    'Site not found',
                    '404 Not Found'
                ]
            },
            'amazonaws.com': {
                'service': 'AWS',
                'check_url': 'http://{subdomain}',
                'fingerprints': [
                    'NoSuchBucket',
                    '404 Not Found'
                ]
            },
            'cloudfront.net': {
                'service': 'AWS CloudFront',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    'The distribution you requested is not configured',
                    '404 Not Found'
                ]
            },
            'surge.sh': {
                'service': 'Surge.sh',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    'project not found',
                    '404 Not Found'
                ]
            },
            'firebaseapp.com': {
                'service': 'Firebase Hosting',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    'Firebase Hosting',
                    '404 Not Found'
                ]
            },
            'web.app': {
                'service': 'Firebase Hosting',
                'check_url': 'https://{subdomain}',
                'fingerprints': [
                    'Firebase Hosting',
                    '404 Not Found'
                ]
            }
        }
        
        # Risk levels
        self.risk_levels = {
            'HIGH': ['GitHub Pages', 'AWS S3 Bucket', 'Heroku', 'Vercel', 'Netlify'],
            'MEDIUM': ['ReadTheDocs', 'Azure App Service', 'Firebase Hosting'],
            'LOW': ['AWS', 'AWS CloudFront']
        }
    
    def resolve_dns(self, subdomain):
        """Resolve DNS for a subdomain"""
        full_subdomain = f"{subdomain}.{self.domain}"
        
        try:
            # Try to get CNAME first
            cname_records = []
            try:
                answers = dns.resolver.resolve(full_subdomain, 'CNAME')
                cname_records = [str(r.target).rstrip('.') for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] CNAME lookup error for {full_subdomain}: {e}{Colors.RESET}")
            
            # Get A records
            try:
                answers = dns.resolver.resolve(full_subdomain, 'A')
                a_records = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                a_records = []
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] A record lookup error for {full_subdomain}: {e}{Colors.RESET}")
                a_records = []
            
            # Check if subdomain exists
            if not cname_records and not a_records:
                return {
                    'exists': False,
                    'cname': None,
                    'a_records': [],
                    'full_subdomain': full_subdomain,
                    'service': None
                }
            
            # Determine service from CNAME
            service = None
            target = None
            
            if cname_records:
                target = cname_records[0]
                for pattern, info in self.takeover_patterns.items():
                    if pattern in target.lower():
                        service = info
                        break
            
            return {
                'exists': True,
                'cname': cname_records[0] if cname_records else None,
                'a_records': a_records,
                'full_subdomain': full_subdomain,
                'service': service,
                'service_name': service['service'] if service else None
            }
            
        except dns.resolver.NXDOMAIN:
            return {
                'exists': False,
                'cname': None,
                'a_records': [],
                'full_subdomain': full_subdomain,
                'service': None
            }
        except Exception as e:
            return {
                'exists': False,
                'cname': None,
                'a_records': [],
                'full_subdomain': full_subdomain,
                'service': None,
                'error': str(e)
            }
    
    def check_http(self, subdomain, cname_target):
        """Check HTTP service for takeover indicators"""
        if not cname_target:
            return None
        
        # Try multiple protocols
        for protocol in ['https://', 'http://']:
            try:
                url = f"{protocol}{subdomain}.{self.domain}"
                
                # Check if this is a known service
                for pattern, info in self.takeover_patterns.items():
                    if pattern in cname_target.lower():
                        # Use the check_url format if available
                        check_url = info.get('check_url', url)
                        check_url = check_url.replace('{subdomain}', f"{subdomain}.{self.domain}")
                        check_url = check_url.replace('{domain}', f"{subdomain}.{self.domain}")
                        check_url = check_url.replace('{bucket}', f"{subdomain}-{self.domain}")
                        
                        try:
                            response = requests.get(
                                check_url,
                                timeout=self.timeout,
                                verify=False,
                                allow_redirects=True,
                                headers={
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                                }
                            )
                            
                            content = response.text[:2000]
                            
                            # Check for takeover fingerprints
                            is_vulnerable = False
                            for fingerprint in info.get('fingerprints', []):
                                if fingerprint in content:
                                    is_vulnerable = True
                                    break
                            
                            # Additional checks for specific services
                            if pattern == 'github.io':
                                if 'There isn\'t a GitHub Pages site here' in content:
                                    is_vulnerable = True
                            elif pattern == 'herokuapp.com':
                                if 'No such app' in content:
                                    is_vulnerable = True
                            elif pattern == 's3.amazonaws.com':
                                if 'NoSuchBucket' in content:
                                    is_vulnerable = True
                            
                            return {
                                'url': check_url,
                                'status_code': response.status_code,
                                'vulnerable': is_vulnerable,
                                'service': info['service'],
                                'content': content[:500],
                                'headers': dict(response.headers)
                            }
                            
                        except requests.exceptions.ConnectionError:
                            # Connection error might indicate takeover
                            return {
                                'url': check_url,
                                'status_code': None,
                                'vulnerable': True,
                                'service': info['service'],
                                'content': 'Connection error - service likely dead',
                                'headers': {}
                            }
                        except requests.exceptions.Timeout:
                            return {
                                'url': check_url,
                                'status_code': None,
                                'vulnerable': True,
                                'service': info['service'],
                                'content': 'Timeout - service likely dead',
                                'headers': {}
                            }
                        except Exception as e:
                            if self.verbose:
                                print(f"{Colors.YELLOW}[!] HTTP check error for {check_url}: {e}{Colors.RESET}")
                            return None
                
                # Try generic check
                try:
                    response = requests.get(
                        url,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=True
                    )
                    
                    # Check for 404 or other takeover indicators
                    if response.status_code in [404, 400, 403]:
                        # Could still be vulnerable - check content
                        content = response.text[:500]
                        if 'not found' in content.lower() or 'no such' in content.lower():
                            return {
                                'url': url,
                                'status_code': response.status_code,
                                'vulnerable': True,
                                'service': 'Unknown Service',
                                'content': content,
                                'headers': dict(response.headers)
                            }
                except:
                    pass
                    
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] Error checking {protocol}{subdomain}.{self.domain}: {e}{Colors.RESET}")
                continue
        
        return None
    
    def get_risk_level(self, service_name):
        """Get risk level for a service"""
        for risk, services in self.risk_levels.items():
            if service_name in services:
                return risk
        return 'MEDIUM'
    
    def scan_subdomain(self, subdomain):
        """Scan a single subdomain"""
        result = {
            'subdomain': subdomain,
            'full_domain': f"{subdomain}.{self.domain}",
            'dns': None,
            'http': None,
            'vulnerable': False,
            'risk': None,
            'service': None,
            'details': None
        }
        
        # DNS resolution
        dns_result = self.resolve_dns(subdomain)
        result['dns'] = dns_result
        
        if not dns_result['exists']:
            if self.verbose:
                print(f"{Colors.YELLOW}[*] {subdomain}.{self.domain}: No DNS records{Colors.RESET}")
            return result
        
        if dns_result['service']:
            result['service'] = dns_result['service_name']
            
            # HTTP check
            http_result = self.check_http(subdomain, dns_result['cname'])
            result['http'] = http_result
            
            if http_result and http_result.get('vulnerable'):
                result['vulnerable'] = True
                result['risk'] = self.get_risk_level(dns_result['service_name'])
                result['details'] = {
                    'cname': dns_result['cname'],
                    'service': dns_result['service_name'],
                    'url': http_result.get('url'),
                    'status_code': http_result.get('status_code'),
                    'fingerprint': http_result.get('content', '')[:200]
                }
                
                print(f"{Colors.RED}[!] VULNERABLE: {subdomain}.{self.domain} -> {dns_result['service_name']} (Risk: {result['risk']}){Colors.RESET}")
            elif http_result:
                print(f"{Colors.GREEN}[+] ACTIVE: {subdomain}.{self.domain} -> {dns_result['service_name']} (Status: {http_result.get('status_code', 'OK')}){Colors.RESET}")
                result['active'] = True
            else:
                print(f"{Colors.YELLOW}[*] {subdomain}.{self.domain}: {dns_result['service_name']} (Unable to verify){Colors.RESET}")
        else:
            print(f"{Colors.CYAN}[*] {subdomain}.{self.domain}: {dns_result.get('cname', 'No CNAME')} (Not a known service){Colors.RESET}")
        
        return result
    
    def scan(self):
        """Scan all subdomains"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] Subdomain Takeover Scanner{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Domain: {self.domain}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Subdomains to test: {len(self.subdomains)}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Threads: {self.threads}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print("")
        
        start_time = time.time()
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_subdomain, sub): sub for sub in self.subdomains}
            
            for future in as_completed(futures):
                completed += 1
                result = future.result()
                self.results.append(result)
                
                if result['vulnerable']:
                    self.vulnerable.append(result)
                elif result.get('active'):
                    self.active.append(result)
                
                # Progress
                if completed % 5 == 0 or completed == len(self.subdomains):
                    progress = (completed / len(self.subdomains)) * 100
                    print(f"\r{Colors.YELLOW}[*] Progress: {completed}/{len(self.subdomains)} ({progress:.1f}%) | Vulnerable: {len(self.vulnerable)}{Colors.RESET}", end='')
        
        print()  # New line
        self.scan_time = time.time() - start_time
    
    def generate_report(self):
        """Generate a detailed report"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.GREEN}[✓] SCAN COMPLETE{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Duration: {self.scan_time:.2f} seconds{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Total Subdomains: {len(self.subdomains)}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Vulnerable: {len(self.vulnerable)}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Active: {len(self.active)}{Colors.RESET}")
        
        # Summary
        print("\n" + f"{Colors.BOLD}{Colors.BLUE}[📊] RESULTS SUMMARY:{Colors.RESET}")
        print("-" * 50)
        
        if self.vulnerable:
            print(f"\n{Colors.RED}{Colors.BOLD}[⚠️] VULNERABLE SUBDOMAINS:{Colors.RESET}")
            for result in self.vulnerable:
                risk_color = Colors.RED if result['risk'] == 'HIGH' else Colors.YELLOW
                print(f"  {risk_color}[{result['risk']}]{Colors.RESET} {result['subdomain']}.{self.domain}")
                print(f"    Service: {result['service']}")
                print(f"    CNAME: {result['details']['cname']}")
                if result['details'].get('url'):
                    print(f"    URL: {result['details']['url']}")
                if result['details'].get('status_code'):
                    print(f"    Status: {result['details']['status_code']}")
        
        if self.active:
            print(f"\n{Colors.GREEN}[✓] ACTIVE SUBDOMAINS:{Colors.RESET}")
            for result in self.active:
                print(f"  {Colors.GREEN}•{Colors.RESET} {result['subdomain']}.{self.domain} ({result['service']})")
        
        # Save report
        self.save_report()
        
        # Print takeover steps
        if self.vulnerable:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}[🔧] TAKEOVER EXPLOITATION STEPS:{Colors.RESET}")
            for result in self.vulnerable:
                service = result['service']
                subdomain = result['subdomain']
                print(f"\n{Colors.CYAN}Target: {subdomain}.{self.domain}{Colors.RESET}")
                print(f"  Service: {service}")
                print(f"  CNAME: {result['details']['cname']}")
                
                if 'GitHub Pages' in service:
                    print(f"  Steps:")
                    print(f"    1. Create a GitHub repository named: {subdomain}")
                    print(f"    2. Enable GitHub Pages in repository settings")
                    print(f"    3. Add content to take over the subdomain")
                elif 'AWS S3' in service:
                    print(f"  Steps:")
                    print(f"    1. Create S3 bucket named: {subdomain}.{self.domain}")
                    print(f"    2. Enable static website hosting")
                    print(f"    3. Upload files to take over the subdomain")
                elif 'Heroku' in service:
                    print(f"  Steps:")
                    print(f"    1. Create Heroku app with name: {subdomain}")
                    print(f"    2. Deploy a simple application")
                    print(f"    3. Add domain to Heroku app")
                elif 'Vercel' in service:
                    print(f"  Steps:")
                    print(f"    1. Import project on Vercel with name: {subdomain}")
                    print(f"    2. Deploy the project")
                    print(f"    3. Add domain in Vercel settings")
                elif 'Netlify' in service:
                    print(f"  Steps:")
                    print(f"    1. Create site on Netlify")
                    print(f"    2. Configure custom domain: {subdomain}.{self.domain}")
                    print(f"    3. Deploy content")
                else:
                    print(f"  Steps:")
                    print(f"    1. Identify the service provider")
                    print(f"    2. Create an account/resource with the same name")
                    print(f"    3. Deploy content to claim the subdomain")
        
        print("\n" + "=" * 70)
        print(f"{Colors.GREEN}[✓] Results saved to: {self.output_file}{Colors.RESET}")
        print("=" * 70)
    
    def save_report(self):
        """Save report to file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SUBDOMAIN TAKEOVER SCAN REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Domain:        {self.domain}\n")
            f.write(f"Scan Started:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {self.scan_time:.2f} seconds\n")
            f.write(f"Total Subdomains: {len(self.subdomains)}\n")
            f.write(f"Vulnerable:    {len(self.vulnerable)}\n")
            f.write(f"Active:        {len(self.active)}\n")
            f.write("=" * 80 + "\n\n")
            
            if self.vulnerable:
                f.write("VULNERABLE SUBDOMAINS\n")
                f.write("-" * 50 + "\n")
                for result in self.vulnerable:
                    f.write(f"\n[RISK: {result['risk']}] {result['subdomain']}.{self.domain}\n")
                    f.write(f"  Service: {result['service']}\n")
                    f.write(f"  CNAME: {result['details']['cname']}\n")
                    if result['details'].get('url'):
                        f.write(f"  URL: {result['details']['url']}\n")
                    if result['details'].get('status_code'):
                        f.write(f"  Status: {result['details']['status_code']}\n")
                    if result['details'].get('fingerprint'):
                        f.write(f"  Fingerprint: {result['details']['fingerprint']}\n")
            
            if self.active:
                f.write("\nACTIVE SUBDOMAINS\n")
                f.write("-" * 50 + "\n")
                for result in self.active:
                    f.write(f"\n  {result['subdomain']}.{self.domain}\n")
                    f.write(f"  Service: {result['service']}\n")
                    f.write(f"  CNAME: {result['dns']['cname']}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Report generated by Subdomain Takeover Scanner\n")
            f.write("Project #5: Subdomain Takeover Detection\n")
            f.write("=" * 80 + "\n")
    
    def run(self):
        """Main execution method"""
        try:
            if not self.subdomains:
                print(f"{Colors.RED}[!] No subdomains to scan!{Colors.RESET}")
                return
            
            self.scan()
            self.generate_report()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.RESET}")
            sys.exit(0)
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

def load_subdomains_from_file(filename):
    """Load subdomains from file"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Colors.YELLOW}[!] File not found: {filename}{Colors.RESET}")
        return []
    except Exception as e:
        print(f"{Colors.RED}[!] Error loading file: {e}{Colors.RESET}")
        return []

def discover_subdomains(domain, wordlist_file=None):
    """Simple subdomain discovery using common names"""
    common_subdomains = [
        'www', 'mail', 'ftp', 'webmail', 'admin', 'blog', 'dev', 'test',
        'api', 'app', 'stage', 'staging', 'prod', 'production', 'backup',
        'images', 'img', 'static', 'media', 'cdn', 'files', 'download',
        'upload', 'docs', 'help', 'support', 'forum', 'wiki', 'news',
        'shop', 'store', 'cart', 'payment', 'secure', 'login', 'account',
        'dashboard', 'portal', 'client', 'partner', 'internal', 'staff'
    ]
    
    # Try to load from wordlist
    if wordlist_file and os.path.exists(wordlist_file):
        subdomains = load_subdomains_from_file(wordlist_file)
        if subdomains:
            print(f"{Colors.GREEN}[✓] Loaded {len(subdomains)} subdomains from {wordlist_file}{Colors.RESET}")
            return subdomains
    
    print(f"{Colors.YELLOW}[!] Using default subdomain list ({len(common_subdomains)} entries){Colors.RESET}")
    return common_subdomains

def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Takeover Detection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with subdomain list
  python takeover_scanner.py example.com -s subdomains.txt
  
  # Discover and scan common subdomains
  python takeover_scanner.py example.com -d
  
  # Scan with specific subdomains
  python takeover_scanner.py example.com -s subdomains.txt -t 20 -v
  
  # Use custom wordlist for discovery
  python takeover_scanner.py example.com -d -w wordlist.txt
        """
    )
    
    parser.add_argument('domain', help='Main domain (e.g., example.com)')
    parser.add_argument('-s', '--subdomains', help='File containing subdomains list')
    parser.add_argument('-d', '--discover', action='store_true', help='Discover common subdomains')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for discovery')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-o', '--output', default='takeover_results.txt', help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Display banner
    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    SUBDOMAIN TAKEOVER DETECTION SCANNER")
    print("    Project #5: Subdomain Takeover Vulnerability Scanner")
    print("=" * 70 + f"{Colors.RESET}\n")
    
    # Get subdomains
    subdomains = []
    
    if args.subdomains:
        # Load from file
        subdomains = load_subdomains_from_file(args.subdomains)
        if not subdomains:
            print(f"{Colors.RED}[!] No subdomains loaded from {args.subdomains}{Colors.RESET}")
            sys.exit(1)
    elif args.discover:
        # Discover common subdomains
        subdomains = discover_subdomains(args.domain, args.wordlist)
        if not subdomains:
            print(f"{Colors.RED}[!] No subdomains discovered{Colors.RESET}")
            sys.exit(1)
    else:
        # Interactive input
        print(f"{Colors.YELLOW}[!] No subdomains provided. Enter subdomains (one per line, blank to finish):{Colors.RESET}")
        print(f"{Colors.CYAN}Tip: Enter subdomains like 'test', 'admin', 'blog'{Colors.RESET}")
        while True:
            line = input("> ").strip()
            if not line:
                break
            subdomains.append(line)
        
        if not subdomains:
            print(f"{Colors.RED}[!] No subdomains provided. Using default list.{Colors.RESET}")
            subdomains = discover_subdomains(args.domain)
    
    print(f"{Colors.BOLD}[*] Testing {len(subdomains)} subdomains on {args.domain}{Colors.RESET}")
    
    # Create scanner
    scanner = SubdomainTakeoverScanner(
        domain=args.domain,
        subdomains=subdomains,
        threads=args.threads,
        timeout=args.timeout,
        output_file=args.output,
        verbose=args.verbose
    )
    
    scanner.run()

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()