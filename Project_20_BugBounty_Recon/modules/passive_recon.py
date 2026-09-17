"""
Phase 1: Passive Reconnaissance
Subdomain enumeration + DNS + WHOIS
"""

import socket
import re
import json
import time
import requests
import urllib3
from datetime import datetime

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] pip install dnspython")
    raise

try:
    import whois
except ImportError:
    whois = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class PassiveRecon:
    def __init__(self, domain, timeout=10, verbose=False):
        self.domain = domain.lower().strip()
        self.timeout = timeout
        self.verbose = verbose

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
        self.resolver.nameservers = ['1.1.1.1', '8.8.8.8']

        self.subdomains = set()
        self.dns_records = {}
        self.whois_info = {}

    # ------------------------------------------------------------------ #
    # DNS ENUMERATION
    # ------------------------------------------------------------------ #
    def safe_query(self, name, rtype, retries=2):
        for _ in range(retries):
            try:
                answers = self.resolver.resolve(name, rtype)
                return [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout,
                    dns.resolver.LifetimeTimeout):
                return []
            except (BlockingIOError, OSError):
                time.sleep(0.2)
                continue
            except Exception:
                return []
        return []

    def enumerate_dns(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] DNS RECORDS{Colors.RESET}")
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA']:
            records = self.safe_query(self.domain, rtype)
            if records:
                self.dns_records[rtype] = records
                print(f"    {rtype}: {len(records)} record(s)")
                for r in records[:3]:
                    print(f"      - {r[:80]}")
        return self.dns_records

    # ------------------------------------------------------------------ #
    # SUBDOMAIN SOURCES
    # ------------------------------------------------------------------ #
    def from_crtsh(self):
        """crt.sh certificate transparency logs."""
        found = set()
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = requests.get(url, timeout=20, verify=False,
                             headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip().lower().lstrip('*.')
                        if name.endswith(self.domain) and name != self.domain:
                            found.add(name)
        except Exception as e:
            if self.verbose:
                print(f"    [!] crt.sh error: {e}")
        return found

    def from_hackertarget(self):
        """HackerTarget hostsearch."""
        found = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            r = requests.get(url, timeout=20, verify=False)
            if r.status_code == 200 and 'error' not in r.text.lower():
                for line in r.text.splitlines():
                    if ',' in line:
                        host = line.split(',')[0].strip().lower()
                        if host.endswith(self.domain):
                            found.add(host)
        except Exception:
            pass
        return found

    def from_alienvault(self):
        """AlienVault OTX passive DNS."""
        found = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            r = requests.get(url, timeout=20, verify=False)
            if r.status_code == 200:
                data = r.json()
                for entry in data.get('passive_dns', []):
                    host = entry.get('hostname', '').lower()
                    if host.endswith(self.domain):
                        found.add(host)
        except Exception:
            pass
        return found

    def from_bruteforce(self):
        """Small built-in subdomain brute-force."""
        common = [
            'www', 'mail', 'api', 'dev', 'staging', 'test', 'admin',
            'blog', 'shop', 'app', 'cdn', 'static', 'assets', 'media',
            'vpn', 'remote', 'git', 'gitlab', 'jenkins', 'portal',
            'dashboard', 'auth', 'sso', 'login', 'help', 'support',
            'docs', 'wiki', 'forum', 'news', 'status', 'monitor',
            'db', 'mysql', 'postgres', 'redis', 'mongo', 'ftp',
            'smtp', 'imap', 'pop', 'webmail', 'ns1', 'ns2', 'mx',
        ]
        found = set()
        for sub in common:
            full = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(full)
                found.add(full)
            except socket.gaierror:
                continue
        return found

    def enumerate_subdomains(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] SUBDOMAIN ENUMERATION{Colors.RESET}")

        sources = [
            ('crt.sh', self.from_crtsh),
            ('hackertarget', self.from_hackertarget),
            ('alienvault', self.from_alienvault),
            ('bruteforce', self.from_bruteforce),
        ]

        for name, func in sources:
            try:
                result = func()
                print(f"    {name}: {len(result)} subdomain(s)")
                self.subdomains.update(result)
            except Exception as e:
                print(f"    {name}: error ({str(e)[:40]})")

        print(f"\n    {Colors.GREEN}Total unique: {len(self.subdomains)}{Colors.RESET}")
        return self.subdomains

    # ------------------------------------------------------------------ #
    # WHOIS
    # ------------------------------------------------------------------ #
    def do_whois(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] WHOIS{Colors.RESET}")
        if not whois:
            print(f"    {Colors.YELLOW}[!] python-whois not installed{Colors.RESET}")
            return {}
        try:
            w = whois.whois(self.domain)
            self.whois_info = {
                'registrar': str(w.registrar) if w.registrar else None,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': list(w.name_servers) if w.name_servers else [],
                'emails': list(w.emails) if w.emails else [],
            }
            for k, v in self.whois_info.items():
                if v:
                    print(f"    {k}: {str(v)[:80]}")
            return self.whois_info
        except Exception as e:
            print(f"    {Colors.YELLOW}[!] WHOIS error: {str(e)[:60]}{Colors.RESET}")
            return {}

    # ------------------------------------------------------------------ #
    # MAIN
    # ------------------------------------------------------------------ #
    def run(self):
        print(f"\n{Colors.BOLD}{Colors.CYAN}===== PHASE 1: PASSIVE RECON ====={Colors.RESET}")
        self.enumerate_dns()
        self.enumerate_subdomains()
        self.do_whois()
        return {
            'dns_records': self.dns_records,
            'subdomains': sorted(self.subdomains),
            'whois': self.whois_info,
        }