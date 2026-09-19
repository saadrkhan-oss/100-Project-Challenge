#!/usr/bin/env python3
"""
Advanced DNS Reconnaissance Toolkit (FIXED for Windows)
Project #16: DNS Enumeration & Subdomain Takeover Advanced

Fixes:
  - Windows BlockingIOError (WinError 10035) on socket
  - KeyboardInterrupt during subdomain loop
  - Network timeouts during enumeration
  - Graceful Ctrl+C handling
"""

import sys
import re
import json
import socket
import argparse
import time
import signal
from datetime import datetime

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.exception
    import dns.rdatatype
    import dns.reversename
except ImportError:
    print("[!] Missing dnspython. Install with: pip install dnspython")
    sys.exit(1)

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] Missing requests. Install with: pip install requests")
    sys.exit(1)

from takeover_services import (
    TAKEOVER_SERVICES, SPF_PATTERN, DKIM_PATTERN,
    DMARC_PREFIX, DMARC_PATTERN
)

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

class DNSReconToolkit:
    def __init__(self, domain, output_file="dns_recon_report.txt",
                 verbose=False, wordlist=None, threads=10):
        self.domain = domain.lower().strip()
        self.output_file = output_file
        self.verbose = verbose
        self.threads = threads
        self.interrupted = False

        # --- Resolver setup with sane timeouts ---
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5
        # Use Cloudflare + Google DNS (more reliable on Windows)
        self.resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']

        # --- Wordlist ---
        if wordlist:
            try:
                with open(wordlist, 'r') as f:
                    self.subdomains = [l.strip() for l in f if l.strip()]
            except Exception as e:
                print(f"{Colors.RED}[!] Cannot read wordlist: {e}{Colors.RESET}")
                self.subdomains = self.default_subdomains()
        else:
            self.subdomains = self.default_subdomains()

        # --- Results ---
        self.results = {
            'domain': self.domain,
            'records': {},
            'zone_transfer': [],
            'subdomains': [],
            'takeover_candidates': [],
            'mail_security': {},
            'dnssec': {},
            'reverse_dns': {},
            'vulnerabilities': [],
        }

    # ------------------------------------------------------------------ #
    # SAFE DNS QUERY (fixes WinError 10035)
    # ------------------------------------------------------------------ #
    def query_record(self, domain, record_type, retries=2):
        """
        Query DNS with retries and full exception handling.
        This is the core fix for Windows BlockingIOError.
        """
        for attempt in range(retries):
            try:
                answers = self.resolver.resolve(domain, record_type)
                return [str(r) for r in answers]

            except (dns.resolver.NoAnswer,
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers,
                    dns.exception.Timeout,
                    dns.resolver.LifetimeTimeout):
                return []

            except BlockingIOError:
                # Windows-specific socket issue — just retry
                if attempt < retries - 1:
                    time.sleep(0.2)
                    continue
                return []

            except OSError as e:
                # WinError 10035 / 10054 / etc.
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] OSError on {record_type} {domain}: {e}{Colors.RESET}")
                if attempt < retries - 1:
                    time.sleep(0.2)
                    continue
                return []

            except KeyboardInterrupt:
                self.interrupted = True
                return []

            except Exception as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] {record_type} {domain}: {e}{Colors.RESET}")
                return []

        return []

    # ------------------------------------------------------------------ #
    # SUBDOMAIN WORDLIST
    # ------------------------------------------------------------------ #
    def default_subdomains(self):
        return [
            'www', 'mail', 'webmail', 'smtp', 'pop', 'imap', 'mx',
            'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
            'ftp', 'sftp', 'ssh', 'vpn', 'remote', 'gateway',
            'api', 'api-v1', 'api-v2', 'rest', 'graphql',
            'dev', 'development', 'staging', 'stage', 'test', 'testing',
            'prod', 'production', 'beta', 'alpha', 'demo',
            'admin', 'administrator', 'panel', 'cpanel', 'whm',
            'blog', 'news', 'forum', 'wiki', 'docs', 'help', 'support',
            'shop', 'store', 'cart', 'checkout', 'payment',
            'cdn', 'static', 'assets', 'media', 'images', 'img',
            'app', 'apps', 'mobile', 'm', 'web',
            'auth', 'login', 'sso', 'id', 'account', 'accounts',
            'cloud', 's3', 'storage', 'files', 'download', 'uploads',
            'monitor', 'status', 'health', 'metrics', 'analytics',
            'mailgun', 'sendgrid', 'mailchimp',
            'git', 'gitlab', 'github', 'bitbucket', 'jenkins',
            'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
        ]

    # ------------------------------------------------------------------ #
    # DNS RECORD ENUMERATION
    # ------------------------------------------------------------------ #
    def enumerate_records(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] DNS RECORD ENUMERATION{Colors.RESET}")
        print(f"    Domain: {self.domain}\n")

        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT',
                       'SOA', 'CAA', 'SRV', 'DS', 'DNSKEY']

        for rtype in record_types:
            if self.interrupted:
                break
            records = self.query_record(self.domain, rtype)
            self.results['records'][rtype] = records

            if records:
                print(f"    {Colors.GREEN}{rtype} Records:{Colors.RESET}")
                for r in records[:10]:
                    print(f"      - {r}")
                if len(records) > 10:
                    print(f"      ... and {len(records) - 10} more")

    # ------------------------------------------------------------------ #
    # ZONE TRANSFER
    # ------------------------------------------------------------------ #
    def test_zone_transfer(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] ZONE TRANSFER TEST (AXFR){Colors.RESET}")

        ns_records = self.results['records'].get('NS', [])
        if not ns_records:
            print(f"    {Colors.YELLOW}[!] No NS records found{Colors.RESET}")
            return

        for ns in ns_records:
            if self.interrupted:
                break

            ns_host = ns.rstrip('.')
            print(f"    Testing {ns_host}...", end=' ')

            try:
                ns_ips = self.query_record(ns_host, 'A')
                if not ns_ips:
                    print(f"{Colors.YELLOW}no A record{Colors.RESET}")
                    continue

                ns_ip = ns_ips[0]

                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, self.domain, timeout=5)
                    )

                    if zone:
                        print(f"{Colors.RED}[!] VULNERABLE{Colors.RESET}")
                        records = []
                        for name, node in zone.nodes.items():
                            subdomain = f"{name}.{self.domain}".rstrip('.')
                            records.append(subdomain)

                        self.results['zone_transfer'].append({
                            'nameserver': ns_host,
                            'ip': ns_ip,
                            'records': records
                        })

                        print(f"      {Colors.RED}Found {len(records)} records via AXFR!{Colors.RESET}")

                        self.results['vulnerabilities'].append({
                            'type': 'Zone Transfer Allowed',
                            'severity': 'CRITICAL',
                            'target': ns_host,
                            'description': f'AXFR allowed on {ns_host} — reveals all DNS records'
                        })

                except (dns.exception.FormError,
                        dns.query.TransferError,
                        dns.exception.Timeout,
                        dns.query.BadResponse,
                        OSError):
                    print(f"{Colors.GREEN}secure (refused){Colors.RESET}")

            except KeyboardInterrupt:
                self.interrupted = True
                print()
                break
            except Exception as e:
                print(f"{Colors.GREEN}secure{Colors.RESET}")
                if self.verbose:
                    print(f"      ({e})")

    # ------------------------------------------------------------------ #
    # SUBDOMAIN ENUMERATION (FIXED)
    # ------------------------------------------------------------------ #
    def enumerate_subdomains(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] SUBDOMAIN ENUMERATION{Colors.RESET}")
        print(f"    Testing {len(self.subdomains)} candidates...\n")

        found = []
        total = len(self.subdomains)

        try:
            for i, sub in enumerate(self.subdomains, 1):
                if self.interrupted:
                    break

                full = f"{sub}.{self.domain}"

                # Progress every 10
                if i % 10 == 0 or i == total:
                    print(f"\r    [{i}/{total}] Testing...", end='', flush=True)

                # Query CNAME first (cheap)
                cname = self.query_record(full, 'CNAME')

                # If no CNAME, query A
                a_records = []
                if not cname:
                    a_records = self.query_record(full, 'A')

                # Query AAAA only if we found something
                aaaa_records = []
                if cname or a_records:
                    aaaa_records = self.query_record(full, 'AAAA')

                if cname or a_records or aaaa_records:
                    entry = {
                        'subdomain': full,
                        'cname': cname[0] if cname else None,
                        'a_records': a_records,
                        'aaaa_records': aaaa_records,
                    }
                    found.append(entry)
                    self.results['subdomains'].append(entry)

                    # Print on new line
                    print()
                    if cname:
                        print(f"    {Colors.CYAN}•{Colors.RESET} {full} → {cname[0]}")
                    else:
                        print(f"    {Colors.CYAN}•{Colors.RESET} {full} → "
                              f"{a_records[0] if a_records else 'AAAA'}")

        except KeyboardInterrupt:
            self.interrupted = True
            print(f"\n    {Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")

        print(f"\n    {Colors.GREEN}Found {len(found)} subdomains{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # SUBDOMAIN TAKEOVER
    # ------------------------------------------------------------------ #
    def detect_takeover(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] SUBDOMAIN TAKEOVER DETECTION{Colors.RESET}")

        if not self.results['subdomains']:
            print(f"    {Colors.YELLOW}[!] No subdomains to analyze{Colors.RESET}")
            return

        candidates = []

        for entry in self.results['subdomains']:
            if self.interrupted:
                break

            cname = entry.get('cname')
            if not cname:
                continue

            cname_lower = cname.lower().rstrip('.')

            for pattern, info in TAKEOVER_SERVICES.items():
                if pattern in cname_lower:
                    is_vulnerable = self.verify_takeover(
                        entry['subdomain'], info['fingerprint']
                    )

                    candidate = {
                        'subdomain': entry['subdomain'],
                        'cname': cname,
                        'service': info['service'],
                        'severity': info['severity'],
                        'verified': is_vulnerable,
                    }
                    candidates.append(candidate)
                    self.results['takeover_candidates'].append(candidate)

                    if is_vulnerable:
                        print(f"    {Colors.RED}[!] TAKEOVER: {entry['subdomain']} "
                              f"→ {info['service']}{Colors.RESET}")
                        self.results['vulnerabilities'].append({
                            'type': 'Subdomain Takeover',
                            'severity': info['severity'],
                            'target': entry['subdomain'],
                            'description': f'{entry["subdomain"]} → {cname} '
                                          f'({info["service"]}) is unclaimed'
                        })
                    else:
                        print(f"    {Colors.GREEN}✓{Colors.RESET} {entry['subdomain']} "
                              f"→ {info['service']} (active)")

        if not candidates:
            print(f"    {Colors.GREEN}✓ No takeover candidates found{Colors.RESET}")

    def verify_takeover(self, subdomain, fingerprint):
        for scheme in ['http', 'https']:
            try:
                r = requests.get(
                    f"{scheme}://{subdomain}",
                    timeout=5, verify=False,
                    headers={'User-Agent': 'Mozilla/5.0'},
                    allow_redirects=False
                )
                if fingerprint.lower() in r.text.lower():
                    return True
            except Exception:
                continue
        return False

    # ------------------------------------------------------------------ #
    # MAIL SECURITY
    # ------------------------------------------------------------------ #
    def analyze_mail_security(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] MAIL SECURITY ANALYSIS{Colors.RESET}")

        # SPF
        spf_found = False
        spf_value = None
        for txt in self.results['records'].get('TXT', []):
            if 'v=spf1' in txt:
                spf_found = True
                spf_value = txt
                break

        # DMARC
        dmarc_found = False
        dmarc_value = None
        dmarc_records = self.query_record(f"_dmarc.{self.domain}", 'TXT')
        for rec in dmarc_records:
            if 'v=DMARC1' in rec:
                dmarc_found = True
                dmarc_value = rec
                break

        # DKIM (common selectors)
        dkim_found = False
        dkim_value = None
        for selector in ['default', 'google', 'mail', 'dkim', 'k1', 's1']:
            if self.interrupted:
                break
            dkim_query = f"{selector}._domainkey.{self.domain}"
            dkim_records = self.query_record(dkim_query, 'TXT')
            for rec in dkim_records:
                if 'v=DKIM1' in rec or 'k=rsa' in rec:
                    dkim_found = True
                    dkim_value = f"{selector}: {rec[:80]}..."
                    break
            if dkim_found:
                break

        self.results['mail_security'] = {
            'spf': {'present': spf_found, 'value': spf_value},
            'dkim': {'present': dkim_found, 'value': dkim_value},
            'dmarc': {'present': dmarc_found, 'value': dmarc_value},
        }

        spf_status = (f"{Colors.GREEN}✓ Present{Colors.RESET}" if spf_found
                      else f"{Colors.RED}✗ Missing{Colors.RESET}")
        dkim_status = (f"{Colors.GREEN}✓ Present{Colors.RESET}" if dkim_found
                       else f"{Colors.RED}✗ Missing{Colors.RESET}")
        dmarc_status = (f"{Colors.GREEN}✓ Present{Colors.RESET}" if dmarc_found
                        else f"{Colors.RED}✗ Missing{Colors.RESET}")

        print(f"    SPF:   {spf_status}")
        if spf_value:
            print(f"           {spf_value[:100]}")
        print(f"    DKIM:  {dkim_status}")
        print(f"    DMARC: {dmarc_status}")
        if dmarc_value:
            print(f"           {dmarc_value[:100]}")

        if not dmarc_found:
            self.results['vulnerabilities'].append({
                'type': 'Missing DMARC',
                'severity': 'MEDIUM',
                'description': 'No DMARC record — email spoofing possible'
            })
        if not dkim_found:
            self.results['vulnerabilities'].append({
                'type': 'Missing DKIM',
                'severity': 'LOW',
                'description': 'No DKIM record detected — email auth weakened'
            })
        if not spf_found:
            self.results['vulnerabilities'].append({
                'type': 'Missing SPF',
                'severity': 'HIGH',
                'description': 'No SPF record — email spoofing trivial'
            })

    # ------------------------------------------------------------------ #
    # REVERSE DNS
    # ------------------------------------------------------------------ #
    def reverse_dns_lookup(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] REVERSE DNS LOOKUP{Colors.RESET}")

        for ip in self.results['records'].get('A', []):
            if self.interrupted:
                break
            try:
                rev = dns.reversename.from_address(ip)
                ptr_answers = self.resolver.resolve(rev, 'PTR')
                ptr = str(ptr_answers[0])
                self.results['reverse_dns'][ip] = ptr
                print(f"    {ip} → {ptr}")
            except Exception:
                if self.verbose:
                    print(f"    {ip} → (no PTR)")

    # ------------------------------------------------------------------ #
    # INFRASTRUCTURE MAP
    # ------------------------------------------------------------------ #
    def build_infrastructure_map(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] DNS INFRASTRUCTURE MAP{Colors.RESET}")
        print(f"    {Colors.BOLD}{self.domain}{Colors.RESET}")

        subs = sorted(self.results['subdomains'], key=lambda x: x['subdomain'])

        for i, entry in enumerate(subs):
            is_last = (i == len(subs) - 1)
            prefix = "    └── " if is_last else "    ├── "

            target = (entry.get('cname') or
                      (entry.get('a_records', ['?'])[0]
                       if entry.get('a_records') else '?'))

            note = ""
            for cand in self.results['takeover_candidates']:
                if cand['subdomain'] == entry['subdomain']:
                    note = f" {Colors.RED}[TAKEOVER: {cand['service']}]{Colors.RESET}"
                    break

            print(f"{prefix}{entry['subdomain']} → {target}{note}")

    # ------------------------------------------------------------------ #
    # VULNERABILITIES
    # ------------------------------------------------------------------ #
    def print_vulnerabilities(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[⚠️] VULNERABILITIES FOUND{Colors.RESET}")

        if not self.results['vulnerabilities']:
            print(f"    {Colors.GREEN}✓ No vulnerabilities detected{Colors.RESET}")
            return

        for i, v in enumerate(self.results['vulnerabilities'], 1):
            color = (Colors.RED if v['severity'] in ('CRITICAL', 'HIGH')
                     else Colors.YELLOW if v['severity'] == 'MEDIUM'
                     else Colors.CYAN)
            target = v.get('target', '')
            target_str = f" [{target}]" if target else ""
            print(f"    {i}. {color}[{v['severity']}]{Colors.RESET} "
                  f"{v['type']}{target_str}")
            print(f"       {v['description']}")

    # ------------------------------------------------------------------ #
    # REPORT
    # ------------------------------------------------------------------ #
    def save_report(self):
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("ADVANCED DNS RECONNAISSANCE REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Domain:      {self.domain}\n")
            f.write(f"Scan Date:   {datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"Interrupted: {self.interrupted}\n")
            f.write("=" * 80 + "\n\n")

            f.write("DNS RECORDS\n" + "-" * 50 + "\n")
            for rtype, records in self.results['records'].items():
                if records:
                    f.write(f"  {rtype}:\n")
                    for r in records:
                        f.write(f"    - {r}\n")
            f.write("\n")

            if self.results['subdomains']:
                f.write("DISCOVERED SUBDOMAINS\n" + "-" * 50 + "\n")
                for entry in self.results['subdomains']:
                    f.write(f"  {entry['subdomain']}\n")
                    if entry.get('cname'):
                        f.write(f"    CNAME → {entry['cname']}\n")
                    if entry.get('a_records'):
                        f.write(f"    A → {', '.join(entry['a_records'])}\n")
                f.write("\n")

            if self.results['zone_transfer']:
                f.write("ZONE TRANSFER (VULNERABLE)\n" + "-" * 50 + "\n")
                for zt in self.results['zone_transfer']:
                    f.write(f"  Nameserver: {zt['nameserver']} ({zt['ip']})\n")
                    f.write(f"  Records:    {len(zt['records'])}\n\n")

            ms = self.results['mail_security']
            if ms:
                f.write("MAIL SECURITY\n" + "-" * 50 + "\n")
                f.write(f"  SPF:   {'Present' if ms['spf']['present'] else 'Missing'}\n")
                if ms['spf'].get('value'):
                    f.write(f"         {ms['spf']['value']}\n")
                f.write(f"  DKIM:  {'Present' if ms['dkim']['present'] else 'Missing'}\n")
                f.write(f"  DMARC: {'Present' if ms['dmarc']['present'] else 'Missing'}\n")
                if ms['dmarc'].get('value'):
                    f.write(f"         {ms['dmarc']['value']}\n")
                f.write("\n")

            if self.results['takeover_candidates']:
                f.write("SUBDOMAIN TAKEOVER CANDIDATES\n" + "-" * 50 + "\n")
                for cand in self.results['takeover_candidates']:
                    status = 'VERIFIED VULNERABLE' if cand['verified'] else 'Active'
                    f.write(f"  [{cand['severity']}] {cand['subdomain']}\n")
                    f.write(f"    CNAME:   {cand['cname']}\n")
                    f.write(f"    Service: {cand['service']}\n")
                    f.write(f"    Status:  {status}\n\n")

            f.write("VULNERABILITIES\n" + "-" * 50 + "\n")
            if self.results['vulnerabilities']:
                for v in self.results['vulnerabilities']:
                    f.write(f"  [{v['severity']}] {v['type']}\n")
                    f.write(f"    {v['description']}\n\n")
            else:
                f.write("  None detected\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("Generated by Advanced DNS Reconnaissance Toolkit — Project #16\n")
            f.write("=" * 80 + "\n")

        print(f"\n{Colors.GREEN}[✓] Report saved: {self.output_file}{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # MAIN SCAN
    # ------------------------------------------------------------------ #
    def scan(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}Advanced DNS Reconnaissance Toolkit{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}Target: {self.domain}{Colors.RESET}")
        print(f"{Colors.BOLD}Started: {datetime.now():%Y-%m-%d %H:%M:%S}{Colors.RESET}\n")

        start = time.time()

        # Verify domain resolves
        try:
            socket.gethostbyname(self.domain)
        except socket.gaierror:
            print(f"{Colors.RED}[!] Cannot resolve {self.domain}{Colors.RESET}")
            return

        try:
            self.enumerate_records()
            self.test_zone_transfer()
            self.enumerate_subdomains()
            self.detect_takeover()
            self.analyze_mail_security()
            self.reverse_dns_lookup()
            self.build_infrastructure_map()
            self.print_vulnerabilities()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user "
                  f"— saving partial report...{Colors.RESET}")
            self.interrupted = True

        finally:
            # ALWAYS save report, even on interrupt
            self.save_report()

            status = "interrupted" if self.interrupted else "completed"
            print(f"\n{Colors.GREEN}[✓] Scan {status} in "
                  f"{time.time() - start:.2f}s{Colors.RESET}")

# ---------------------------------------------------------------------- #
# MAIN
# ---------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="Advanced DNS Reconnaissance Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dns_recon.py example.com
  python dns_recon.py github.com -v
  python dns_recon.py yourdomain.com -w subdomains.txt
  python dns_recon.py example.com -o my_report.txt
        """
    )
    p.add_argument('domain', help='Target domain')
    p.add_argument('-w', '--wordlist', help='Subdomain wordlist file')
    p.add_argument('-o', '--output', default='dns_recon_report.txt',
                   help='Output file name')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  ADVANCED DNS RECONNAISSANCE TOOLKIT")
    print("  Project #16: DNS Enumeration & Subdomain Takeover")
    print("=" * 70)
    print(f"{Colors.RESET}")

    tool = DNSReconToolkit(
        domain=args.domain,
        output_file=args.output,
        verbose=args.verbose,
        wordlist=args.wordlist
    )

    try:
        tool.scan()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Exiting gracefully...{Colors.RESET}")
        try:
            tool.save_report()
        except Exception:
            pass
        sys.exit(0)

if __name__ == '__main__':
    main()