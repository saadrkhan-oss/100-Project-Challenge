#!/usr/bin/env python3
"""
Subdomain Enumeration Tool - Build from Scratch
Project #1: Passive Reconnaissance
"""

import socket
import sys
import time
import json
import requests
import dns.resolver
import dns.zone
from concurrent.futures import ThreadPoolExecutor, as_completed

class SubdomainEnumerator:
    def __init__(self, domain, wordlist_path="subdomains.txt"):
        self.domain = domain
        self.subdomains_found = set()
        self.wordlist_path = wordlist_path
        
    def resolve_subdomain(self, subdomain):
        """Attempt to resolve a subdomain to an IP address"""
        full_domain = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            return (full_domain, ip)
        except socket.gaierror:
            return None
        except Exception:
            return None
    
    def brute_force_dns(self, wordlist, max_workers=50):
        """Brute force subdomains using a wordlist"""
        print(f"[*] Starting DNS brute-force on {self.domain}")
        print(f"[*] Using {len(wordlist)} subdomain candidates")
        
        found_count = 0
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.resolve_subdomain, sub): sub 
                      for sub in wordlist}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    full_domain, ip = result
                    self.subdomains_found.add(full_domain)
                    found_count += 1
                    print(f"[+] Found: {full_domain} -> {ip}")
        
        print(f"[*] DNS brute-force complete. Found {found_count} subdomains")
        return self.subdomains_found
    
    def query_certificate_logs(self):
        """Query Certificate Transparency logs for subdomains"""
        print(f"[*] Querying Certificate Transparency logs for {self.domain}")
        
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            
            if response.status_code == 200:
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    print("[!] Invalid JSON response from crt.sh")
                    return set()
                
                cert_subdomains = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        for name in name_value.split('\n'):
                            name = name.strip().lower()
                            if name.endswith(self.domain) and name != self.domain:
                                if name.startswith('*.'):
                                    name = name[2:]
                                cert_subdomains.add(name)
                
                print(f"[+] Found {len(cert_subdomains)} subdomains from certificate logs")
                self.subdomains_found.update(cert_subdomains)
                return cert_subdomains
            else:
                print(f"[!] Certificate log query failed: {response.status_code}")
                return set()
                
        except Exception as e:
            print(f"[!] Error querying certificate logs: {e}")
            return set()
    
    def attempt_zone_transfer(self):
        """Attempt DNS zone transfer (AXFR)"""
        print(f"[*] Attempting DNS zone transfer for {self.domain}")
        
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            nameservers = [str(ns).rstrip('.') for ns in ns_records]
            print(f"[*] Nameservers found: {nameservers}")
            
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=5))
                    if zone:
                        print(f"[+] Zone transfer successful from {ns}!")
                        for name, node in zone.nodes.items():
                            if name:
                                subdomain = f"{name}.{self.domain}"
                                self.subdomains_found.add(subdomain)
                                print(f"[+] Found: {subdomain}")
                        return self.subdomains_found
                    else:
                        print(f"[-] Zone transfer failed from {ns}")
                        
                except Exception as e:
                    print(f"[-] Zone transfer not allowed on {ns}")
                    continue
                    
        except Exception as e:
            print(f"[!] Error during zone transfer: {e}")
        return set()
    
    def load_wordlist(self, wordlist_path):
        """Load subdomain wordlist from file or use default"""
        try:
            with open(wordlist_path, 'r') as f:
                wordlist = [line.strip().lower() for line in f if line.strip()]
                print(f"[*] Loaded {len(wordlist)} subdomains from {wordlist_path}")
                return wordlist
        except FileNotFoundError:
            default_wordlist = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
                'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 
                'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin',
                'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 
                'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 
                'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web',
                'media', 'email', 'images', 'img', 'video', 'download', 'dns',
                'ns4', 'dns2', 'dns1', 'gw', 'firewall', 'proxy', 'sip', 'voip',
                'api', 'app', 'stage', 'staging', 'prod', 'production', 'test',
                'cloud', 'server', 'webserver', 'appserver', 'db', 'database'
            ]
            print(f"[!] Wordlist not found, using default {len(default_wordlist)} entries")
            print(f"[!] Create a file named 'subdomains.txt' for custom wordlist")
            return default_wordlist
    
    def save_results(self, filename="subdomains_found.txt"):
        """Save found subdomains to file"""
        with open(filename, 'w') as f:
            for subdomain in sorted(self.subdomains_found):
                f.write(f"{subdomain}\n")
        print(f"[*] Results saved to {filename}")
    
    def run(self):
        """Main execution method"""
        print("=" * 60)
        print("    SUBSCOUT - Subdomain Enumeration Tool")
        print("    Project #1: Passive Reconnaissance")
        print("    Build from Scratch")
        print("=" * 60)
        print(f"[*] Target Domain: {self.domain}")
        
        start_time = time.time()
        
        wordlist = self.load_wordlist(self.wordlist_path)
        
        print("\n[Phase 1: DNS Brute-Force]")
        dns_count_before = len(self.subdomains_found)
        self.brute_force_dns(wordlist)
        dns_count = len(self.subdomains_found) - dns_count_before
        
        print("\n[Phase 2: Certificate Logs Query]")
        cert_count_before = len(self.subdomains_found)
        self.query_certificate_logs()
        cert_count = len(self.subdomains_found) - cert_count_before
        
        print("\n[Phase 3: Zone Transfer Attempt]")
        zone_count_before = len(self.subdomains_found)
        self.attempt_zone_transfer()
        zone_count = len(self.subdomains_found) - zone_count_before
        
        self.save_results()
        
        elapsed_time = time.time() - start_time
        print("\n" + "=" * 60)
        print("[✓] ENUMERATION COMPLETE")
        print(f"[✓] Time taken: {elapsed_time:.2f} seconds")
        print(f"\n[📊] BREAKDOWN:")
        print(f"    DNS Brute-Force:        {dns_count} subdomains")
        print(f"    Certificate Logs:        {cert_count} subdomains")
        print(f"    Zone Transfer:           {zone_count} subdomains")
        print(f"\n[📈] TOTAL UNIQUE:           {len(self.subdomains_found)} subdomains")
        print(f"[✓] Results saved to: subdomains_found.txt")
        print("=" * 60)
        
        if self.subdomains_found:
            print("\n[🔍] Sample of found subdomains:")
            for sub in list(self.subdomains_found)[:10]:
                print(f"    • {sub}")
            if len(self.subdomains_found) > 10:
                print(f"    ... and {len(self.subdomains_found) - 10} more")
        else:
            print("\n[!] No subdomains found. Try a larger wordlist or different domain.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python subdomain_enum.py <domain> [wordlist.txt]")
        print("Example: python subdomain_enum.py example.com")
        print("Example: python subdomain_enum.py example.com subdomains.txt")
        sys.exit(1)
    
    domain = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else "subdomains.txt"
    
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"[!] Invalid domain: {domain}")
        sys.exit(1)
    
    enumerator = SubdomainEnumerator(domain, wordlist)
    enumerator.run()

if __name__ == "__main__":
    main()
