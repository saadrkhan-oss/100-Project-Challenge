"""
Phase 2: Active Reconnaissance
Port scanning + live host detection + service banners
"""

import socket
import ssl
import time
import re
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class ActiveRecon:
    # Top 100 common ports
    TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161,
        389, 443, 445, 465, 587, 636, 873, 993, 995, 1080,
        1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
        2181, 3000, 3128, 3268, 3306, 3389, 3690, 4000, 4443,
        5000, 5432, 5555, 5601, 5672, 5900, 5984, 5985, 5986,
        6379, 6443, 7001, 7002, 7443, 8000, 8001, 8006, 8008,
        8009, 8010, 8043, 8069, 8080, 8081, 8082, 8083, 8086,
        8088, 8090, 8123, 8161, 8180, 8200, 8300, 8443, 8500,
        8834, 8880, 8888, 8983, 9000, 9001, 9042, 9060, 9080,
        9090, 9091, 9200, 9300, 9418, 9443, 9600, 9999, 10000,
        10250, 11211, 15672, 27017, 27018, 50000, 50070,
    ]

    SERVICE_MAP = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC',
        139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP',
        443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP',
        636: 'LDAPS', 873: 'Rsync', 993: 'IMAPS', 995: 'POP3S',
        1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS',
        3000: 'Node/Grafana', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
        9200: 'Elasticsearch', 27017: 'MongoDB',
    }

    BANNER_PORTS = {
        21: b'QUIT\r\n',
        22: b'SSH-2.0-Client\r\n',
        25: b'EHLO test\r\n',
        80: b'HEAD / HTTP/1.0\r\n\r\n',
        110: b'QUIT\r\n',
        143: b'A001 LOGOUT\r\n',
        443: b'HEAD / HTTP/1.0\r\n\r\n',
    }

    def __init__(self, domain, subdomains=None, timeout=3,
                 threads=100, verbose=False):
        self.domain = domain
        self.subdomains = subdomains or []
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose

        self.live_hosts = []          # list of {host, ip, ports}
        self.all_open_ports = set()

    def get_ip(self, host):
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    def check_host_alive(self, host):
        """Check if host is alive via DNS resolution."""
        ip = self.get_ip(host)
        return (host, ip) if ip else None

    def grab_banner(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((ip, port)) != 0:
                sock.close()
                return None
            if port in self.BANNER_PORTS:
                try:
                    sock.send(self.BANNER_PORTS[port])
                    time.sleep(0.3)
                except Exception:
                    pass
            banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
            sock.close()
            banner = ' '.join(banner.split())[:100]
            return banner if banner else None
        except Exception:
            return None

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                service = self.SERVICE_MAP.get(port, 'Unknown')
                banner = self.grab_banner(ip, port)
                return {
                    'port': port,
                    'service': service,
                    'banner': banner,
                }
        except Exception:
            pass
        return None

    def scan_host(self, host):
        """Scan a single host."""
        ip = self.get_ip(host)
        if not ip:
            return None

        result = {'host': host, 'ip': ip, 'ports': [], 'technologies': {}}

        # Port scan (parallel)
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.scan_port, ip, p): p for p in self.TOP_PORTS}
            for fut in as_completed(futures):
                port_info = fut.result()
                if port_info:
                    open_ports.append(port_info)

        open_ports.sort(key=lambda x: x['port'])
        result['ports'] = open_ports

        # Detect technologies on HTTP/HTTPS ports
        for scheme, port in [('http', 80), ('https', 443),
                             ('http', 8080), ('https', 8443),
                             ('http', 8000), ('https', 4443)]:
            if any(p['port'] == port for p in open_ports):
                tech = self.detect_tech(f"{scheme}://{host}:{port}")
                if tech:
                    result['technologies'][f"{scheme}:{port}"] = tech

        return result

    def detect_tech(self, url):
        """Detect technologies from headers."""
        try:
            r = requests.get(url, timeout=self.timeout, verify=False,
                             allow_redirects=True,
                             headers={'User-Agent': 'Mozilla/5.0'})
            tech = {}
            h = r.headers
            if 'Server' in h:
                tech['server'] = h['Server']
            if 'X-Powered-By' in h:
                tech['powered_by'] = h['X-Powered-By']
            if 'X-Generator' in h:
                tech['generator'] = h['X-Generator']
            if 'Content-Type' in h:
                tech['content_type'] = h['Content-Type']
            return tech
        except Exception:
            return {}

    def run(self):
        print(f"\n{Colors.BOLD}{Colors.CYAN}===== PHASE 2: ACTIVE RECON ====={Colors.RESET}")

        # Build host list: root + subdomains
        hosts = [self.domain] + list(self.subdomains)
        hosts = list(set(hosts))

        print(f"    Scanning {len(hosts)} host(s) across {len(self.TOP_PORTS)} ports...")

        results = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(self.scan_host, h): h for h in hosts}
            for fut in as_completed(futures):
                r = fut.result()
                if r:
                    results.append(r)
                    n_ports = len(r['ports'])
                    if n_ports:
                        print(f"    {Colors.GREEN}[+]{Colors.RESET} {r['host']} "
                              f"({r['ip']}) — {n_ports} open port(s)")
                        for p in r['ports']:
                            self.all_open_ports.add(p['port'])
                    else:
                        print(f"    {Colors.YELLOW}[-]{Colors.RESET} {r['host']} "
                              f"({r['ip']}) — no open ports")

        self.live_hosts = results
        return {
            'live_hosts': results,
            'all_open_ports': sorted(self.all_open_ports),
        }