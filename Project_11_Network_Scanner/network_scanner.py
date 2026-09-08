#!/usr/bin/env python3
"""
Advanced Network Scanner with OS Detection
Project #11: Network Scanning & OS Fingerprinting
"""

import socket
import sys
import time
import threading
import ipaddress
import subprocess
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import os
import platform

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

class NetworkScanner:
    def __init__(self, target, ports=None, timeout=2, threads=50, output_file="network_scan_report.txt", verbose=False):
        self.target = target
        self.ports = ports or [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
        self.timeout = timeout
        self.threads = min(threads, 50)
        self.output_file = output_file
        self.verbose = verbose
        
        self.lock = threading.Lock()
        self.results = {}
        self.total_hosts = 0
        
        # Parse target
        self.hosts_list = self.parse_target(target)
        
        # Common services for banner grabbing
        self.banner_ports = {
            21: b'QUIT\r\n',
            22: b'SSH-2.0-Client\r\n',
            25: b'EHLO test\r\n',
            80: b'HEAD / HTTP/1.0\r\n\r\n',
            110: b'QUIT\r\n',
            143: b'A001 LOGOUT\r\n',
            443: b'HEAD / HTTP/1.0\r\n\r\n',
            3306: b'\x00\x00\x00\x01\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            3389: b'\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00',
            5432: b'\x00\x00\x00\x08\x04\xd2\x16\x2f',
            6379: b'INFO\r\n',
        }
        
        # OS detection based on TTL
        self.ttl_os = {
            64: ('Linux/Unix/macOS', 'HIGH'),
            128: ('Windows', 'HIGH'),
            255: ('Cisco/Network Device', 'MEDIUM'),
            60: ('Linux (older)', 'MEDIUM'),
            65: ('Linux (some)', 'MEDIUM'),
            127: ('Windows (some)', 'MEDIUM'),
        }
    
    def parse_target(self, target):
        """Parse target into list of IPs"""
        hosts = []
        
        # Check if it's a CIDR range
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
                print(f"{Colors.CYAN}[*] CIDR range: {target} ({len(hosts)} hosts){Colors.RESET}")
                return hosts
            except ValueError:
                pass
        
        # Check if it's an IP range
        if '-' in target:
            try:
                parts = target.split('-')
                base = parts[0]
                if len(parts) == 2:
                    start_ip = base
                    end_num = int(parts[1])
                    base_parts = base.split('.')
                    base_prefix = '.'.join(base_parts[:-1])
                    start_num = int(base_parts[-1])
                    for i in range(start_num, end_num + 1):
                        hosts.append(f"{base_prefix}.{i}")
                    print(f"{Colors.CYAN}[*] IP range: {target} ({len(hosts)} hosts){Colors.RESET}")
                    return hosts
            except ValueError:
                pass
        
        # Single IP or hostname
        try:
            ipaddress.ip_address(target)
            hosts.append(target)
            print(f"{Colors.CYAN}[*] Single IP: {target}{Colors.RESET}")
            return hosts
        except ValueError:
            try:
                ip = socket.gethostbyname(target)
                hosts.append(ip)
                print(f"{Colors.CYAN}[*] Hostname: {target} -> {ip}{Colors.RESET}")
                return hosts
            except socket.gaierror:
                print(f"{Colors.RED}[!] Cannot resolve: {target}{Colors.RESET}")
                sys.exit(1)
    
    def ping_host(self, ip):
        """Ping a host using multiple methods"""
        # Special case for localhost - always alive
        if ip in ['127.0.0.1', '::1', 'localhost']:
            print(f"{Colors.GREEN}[✓] Localhost detected - assuming alive{Colors.RESET}")
            return True, 128  # Windows default TTL for localhost
        
        # Method 1: TCP connection test (most reliable)
        test_ports = [80, 443, 22, 25, 53, 21, 23]
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True, self.get_ttl_from_connection(ip, port)
            except:
                continue
        
        # Method 2: Raw ping command
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=2,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=2
                )
            
            if result.returncode == 0:
                output = result.stdout.decode('utf-8', errors='ignore')
                ttl_match = re.search(r'TTL=(\d+)', output)
                if ttl_match:
                    return True, int(ttl_match.group(1))
                return True, None
        except:
            pass
        
        return False, None
    
    def get_ttl_from_connection(self, ip, port):
        """Get TTL from TCP connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            # Try to get TTL from socket
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            sock.close()
            return ttl
        except:
            return None
    
    def scan_port(self, ip, port):
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            result = sock.connect_ex((ip, port))
            elapsed = time.time() - start_time
            
            if result == 0:
                service = self.get_service_name(port)
                banner = self.grab_banner(ip, port, sock)
                sock.close()
                
                return {
                    'port': port,
                    'service': service,
                    'state': 'open',
                    'banner': banner,
                    'response_time': elapsed
                }
            
            sock.close()
            return None
            
        except socket.error:
            return None
        except Exception:
            return None
    
    def get_service_name(self, port):
        """Get service name for a port"""
        services = {
            20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC',
            139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
            1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
    
    def grab_banner(self, ip, port, sock):
        """Grab banner from open port"""
        try:
            sock.settimeout(2)
            
            if port in self.banner_ports:
                sock.send(self.banner_ports[port])
                time.sleep(0.5)
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            banner = ' '.join(banner.split())
            if len(banner) > 100:
                banner = banner[:100] + '...'
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def scan_host(self, ip):
        """Scan a single host"""
        result = {
            'ip': ip,
            'alive': False,
            'ttl': None,
            'os': None,
            'os_confidence': None,
            'ports': []
        }
        
        # Ping host
        alive, ttl = self.ping_host(ip)
        
        if alive:
            result['alive'] = True
            result['ttl'] = ttl
            
            # Identify OS from TTL
            if ttl:
                os_info = self.ttl_os.get(ttl, ('Unknown', 'LOW'))
                result['os'] = os_info[0]
                result['os_confidence'] = os_info[1]
            else:
                result['os'] = 'Unknown'
                result['os_confidence'] = 'LOW'
            
            # Scan TCP ports
            tcp_ports = []
            with ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
                futures = {executor.submit(self.scan_port, ip, port): port for port in self.ports}
                for future in as_completed(futures):
                    port_result = future.result()
                    if port_result:
                        tcp_ports.append(port_result)
            
            result['ports'] = sorted(tcp_ports, key=lambda x: x['port'])
            
            # Print results
            with self.lock:
                self.print_host_result(result)
        
        return result
    
    def print_host_result(self, result):
        """Print results for a single host"""
        if not result['alive']:
            return
        
        ip = result['ip']
        ttl = result['ttl'] or '?'
        os_name = result['os'] or 'Unknown'
        confidence = result['os_confidence'] or 'LOW'
        ports = result['ports']
        
        os_color = Colors.GREEN if 'Linux' in os_name or 'Unix' in os_name else Colors.BLUE if 'Windows' in os_name else Colors.YELLOW
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Host: {ip}{Colors.RESET}")
        print(f"    {Colors.YELLOW}TTL:{Colors.RESET} {ttl}")
        print(f"    {Colors.YELLOW}OS:{Colors.RESET} {os_color}{os_name}{Colors.RESET} (Confidence: {confidence})")
        
        if ports:
            print(f"    {Colors.YELLOW}Open Ports:{Colors.RESET}")
            for p in ports:
                banner = f" ({p['banner']})" if p['banner'] else ""
                print(f"      {p['port']}/tcp - {p['service']}{banner}")
        else:
            print(f"    {Colors.YELLOW}Open Ports:{Colors.RESET} None found")
    
    def scan(self):
        """Main scan method"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] Advanced Network Scanner{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Target: {self.target}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Hosts: {len(self.hosts_list)}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Ports: {len(self.ports)}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Threads: {self.threads}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Timeout: {self.timeout}s{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print("")
        
        start_time = time.time()
        
        self.total_hosts = len(self.hosts_list)
        completed = 0
        
        # For single host, scan directly
        if len(self.hosts_list) == 1:
            ip = self.hosts_list[0]
            print(f"{Colors.CYAN}[*] Scanning single host: {ip}{Colors.RESET}")
            result = self.scan_host(ip)
            if result['alive']:
                self.results[ip] = result
            completed = 1
        else:
            # Scan multiple hosts with threading
            with ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
                futures = {executor.submit(self.scan_host, ip): ip for ip in self.hosts_list}
                
                for future in as_completed(futures):
                    completed += 1
                    result = future.result()
                    if result['alive']:
                        self.results[result['ip']] = result
                    
                    if completed % 2 == 0 or completed == self.total_hosts:
                        progress = (completed / self.total_hosts) * 100
                        print(f"\r{Colors.YELLOW}[*] Progress: {completed}/{self.total_hosts} ({progress:.1f}%) | Live hosts: {len(self.results)}{Colors.RESET}", end='')
            
            print()
        
        self.scan_time = time.time() - start_time
        
        # Print summary
        self.print_summary()
        
        # Generate report
        self.generate_report()
        
        print(f"\n{Colors.GREEN}[✓] Scan completed in {self.scan_time:.2f} seconds{Colors.RESET}")
        print(f"{Colors.GREEN}[✓] Report saved to: {self.output_file}{Colors.RESET}")
    
    def print_summary(self):
        """Print scan summary"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.GREEN}[📊] SCAN SUMMARY{Colors.RESET}")
        print("=" * 70)
        
        live_hosts = len(self.results)
        print(f"{Colors.BOLD}Total hosts: {self.total_hosts}{Colors.RESET}")
        print(f"{Colors.BOLD}Live hosts: {live_hosts}{Colors.RESET}")
        
        if live_hosts == 0:
            print(f"\n{Colors.YELLOW}[!] No live hosts detected.{Colors.RESET}")
            return
        
        # OS distribution
        os_counts = {}
        for ip, result in self.results.items():
            os_name = result.get('os', 'Unknown')
            os_counts[os_name] = os_counts.get(os_name, 0) + 1
        
        if os_counts:
            print(f"\n{Colors.BOLD}OS Distribution:{Colors.RESET}")
            for os_name, count in sorted(os_counts.items(), key=lambda x: x[1], reverse=True):
                color = Colors.GREEN if 'Linux' in os_name or 'Unix' in os_name else Colors.BLUE if 'Windows' in os_name else Colors.YELLOW
                print(f"  {color}{os_name}{Colors.RESET}: {count}")
        
        # Port statistics
        total_ports = sum(len(r.get('ports', [])) for r in self.results.values())
        if total_ports > 0:
            print(f"\n{Colors.BOLD}Open Ports Found:{Colors.RESET} {total_ports}")
            
            port_counts = {}
            for ip, result in self.results.items():
                for port in result.get('ports', []):
                    port_num = port['port']
                    port_counts[port_num] = port_counts.get(port_num, 0) + 1
            
            print(f"  {Colors.YELLOW}Top open ports:{Colors.RESET}")
            for port, count in sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                service = self.get_service_name(port)
                print(f"    {port}/tcp ({service}): {count} host(s)")
    
    def generate_report(self):
        """Generate detailed report file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("NETWORK SCAN REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:         {self.target}\n")
            f.write(f"Scan Date:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration:  {self.scan_time:.2f} seconds\n")
            f.write(f"Total Hosts:    {self.total_hosts}\n")
            f.write(f"Live Hosts:     {len(self.results)}\n")
            f.write("=" * 80 + "\n\n")
            
            if not self.results:
                f.write("No live hosts detected.\n")
                return
            
            for ip, result in sorted(self.results.items()):
                f.write(f"\n{'=' * 60}\n")
                f.write(f"HOST: {ip}\n")
                f.write(f"{'=' * 60}\n")
                
                f.write(f"  TTL: {result.get('ttl', '?')}\n")
                f.write(f"  OS: {result.get('os', 'Unknown')} (Confidence: {result.get('os_confidence', 'LOW')})\n")
                
                ports = result.get('ports', [])
                if ports:
                    f.write(f"  Open Ports:\n")
                    for port in ports:
                        banner = f" - {port['banner']}" if port.get('banner') else ""
                        f.write(f"    {port['port']}/tcp {port['service']}{banner}\n")
                else:
                    f.write(f"  Open Ports: None\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Report generated by Advanced Network Scanner\n")
            f.write("Project #11: Network Scanning & OS Detection\n")
            f.write("=" * 80 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Network Scanner with OS Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan localhost
  python network_scanner.py 127.0.0.1
  
  # Scan a remote host
  python network_scanner.py scanme.nmap.org
  
  # Scan with specific ports
  python network_scanner.py scanme.nmap.org -p 22,80,443
        """
    )
    
    parser.add_argument('target', help='Target (IP, hostname, or CIDR range)')
    parser.add_argument('-p', '--ports', help='Comma-separated ports to scan')
    parser.add_argument('-t', '--timeout', type=float, default=2, help='Connection timeout in seconds (default: 2)')
    parser.add_argument('--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-o', '--output', default='network_scan_report.txt', help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    
    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    ADVANCED NETWORK SCANNER")
    print("    Project #11: Network Scanning & OS Detection")
    print("=" * 70 + f"{Colors.RESET}\n")
    
    scanner = NetworkScanner(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        output_file=args.output,
        verbose=args.verbose
    )
    
    scanner.scan()

if __name__ == "__main__":
    main()