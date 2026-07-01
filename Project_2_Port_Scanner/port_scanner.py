#!/usr/bin/env python3
"""
Advanced Port Scanner with Service Detection
Project #2: Active Reconnaissance & Port Scanning
"""

import socket
import sys
import threading
import time
import argparse
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Color codes for terminal output - Windows compatible
class Colors:
    try:
        # Try to use ANSI colors (Linux/Mac/Windows 10+)
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
        BOLD = '\033[1m'
    except:
        # Fallback for older Windows
        GREEN = ''
        RED = ''
        YELLOW = ''
        BLUE = ''
        CYAN = ''
        WHITE = ''
        RESET = ''
        BOLD = ''

class PortScanner:
    def __init__(self, target, ports=None, timeout=2, max_threads=50, verbose=False, output_file="scan_results.txt"):
        """
        Initialize the port scanner
        
        Args:
            target: IP address or domain name to scan
            ports: List of ports to scan (default: top 20)
            timeout: Connection timeout in seconds
            max_threads: Maximum number of concurrent threads
            verbose: Enable verbose output
            output_file: File to save results
        """
        self.target = target
        self.ports = ports or self.get_default_ports()
        self.timeout = timeout
        self.max_threads = max_threads
        self.verbose = verbose
        self.output_file = output_file
        self.open_ports = []
        self.results = []
        self.lock = threading.Lock()
        
        # Resolve target to IP
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"{Colors.RED}[!] Error: Could not resolve hostname: {target}{Colors.RESET}")
            sys.exit(1)
    
    def get_default_ports(self):
        """Return the default port list (top 20 common ports)"""
        return [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            111,   # RPC
            135,   # MSRPC
            139,   # NetBIOS
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            993,   # IMAPS
            995,   # POP3S
            1723,  # PPTP
            3306,  # MySQL
            3389,  # RDP
            5900,  # VNC
            8080   # HTTP-Alt
        ]
    
    def get_service_name(self, port):
        """Get common service name for a port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
            135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
            995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL',
            3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def clean_banner(self, banner):
        """Clean banner text to remove non-printable characters"""
        if not banner:
            return 'No banner available'
        # Remove non-printable characters
        printable = ''.join(chr(c) for c in range(32, 127))
        printable += '\n\r\t'
        cleaned = ''.join(c for c in banner if c in printable or c.isprintable())
        # Remove excessive whitespace
        cleaned = ' '.join(cleaned.split())
        # Limit length
        if len(cleaned) > 100:
            cleaned = cleaned[:100] + '...'
        return cleaned
    
    def grab_banner(self, sock, port, timeout=2):
        """
        Attempt to grab banner from open port
        
        Args:
            sock: Connected socket
            port: Port number
            timeout: Time to wait for banner
        
        Returns:
            Banner string or None
        """
        try:
            sock.settimeout(timeout)
            
            # Send different probes based on port
            probes = {
                21: b'QUIT\r\n',           # FTP
                22: b'SSH-2.0-Client\r\n',  # SSH
                25: b'EHLO test\r\n',       # SMTP
                80: b'HEAD / HTTP/1.0\r\n\r\n',  # HTTP
                110: b'QUIT\r\n',           # POP3
                143: b'A001 LOGOUT\r\n',    # IMAP
                443: b'HEAD / HTTP/1.0\r\n\r\n',  # HTTPS
                3306: b'\x00\x00\x00\x01\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # MySQL
                3389: b'\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00',  # RDP
            }
            
            # Send probe if available for this port
            if port in probes:
                sock.send(probes[port])
                time.sleep(0.5)
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return self.clean_banner(banner)
            
        except socket.timeout:
            return 'Banner timeout'
        except ConnectionResetError:
            return 'Connection reset'
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Banner grab error on port {port}: {e}{Colors.RESET}")
            return None
    
    def scan_port(self, port):
        """
        Scan a single port
        
        Args:
            port: Port number to scan
        """
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            start_time = time.time()
            result = sock.connect_ex((self.target_ip, port))
            connect_time = time.time() - start_time
            
            if result == 0:
                # Port is open
                service = self.get_service_name(port)
                banner = self.grab_banner(sock, port)
                
                with self.lock:
                    self.open_ports.append(port)
                    self.results.append({
                        'port': port,
                        'service': service,
                        'banner': banner if banner else 'No banner',
                        'response_time': f"{connect_time:.3f}s"
                    })
                    
                    # Print result immediately
                    status = f"{Colors.GREEN}OPEN{Colors.RESET}"
                    banner_text = f" [{Colors.CYAN}{banner if banner else 'No banner'}{Colors.RESET}]" if banner else ""
                    print(f"  {Colors.BOLD}{Colors.WHITE}{port:>5}/tcp{Colors.RESET}  {status}  {Colors.YELLOW}{service:>10}{Colors.RESET}  {banner_text}")
            
            elif self.verbose and result not in [111, 10061]:  # Ignore connection refused
                print(f"  {port:>5}/tcp  {Colors.RED}CLOSED{Colors.RESET}  (Error: {result})")
            
            sock.close()
            
        except socket.error as e:
            if self.verbose:
                print(f"  {port:>5}/tcp  {Colors.RED}ERROR{Colors.RESET}  {str(e)[:30]}")
        except Exception as e:
            if self.verbose:
                print(f"  {port:>5}/tcp  {Colors.RED}ERROR{Colors.RESET}  {str(e)[:30]}")
    
    def scan_ports(self):
        """Scan all ports using threading"""
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Scanning {len(self.ports)} ports on {self.target} ({self.target_ip}){Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Timeout: {self.timeout}s, Max threads: {self.max_threads}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"\n{Colors.BOLD}{'PORT':>5}  {'STATE':<6}  {'SERVICE':<12}  {'VERSION/BANNER'}{Colors.RESET}")
        print("-" * 70)
        
        start_time = time.time()
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all tasks
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            
            # Wait for completion with progress
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if self.verbose or completed == len(self.ports):
                    progress = (completed / len(self.ports)) * 100
                    print(f"\r{Colors.YELLOW}[*] Progress: {completed}/{len(self.ports)} ports ({progress:.1f}%){Colors.RESET}", end='')
        
        print()  # New line after progress
        self.scan_time = time.time() - start_time
    
    def generate_report(self):
        """Generate a detailed report file"""
        filename = self.output_file
        with open(filename, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("PORT SCAN RESULTS - Project #2\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:         {self.target}\n")
            f.write(f"IP Address:     {self.target_ip}\n")
            f.write(f"Scan Started:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration:  {self.scan_time:.2f} seconds\n")
            f.write(f"Total Ports:    {len(self.ports)}\n")
            f.write(f"Open Ports:     {len(self.open_ports)}\n")
            f.write("=" * 80 + "\n\n")
            
            # Results table
            if self.results:
                f.write("PORT     STATE    SERVICE      VERSION/BANNER\n")
                f.write("-" * 70 + "\n")
                for result in self.results:
                    f.write(f"{result['port']:>5}/tcp  OPEN     {result['service']:<12} {result['banner']}\n")
            else:
                f.write("No open ports found.\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Scan completed successfully\n")
            f.write(f"Results saved at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        print(f"\n{Colors.GREEN}[✓] Results saved to: {filename}{Colors.RESET}")
    
    def print_summary(self):
        """Print a summary of the scan results"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.GREEN}[✓] SCAN COMPLETE{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[✓] Target: {self.target} ({self.target_ip}){Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[✓] Duration: {self.scan_time:.2f} seconds{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[✓] Open ports found: {len(self.open_ports)}{Colors.RESET}")
        print("=" * 70 + "\n")
        
        if self.open_ports:
            print(f"{Colors.BOLD}Open Ports Summary:{Colors.RESET}")
            for port in sorted(self.open_ports):
                service = self.get_service_name(port)
                print(f"  {Colors.GREEN}• Port {port}{Colors.RESET} ({Colors.YELLOW}{service}{Colors.RESET})")
        else:
            print(f"{Colors.YELLOW}[!] No open ports found. Target may be down or firewall is blocking connections.{Colors.RESET}")
    
    def run(self):
        """Main execution method"""
        try:
            self.scan_ports()
            self.print_summary()
            self.generate_report()
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.RESET}")
            sys.exit(0)
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner with Service Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py scanme.nmap.org
  python port_scanner.py 127.0.0.1 -p 80,443,8080
  python port_scanner.py example.com -t 3 -v
  python port_scanner.py 192.168.1.1 -p 22,80,443 -o custom_results.txt
        """
    )
    
    parser.add_argument('target', help='Target IP address or domain name')
    parser.add_argument('-p', '--ports', help='Ports to scan (comma-separated, e.g., 80,443,8080)')
    parser.add_argument('-t', '--timeout', type=float, default=2.0, help='Connection timeout in seconds (default: 2)')
    parser.add_argument('-th', '--threads', type=int, default=50, help='Maximum number of threads (default: 50)')
    parser.add_argument('-o', '--output', default='scan_results.txt', help='Output file name (default: scan_results.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--top100', action='store_true', help='Scan top 100 ports instead of default 20')
    
    args = parser.parse_args()
    
    # Parse ports
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print(f"{Colors.RED}[!] Error: Invalid port format. Use comma-separated numbers (e.g., 80,443,8080){Colors.RESET}")
            sys.exit(1)
    elif args.top100:
        ports = list(range(1, 101))  # Top 100 ports
    else:
        ports = None  # Will use default top 20
    
    # Display banner
    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    ADVANCED PORT SCANNER - Project #2")
    print("    Active Reconnaissance & Service Detection")
    print("=" * 70 + f"{Colors.RESET}\n")
    
    # Create and run scanner
    scanner = PortScanner(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        max_threads=args.threads,
        verbose=args.verbose,
        output_file=args.output
    )
    
    scanner.run()

if __name__ == "__main__":
    main()