#!/usr/bin/env python3
"""
SSH Server Security Auditor
Project #10: SSH Security Audit Tool
"""

import socket
import sys
import time
import re
import argparse
from datetime import datetime
import paramiko
import threading

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

class SSHAuditor:
    def __init__(self, host, port=22, timeout=10, output_file="ssh_audit_report.txt", verbose=False):
        """
        Initialize the SSH Auditor
        
        Args:
            host: Target hostname or IP
            port: SSH port (default: 22)
            timeout: Connection timeout in seconds
            output_file: Output file name
            verbose: Enable verbose output
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        
        self.results = {
            'host': host,
            'port': port,
            'version': None,
            'protocol': None,
            'os': None,
            'ciphers': {'supported': [], 'weak': []},
            'macs': {'supported': [], 'weak': []},
            'kex': {'supported': [], 'weak': []},
            'auth_methods': [],
            'security_issues': [],
            'recommendations': [],
            'score': 0,
            'grade': 'F'
        }
        
        # Weak configurations database
        self.weak_ciphers = [
            'aes128-cbc', 'aes192-cbc', 'aes256-cbc',
            '3des-cbc', 'des-cbc', 'des-cfb', 'des-ede3-cbc',
            'arcfour', 'arcfour128', 'arcfour256',
            'blowfish-cbc', 'cast128-cbc',
            'rijndael-cbc', 'aes256-ctr'  # Some consider CTR weak
        ]
        
        self.weak_macs = [
            'hmac-md5', 'hmac-md5-96', 'hmac-ripemd160',
            'hmac-ripemd160@openssh.com', 'hmac-sha1',
            'hmac-sha1-96', 'umac-64@openssh.com',
            'hmac-md5-etm@openssh.com'
        ]
        
        self.weak_kex = [
            'diffie-hellman-group1-sha1',
            'diffie-hellman-group14-sha1',
            'diffie-hellman-group-exchange-sha1',
            'diffie-hellman-group-exchange-sha1@openssh.com',
            'rsa1024-sha1', 'rsa2048-sha256'
        ]
        
        self.strong_ciphers = [
            'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
            'chacha20-poly1305@openssh.com', 'aes256-ctr', 'aes128-ctr'
        ]
        
        self.strong_macs = [
            'hmac-sha2-256', 'hmac-sha2-512',
            'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'
        ]
        
        self.strong_kex = [
            'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256',
            'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
            'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512'
        ]
    
    def test_connection(self):
        """Test if SSH server is reachable"""
        print(f"{Colors.BOLD}[*] Testing connection to {self.host}:{self.port}...{Colors.RESET}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            
            if result == 0:
                print(f"{Colors.GREEN}[✓] SSH server is reachable!{Colors.RESET}")
                return True
            else:
                print(f"{Colors.RED}[!] Cannot reach SSH server on {self.host}:{self.port}{Colors.RESET}")
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {str(e)[:50]}{Colors.RESET}")
            return False
    
    def get_banner(self):
        """Get SSH server banner"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Grabbing SSH banner...{Colors.RESET}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                print(f"{Colors.GREEN}[✓] Banner received!{Colors.RESET}")
                print(f"  {Colors.CYAN}{banner}{Colors.RESET}")
                
                # Parse banner for version info
                self.parse_banner(banner)
                return banner
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error getting banner: {str(e)[:50]}{Colors.RESET}")
        
        return None
    
    def parse_banner(self, banner):
        """Parse SSH banner for version and OS info"""
        self.results['version'] = banner
        
        # Extract SSH version
        version_match = re.search(r'SSH-([0-9.]+)-([^\s]+)', banner)
        if version_match:
            self.results['protocol'] = version_match.group(1)
            self.results['version'] = version_match.group(2)
            print(f"  {Colors.YELLOW}Protocol:{Colors.RESET} {self.results['protocol']}")
            print(f"  {Colors.YELLOW}Version:{Colors.RESET} {self.results['version']}")
        
        # Detect OS from version
        if 'OpenSSH' in banner:
            if '4.3' in banner:
                self.results['os'] = 'RHEL/CentOS 4/5'
            elif '5.3' in banner or '5.4' in banner:
                self.results['os'] = 'RHEL/CentOS 6'
            elif '6.6' in banner:
                self.results['os'] = 'RHEL/CentOS 7'
            elif '7.2' in banner or '7.4' in banner:
                self.results['os'] = 'Ubuntu 16.04'
            elif '7.9' in banner or '8.0' in banner:
                self.results['os'] = 'Ubuntu 18.04/20.04'
            elif '8.2' in banner or '8.4' in banner:
                self.results['os'] = 'Ubuntu 20.04/22.04'
            elif '9.0' in banner:
                self.results['os'] = 'Ubuntu 22.04+'
            else:
                self.results['os'] = 'Linux (unknown distro)'
            
            if self.results['os']:
                print(f"  {Colors.YELLOW}OS:{Colors.RESET} {self.results['os']}")
        
        # Check for protocol version vulnerabilities
        if self.results['protocol'] == '1':
            self.results['security_issues'].append({
                'issue': 'SSH Protocol version 1',
                'description': 'Protocol version 1 is insecure and should be disabled',
                'risk': 'CRITICAL',
                'recommendation': 'Disable SSH Protocol 1 in sshd_config'
            })
            print(f"  {Colors.RED}⚠️ SSH Protocol version 1 detected (CRITICAL risk){Colors.RESET}")
        elif self.results['protocol'] == '2':
            print(f"  {Colors.GREEN}✓ SSH Protocol version 2 (Good){Colors.RESET}")
    
    def get_supported_algorithms(self):
        """Get supported ciphers, MACs, and KEX algorithms using paramiko"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Scanning supported algorithms...{Colors.RESET}")
        
        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect with transport to get algorithms
            transport = paramiko.Transport((self.host, self.port))
            transport.connect()
            
            # Get supported algorithms
            algorithms = transport.get_security_options()
            
            # Check ciphers
            self.check_ciphers(algorithms.ciphers)
            
            # Check MACs
            self.check_macs(algorithms.macs)
            
            # Check KEX
            self.check_kex(algorithms.kex)
            
            # Get authentication methods
            self.get_auth_methods(transport)
            
            transport.close()
            client.close()
            
        except paramiko.SSHException as e:
            print(f"{Colors.RED}[!] SSH Error: {str(e)[:50]}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error scanning algorithms: {str(e)[:50]}{Colors.RESET}")
    
    def check_ciphers(self, ciphers):
        """Check ciphers for weak configurations"""
        print(f"\n  {Colors.BOLD}{Colors.YELLOW}Ciphers:{Colors.RESET}")
        supported = []
        weak = []
        
        for cipher in ciphers:
            supported.append(cipher)
            if cipher in self.weak_ciphers:
                weak.append(cipher)
                print(f"    {Colors.RED}✗ {cipher} (WEAK){Colors.RESET}")
            elif cipher in self.strong_ciphers:
                print(f"    {Colors.GREEN}✓ {cipher} (Strong){Colors.RESET}")
            else:
                print(f"    {Colors.CYAN}? {cipher} (Unknown){Colors.RESET}")
        
        self.results['ciphers']['supported'] = supported
        self.results['ciphers']['weak'] = weak
        
        if weak:
            self.results['security_issues'].append({
                'issue': 'Weak ciphers supported',
                'description': f'Weak ciphers found: {", ".join(weak)}',
                'risk': 'HIGH',
                'recommendation': 'Remove weak ciphers, use only strong ciphers like aes256-gcm@openssh.com, chacha20-poly1305@openssh.com'
            })
    
    def check_macs(self, macs):
        """Check MAC algorithms for weak configurations"""
        print(f"\n  {Colors.BOLD}{Colors.YELLOW}MAC Algorithms:{Colors.RESET}")
        supported = []
        weak = []
        
        for mac in macs:
            supported.append(mac)
            if mac in self.weak_macs:
                weak.append(mac)
                print(f"    {Colors.RED}✗ {mac} (WEAK){Colors.RESET}")
            elif mac in self.strong_macs:
                print(f"    {Colors.GREEN}✓ {mac} (Strong){Colors.RESET}")
            else:
                print(f"    {Colors.CYAN}? {mac} (Unknown){Colors.RESET}")
        
        self.results['macs']['supported'] = supported
        self.results['macs']['weak'] = weak
        
        if weak:
            self.results['security_issues'].append({
                'issue': 'Weak MAC algorithms supported',
                'description': f'Weak MACs found: {", ".join(weak)}',
                'risk': 'MEDIUM',
                'recommendation': 'Remove weak MACs, use only strong algorithms like hmac-sha2-256, hmac-sha2-512'
            })
    
    def check_kex(self, kex_algorithms):
        """Check KEX algorithms for weak configurations"""
        print(f"\n  {Colors.BOLD}{Colors.YELLOW}Key Exchange Algorithms:{Colors.RESET}")
        supported = []
        weak = []
        
        for kex in kex_algorithms:
            supported.append(kex)
            if kex in self.weak_kex:
                weak.append(kex)
                print(f"    {Colors.RED}✗ {kex} (WEAK){Colors.RESET}")
            elif kex in self.strong_kex:
                print(f"    {Colors.GREEN}✓ {kex} (Strong){Colors.RESET}")
            else:
                print(f"    {Colors.CYAN}? {kex} (Unknown){Colors.RESET}")
        
        self.results['kex']['supported'] = supported
        self.results['kex']['weak'] = weak
        
        if weak:
            self.results['security_issues'].append({
                'issue': 'Weak KEX algorithms supported',
                'description': f'Weak KEX found: {", ".join(weak)}',
                'risk': 'HIGH',
                'recommendation': 'Remove weak KEX, use only strong algorithms like curve25519-sha256, ecdh-sha2-nistp256'
            })
    
    def get_auth_methods(self, transport):
        """Get supported authentication methods"""
        print(f"\n  {Colors.BOLD}{Colors.YELLOW}Authentication Methods:{Colors.RESET}")
        
        try:
            # Try to get auth methods
            auth_methods = transport.auth_none('test')
            
            if auth_methods:
                self.results['auth_methods'] = auth_methods
                
                for method in auth_methods:
                    if method == 'password':
                        print(f"    {Colors.RED}✗ password (HIGH RISK){Colors.RESET}")
                        self.results['security_issues'].append({
                            'issue': 'Password authentication allowed',
                            'description': 'Password authentication is enabled',
                            'risk': 'HIGH',
                            'recommendation': 'Disable password authentication, use SSH keys only'
                        })
                    elif method == 'publickey':
                        print(f"    {Colors.GREEN}✓ publickey (Good){Colors.RESET}")
                    elif method == 'keyboard-interactive':
                        print(f"    {Colors.YELLOW}? keyboard-interactive (Medium Risk){Colors.RESET}")
                    else:
                        print(f"    {Colors.CYAN}? {method}{Colors.RESET}")
            else:
                print(f"    {Colors.YELLOW}Could not determine auth methods{Colors.RESET}")
                
        except Exception as e:
            if self.verbose:
                print(f"    {Colors.YELLOW}Error getting auth methods: {str(e)[:30]}{Colors.RESET}")
    
    def check_root_login(self):
        """Check if root login is allowed by attempting login"""
        print(f"\n  {Colors.BOLD}{Colors.YELLOW}Root Login Check:{Colors.RESET}")
        
        try:
            # Attempt to check root login by trying to start authentication
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try to connect with root user (will fail but may reveal if root login is allowed)
            transport = paramiko.Transport((self.host, self.port))
            transport.connect()
            
            # Try root login (with empty password, will fail but may indicate allowed)
            try:
                transport.auth_password('root', 'invalid')
            except paramiko.AuthenticationException:
                # This is expected, but some servers might reject before auth
                pass
            except paramiko.SSHException:
                pass
            
            # Check if root is allowed by trying to start auth
            try:
                # Some servers reveal if root login is allowed
                transport.auth_none('root')
                print(f"    {Colors.RED}✗ Root login may be allowed (CRITICAL RISK){Colors.RESET}")
                self.results['security_issues'].append({
                    'issue': 'Root login allowed',
                    'description': 'Root user may be allowed to login via SSH',
                    'risk': 'CRITICAL',
                    'recommendation': 'Disable root login by setting PermitRootLogin no in sshd_config'
                })
            except:
                print(f"    {Colors.GREEN}✓ Root login likely disabled{Colors.RESET}")
            
            transport.close()
            
        except Exception as e:
            if self.verbose:
                print(f"    {Colors.YELLOW}Could not check root login: {str(e)[:30]}{Colors.RESET}")
    
    def calculate_score(self):
        """Calculate security score (0-100)"""
        score = 100
        deductions = 0
        
        # Deduct for weak ciphers
        weak_cipher_count = len(self.results['ciphers']['weak'])
        if weak_cipher_count > 0:
            deductions += min(weak_cipher_count * 8, 30)
        
        # Deduct for weak MACs
        weak_mac_count = len(self.results['macs']['weak'])
        if weak_mac_count > 0:
            deductions += min(weak_mac_count * 6, 20)
        
        # Deduct for weak KEX
        weak_kex_count = len(self.results['kex']['weak'])
        if weak_kex_count > 0:
            deductions += min(weak_kex_count * 8, 25)
        
        # Deduct for auth issues
        if 'password' in self.results['auth_methods']:
            deductions += 15
        
        # Deduct for root login issues
        root_login_issue = any(i['issue'] == 'Root login allowed' for i in self.results['security_issues'])
        if root_login_issue:
            deductions += 20
        
        # Deduct for protocol version 1
        if self.results['protocol'] == '1':
            deductions += 30
        
        # Calculate final score
        score = max(0, 100 - deductions)
        self.results['score'] = score
        
        # Determine grade
        if score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 70:
            grade = 'C'
        elif score >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        self.results['grade'] = grade
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] Security Score:{Colors.RESET}")
        score_color = Colors.GREEN if grade in ['A', 'B'] else Colors.YELLOW if grade in ['C', 'D'] else Colors.RED
        print(f"  {score_color}{score}/100 ({grade}){Colors.RESET}")
        
        return score, grade
    
    def generate_recommendations(self):
        """Generate security recommendations"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📋] Recommendations:{Colors.RESET}")
        
        recommendations = []
        
        # Version recommendations
        if self.results['version'] and 'OpenSSH' in self.results['version']:
            version_num = re.search(r'(\d+\.\d+)', self.results['version'])
            if version_num:
                major = float(version_num.group(1))
                if major < 7.9:
                    recommendations.append(f"Upgrade OpenSSH from {self.results['version']} to 7.9+ or 9.0+")
        
        # Cipher recommendations
        if self.results['ciphers']['weak']:
            recommendations.append("Remove weak ciphers (CBC, 3DES, RC4)")
            recommendations.append("Use only strong ciphers: aes256-gcm@openssh.com, chacha20-poly1305@openssh.com")
        
        # MAC recommendations
        if self.results['macs']['weak']:
            recommendations.append("Remove weak MAC algorithms (MD5, SHA1)")
            recommendations.append("Use only strong MACs: hmac-sha2-256, hmac-sha2-512")
        
        # KEX recommendations
        if self.results['kex']['weak']:
            recommendations.append("Remove weak KEX algorithms (diffie-hellman-group1-sha1)")
            recommendations.append("Use only strong KEX: curve25519-sha256, ecdh-sha2-nistp256")
        
        # Auth recommendations
        if 'password' in self.results['auth_methods']:
            recommendations.append("Disable password authentication, use SSH keys only")
            recommendations.append("Set 'PasswordAuthentication no' in sshd_config")
        
        # Root login recommendations
        root_login_issue = any(i['issue'] == 'Root login allowed' for i in self.results['security_issues'])
        if root_login_issue:
            recommendations.append("Disable root login (PermitRootLogin no)")
            recommendations.append("Use sudo for administrative tasks")
        
        # Protocol recommendations
        if self.results['protocol'] == '1':
            recommendations.append("Disable SSH Protocol 1 (Protocol 2 only)")
        
        # General recommendations
        recommendations.append("Enable SSH key-based authentication for all users")
        recommendations.append("Use strong key types: ed25519 or RSA 4096+")
        recommendations.append("Implement fail2ban to prevent brute force attacks")
        recommendations.append("Monitor SSH logs for suspicious activity")
        
        # Remove duplicates
        self.results['recommendations'] = list(set(recommendations))
        
        # Print recommendations
        for i, rec in enumerate(self.results['recommendations'][:10], 1):
            print(f"  {Colors.CYAN}{i}.{Colors.RESET} {rec}")
        
        return self.results['recommendations']
    
    def generate_report(self):
        """Generate detailed report file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SSH SERVER SECURITY AUDIT REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:         {self.host}:{self.port}\n")
            f.write(f"Audit Date:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Server Information
            f.write("SSH SERVER INFORMATION\n")
            f.write("-" * 50 + "\n")
            f.write(f"Version: {self.results['version'] or 'Unknown'}\n")
            f.write(f"Protocol: {self.results['protocol'] or 'Unknown'}\n")
            f.write(f"OS: {self.results['os'] or 'Unknown'}\n\n")
            
            # Ciphers
            f.write("CIPHERS\n")
            f.write("-" * 50 + "\n")
            f.write("Supported ciphers:\n")
            for cipher in self.results['ciphers']['supported']:
                status = "✗ WEAK" if cipher in self.weak_ciphers else "✓ Strong"
                f.write(f"  {cipher}: {status}\n")
            f.write("\n")
            
            # MACs
            f.write("MAC ALGORITHMS\n")
            f.write("-" * 50 + "\n")
            for mac in self.results['macs']['supported']:
                status = "✗ WEAK" if mac in self.weak_macs else "✓ Strong"
                f.write(f"  {mac}: {status}\n")
            f.write("\n")
            
            # KEX
            f.write("KEY EXCHANGE ALGORITHMS\n")
            f.write("-" * 50 + "\n")
            for kex in self.results['kex']['supported']:
                status = "✗ WEAK" if kex in self.weak_kex else "✓ Strong"
                f.write(f"  {kex}: {status}\n")
            f.write("\n")
            
            # Authentication
            f.write("AUTHENTICATION METHODS\n")
            f.write("-" * 50 + "\n")
            for method in self.results['auth_methods']:
                status = "✗ RISK" if method == 'password' else "✓ Good"
                f.write(f"  {method}: {status}\n")
            f.write("\n")
            
            # Security Issues
            f.write("SECURITY ISSUES\n")
            f.write("-" * 50 + "\n")
            if self.results['security_issues']:
                for issue in self.results['security_issues']:
                    f.write(f"  {issue['risk']}: {issue['issue']}\n")
                    f.write(f"    Description: {issue['description']}\n")
                    f.write(f"    Recommendation: {issue['recommendation']}\n")
                    f.write("  " + "-" * 30 + "\n")
            else:
                f.write("  No security issues detected\n")
            f.write("\n")
            
            # Score and Grade
            f.write("SECURITY SCORE\n")
            f.write("-" * 50 + "\n")
            f.write(f"Score: {self.results['score']}/100\n")
            f.write(f"Grade: {self.results['grade']}\n\n")
            
            # Recommendations
            f.write("RECOMMENDATIONS\n")
            f.write("-" * 50 + "\n")
            for i, rec in enumerate(self.results['recommendations'], 1):
                f.write(f"  {i}. {rec}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Report generated by SSH Server Security Auditor\n")
            f.write("Project #10: SSH Security Audit Tool\n")
            f.write("=" * 80 + "\n")
        
        print(f"\n{Colors.GREEN}[✓] Report saved to: {self.output_file}{Colors.RESET}")
    
    def audit(self):
        """Main audit method"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] SSH Server Security Auditor{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Target: {self.host}:{self.port}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print("")
        
        start_time = time.time()
        
        # Test connection
        if not self.test_connection():
            print(f"{Colors.RED}[!] Cannot proceed with audit - target unreachable{Colors.RESET}")
            return
        
        # Perform audit
        self.get_banner()
        self.get_supported_algorithms()
        self.check_root_login()
        
        # Calculate score and generate recommendations
        self.calculate_score()
        self.generate_recommendations()
        
        # Generate report
        self.generate_report()
        
        self.audit_time = time.time() - start_time
        print(f"\n{Colors.GREEN}[✓] Audit completed in {self.audit_time:.2f} seconds{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="SSH Server Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit a remote SSH server
  python ssh_auditor.py scanme.nmap.org
  
  # Audit with custom port
  python ssh_auditor.py localhost -p 2222
  
  # Audit with verbose output
  python ssh_auditor.py scanme.nmap.org -v
  
  # Custom output file
  python ssh_auditor.py scanme.nmap.org -o my_report.txt
        """
    )
    
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', default='ssh_audit_report.txt', help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Display banner
    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    SSH SERVER SECURITY AUDITOR")
    print("    Project #10: SSH Security Audit Tool")
    print("=" * 70 + f"{Colors.RESET}\n")
    
    # Create and run auditor
    auditor = SSHAuditor(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        output_file=args.output,
        verbose=args.verbose
    )
    
    auditor.audit()

if __name__ == "__main__":
    main()