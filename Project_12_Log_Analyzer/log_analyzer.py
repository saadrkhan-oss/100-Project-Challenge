#!/usr/bin/env python3
"""
Security Log Analyzer
Project #12: Log Analysis & Security Monitoring Tool
"""

import re
import sys
import argparse
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import ipaddress
import json

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

class LogAnalyzer:
    def __init__(self, log_file, output_file="log_analysis_report.txt", verbose=False):
        """
        Initialize the Log Analyzer
        
        Args:
            log_file: Path to log file
            output_file: Output file name
            verbose: Enable verbose output
        """
        self.log_file = log_file
        self.output_file = output_file
        self.verbose = verbose
        
        # Attack patterns
        self.attack_patterns = {
            'sql_injection': {
                'patterns': [
                    r'SELECT.*FROM',
                    r'UNION.*SELECT',
                    r'DROP.*TABLE',
                    r'INSERT.*INTO',
                    r'UPDATE.*SET',
                    r'DELETE.*FROM',
                    r'OR 1=1',
                    r'AND 1=1',
                    r'--',
                    r'#',
                    r'/\*.*\*/',
                    r'\' OR \'1\'=\'1',
                    r'\" OR \"1\"=\"1',
                ],
                'severity': 'HIGH',
                'description': 'SQL Injection attempts'
            },
            'xss': {
                'patterns': [
                    r'<script',
                    r'</script>',
                    r'onerror=',
                    r'onload=',
                    r'onclick=',
                    r'onmouseover=',
                    r'onfocus=',
                    r'alert\(',
                    r'prompt\(',
                    r'confirm\(',
                    r'<img.*onerror',
                    r'<svg.*onload',
                    r'javascript:',
                    r'%3Cscript%3E',
                    r'&lt;script&gt;',
                ],
                'severity': 'HIGH',
                'description': 'Cross-Site Scripting attempts'
            },
            'bruteforce': {
                'patterns': [
                    r'POST /wp-login.php',
                    r'POST /login',
                    r'POST /admin/login',
                    r'POST /wp-admin/admin-ajax.php',
                    r'Failed password',
                    r'authentication failure',
                    r'Invalid username',
                    r'Bad password',
                    r'401',
                ],
                'severity': 'MEDIUM',
                'description': 'Brute force attempts'
            },
            'directory_traversal': {
                'patterns': [
                    r'\.\./',
                    r'\.\.\\',
                    r'/etc/passwd',
                    r'/etc/shadow',
                    r'/etc/hosts',
                    r'/proc/self/environ',
                    r'/windows/win.ini',
                    r'/boot.ini',
                    r'%2e%2e%2f',
                    r'..%2f',
                ],
                'severity': 'HIGH',
                'description': 'Directory traversal attempts'
            },
            'file_inclusion': {
                'patterns': [
                    r'file://',
                    r'php://',
                    r'zip://',
                    r'data://',
                    r'phar://',
                    r'http://.*evil',
                    r'https://.*evil',
                ],
                'severity': 'MEDIUM',
                'description': 'File inclusion attempts'
            },
            'command_injection': {
                'patterns': [
                    r';.*ls',
                    r';.*cat',
                    r';.*wget',
                    r'\|.*whoami',
                    r'\|.*id',
                    r'`.*`',
                    r'\$\(.*\)',
                    r'&&.*ls',
                    r'&&.*wget',
                    r'||.*whoami',
                ],
                'severity': 'HIGH',
                'description': 'Command injection attempts'
            },
            'path_traversal': {
                'patterns': [
                    r'\.\./\.\./',
                    r'\.\.\\\.\.\\',
                    r'%2e%2e%2f%2e%2e%2f',
                    r'..%252f..%252f',
                ],
                'severity': 'MEDIUM',
                'description': 'Path traversal attempts'
            }
        }
        
        # Results storage
        self.log_entries = []
        self.attack_entries = defaultdict(list)
        self.ip_requests = defaultdict(int)
        self.status_codes = defaultdict(int)
        self.request_methods = defaultdict(int)
        self.hourly_requests = defaultdict(int)
        self.user_agents = defaultdict(int)
        self.url_requests = defaultdict(int)
        self.failed_logins = defaultdict(int)
        self.successful_logins = defaultdict(int)
        
        # Alert thresholds
        self.bruteforce_threshold = 10  # Failed attempts per IP
        self.sqli_threshold = 5  # SQLi attempts per IP
        self.xss_threshold = 5  # XSS attempts per IP
        
        self.alerts = []
        self.attackers = defaultdict(lambda: defaultdict(int))
        self.unique_ips = set()
        self.total_lines = 0
        self.parsed_lines = 0
        
        # Parse log
        self.parse_log()
    
    def parse_apache_log(self, line):
        """
        Parse Apache combined log format:
        127.0.0.1 - - [08/Sep/2026:21:15:45 +0000] "GET /index.html HTTP/1.1" 200 435 "-" "Mozilla/5.0"
        """
        # Apache combined log pattern
        pattern = r'^(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
        
        match = re.search(pattern, line)
        if match:
            ip, _, _, timestamp, method, url, protocol, status, size, referer, user_agent = match.groups()
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'url': url,
                'protocol': protocol,
                'status': int(status),
                'size': int(size),
                'referer': referer,
                'user_agent': user_agent
            }
        
        # Try simpler format
        pattern = r'^(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
        match = re.search(pattern, line)
        if match:
            ip, _, _, timestamp, method, url, protocol, status, size = match.groups()
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'url': url,
                'protocol': protocol,
                'status': int(status),
                'size': int(size),
                'referer': '',
                'user_agent': ''
            }
        
        return None
    
    def parse_nginx_log(self, line):
        """
        Parse Nginx log format:
        127.0.0.1 - - [08/Sep/2026:21:15:45 +0000] "GET /index.html HTTP/1.1" 200 435 "-" "Mozilla/5.0"
        """
        # Nginx default log format is similar to Apache combined
        return self.parse_apache_log(line)
    
    def parse_custom_log(self, line):
        """Parse common log formats"""
        # Try common formats
        for parser in [self.parse_apache_log, self.parse_nginx_log]:
            result = parser(line)
            if result:
                return result
        return None
    
    def detect_attacks(self, entry):
        """Detect attacks in log entry"""
        if not entry:
            return None
        
        url = entry.get('url', '')
        query = url.split('?')[1] if '?' in url else ''
        full_url = url
        user_agent = entry.get('user_agent', '')
        method = entry.get('method', '')
        
        detected_attacks = []
        
        for attack_type, data in self.attack_patterns.items():
            for pattern in data['patterns']:
                # Search in URL and query string
                if re.search(pattern, full_url, re.IGNORECASE) or re.search(pattern, query, re.IGNORECASE):
                    detected_attacks.append({
                        'type': attack_type,
                        'severity': data['severity'],
                        'description': data['description'],
                        'pattern': pattern,
                        'matched_url': full_url[:100]
                    })
                    break
        
        # Special detection for brute force
        if entry.get('status') == 401 or 'Failed password' in str(entry) or '/wp-login.php' in full_url:
            detected_attacks.append({
                'type': 'bruteforce',
                'severity': 'MEDIUM',
                'description': 'Brute force attempt',
                'pattern': 'Failed login',
                'matched_url': full_url[:100]
            })
        
        return detected_attacks
    
    def parse_log(self):
        """Parse the log file"""
        print(f"{Colors.BOLD}[*] Parsing log file: {self.log_file}{Colors.RESET}")
        
        if not os.path.exists(self.log_file):
            print(f"{Colors.RED}[!] Log file not found: {self.log_file}{Colors.RESET}")
            return
        
        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading file: {e}{Colors.RESET}")
            return
        
        self.total_lines = len(lines)
        print(f"{Colors.CYAN}[*] Total lines: {self.total_lines}{Colors.RESET}")
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            entry = self.parse_custom_log(line)
            
            if entry:
                self.parsed_lines += 1
                self.log_entries.append(entry)
                
                # Update statistics
                ip = entry.get('ip', 'Unknown')
                self.ip_requests[ip] += 1
                self.unique_ips.add(ip)
                
                status = entry.get('status', 0)
                self.status_codes[status] += 1
                
                method = entry.get('method', 'Unknown')
                self.request_methods[method] += 1
                
                # Timestamp handling
                timestamp = entry.get('timestamp', '')
                if timestamp:
                    try:
                        # Parse timestamp (Apache format: 08/Sep/2026:21:15:45 +0000)
                        dt = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
                        hour = dt.hour
                        self.hourly_requests[hour] += 1
                    except:
                        pass
                
                user_agent = entry.get('user_agent', 'Unknown')
                self.user_agents[user_agent[:50]] += 1
                
                url = entry.get('url', 'Unknown')
                self.url_requests[url[:100]] += 1
                
                # Detect attacks
                attacks = self.detect_attacks(entry)
                if attacks:
                    for attack in attacks:
                        self.attack_entries[ip].append(attack)
                        self.attackers[ip][attack['type']] += 1
                    
                    # Check for brute force
                    if entry.get('status') == 401 or 'Failed password' in str(entry):
                        self.failed_logins[ip] += 1
                    elif entry.get('status') == 200 and '/login' in entry.get('url', ''):
                        self.successful_logins[ip] += 1
        
        print(f"{Colors.GREEN}[✓] Parsed {self.parsed_lines} entries{Colors.RESET}")
        self.generate_alerts()
    
    def generate_alerts(self):
        """Generate security alerts based on analysis"""
        print(f"\n{Colors.BOLD}[*] Generating alerts...{Colors.RESET}")
        
        # Check for brute force attacks
        for ip, count in self.failed_logins.items():
            if count >= self.bruteforce_threshold:
                success_count = self.successful_logins.get(ip, 0)
                alert = {
                    'severity': 'CRITICAL' if success_count > 0 else 'HIGH',
                    'type': 'Brute Force Attack',
                    'ip': ip,
                    'description': f'{count} failed login attempts from {ip}',
                    'successful': success_count > 0,
                    'success_count': success_count
                }
                self.alerts.append(alert)
                
                if success_count > 0:
                    print(f"{Colors.RED}[!] CRITICAL: Successful brute force from {ip} ({count} attempts, {success_count} successful){Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[!] HIGH: Brute force attack from {ip} ({count} attempts){Colors.RESET}")
        
        # Check for SQL injection
        for ip, attacks in self.attackers.items():
            sqli_count = attacks.get('sql_injection', 0)
            xss_count = attacks.get('xss', 0)
            
            if sqli_count >= self.sqli_threshold:
                alert = {
                    'severity': 'CRITICAL',
                    'type': 'SQL Injection Attempts',
                    'ip': ip,
                    'description': f'{sqli_count} SQL injection attempts from {ip}'
                }
                self.alerts.append(alert)
                print(f"{Colors.RED}[!] CRITICAL: SQL injection attempts from {ip} ({sqli_count}){Colors.RESET}")
            
            if xss_count >= self.xss_threshold:
                alert = {
                    'severity': 'HIGH',
                    'type': 'XSS Attempts',
                    'ip': ip,
                    'description': f'{xss_count} XSS attempts from {ip}'
                }
                self.alerts.append(alert)
                print(f"{Colors.YELLOW}[!] HIGH: XSS attempts from {ip} ({xss_count}){Colors.RESET}")
        
        # Check for directory traversal
        for ip, attacks in self.attackers.items():
            dir_count = attacks.get('directory_traversal', 0)
            if dir_count >= 3:
                alert = {
                    'severity': 'HIGH',
                    'type': 'Directory Traversal',
                    'ip': ip,
                    'description': f'{dir_count} directory traversal attempts from {ip}'
                }
                self.alerts.append(alert)
                print(f"{Colors.YELLOW}[!] HIGH: Directory traversal from {ip} ({dir_count}){Colors.RESET}")
        
        if not self.alerts:
            print(f"{Colors.GREEN}[✓] No critical alerts generated{Colors.RESET}")
    
    def generate_report(self):
        """Generate analysis report"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.GREEN}[📊] Log Analysis Report{Colors.RESET}")
        print("=" * 70)
        
        print(f"{Colors.BOLD}[📁] File:{Colors.RESET} {self.log_file}")
        print(f"{Colors.BOLD}[📅] Total lines:{Colors.RESET} {self.total_lines}")
        print(f"{Colors.BOLD}[📅] Parsed entries:{Colors.RESET} {self.parsed_lines}")
        print("")
        
        # Attack summary
        attack_summary = defaultdict(int)
        for ip, attacks in self.attackers.items():
            for attack_type, count in attacks.items():
                attack_summary[attack_type] += count
        
        if attack_summary:
            print(f"{Colors.BOLD}{Colors.RED}[⚠️] ATTACK DETECTIONS:{Colors.RESET}")
            attack_colors = {
                'sql_injection': Colors.RED,
                'xss': Colors.YELLOW,
                'bruteforce': Colors.YELLOW,
                'directory_traversal': Colors.RED,
                'file_inclusion': Colors.YELLOW,
                'command_injection': Colors.RED,
                'path_traversal': Colors.YELLOW
            }
            for attack_type, count in sorted(attack_summary.items(), key=lambda x: x[1], reverse=True):
                color = attack_colors.get(attack_type, Colors.WHITE)
                print(f"    {color}•{Colors.RESET} {attack_type.replace('_', ' ').title()}: {count}")
            print("")
        
        # Top attackers
        if self.attackers:
            print(f"{Colors.BOLD}{Colors.BLUE}[🔍] TOP ATTACKERS:{Colors.RESET}")
            attackers_list = []
            for ip, attacks in self.attackers.items():
                total = sum(attacks.values())
                main_attack = max(attacks.items(), key=lambda x: x[1])
                attackers_list.append((ip, total, main_attack[0]))
            
            for idx, (ip, total, attack_type) in enumerate(sorted(attackers_list, key=lambda x: x[1], reverse=True)[:5], 1):
                print(f"    {idx}. {ip} - {total} attempts ({attack_type.replace('_', ' ').title()})")
            print("")
        
        # Statistics
        print(f"{Colors.BOLD}{Colors.BLUE}[📊] STATISTICS:{Colors.RESET}")
        print(f"    Total Requests: {self.parsed_lines}")
        print(f"    Unique IPs: {len(self.unique_ips)}")
        print(f"    Unique User Agents: {len(self.user_agents)}")
        print("")
        
        # Status codes
        if self.status_codes:
            print(f"    {Colors.YELLOW}Status Codes:{Colors.RESET}")
            total = sum(self.status_codes.values())
            for status, count in sorted(self.status_codes.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total) * 100 if total > 0 else 0
                color = Colors.GREEN if status == 200 else Colors.YELLOW if status in [301, 302, 304] else Colors.RED
                print(f"      {color}{status}{Colors.RESET}: {count} ({percentage:.1f}%)")
            print("")
        
        # Request methods
        if self.request_methods:
            print(f"    {Colors.YELLOW}Request Methods:{Colors.RESET}")
            for method, count in sorted(self.request_methods.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"      {method}: {count}")
            print("")
        
        # Hourly traffic
        if self.hourly_requests:
            print(f"    {Colors.YELLOW}Peak Hours:{Colors.RESET}")
            peak_hours = sorted(self.hourly_requests.items(), key=lambda x: x[1], reverse=True)[:3]
            for hour, count in peak_hours:
                print(f"      {hour:02d}:00 - {count} requests")
            print("")
        
        # Top URLs
        if self.url_requests:
            print(f"    {Colors.YELLOW}Top URLs:{Colors.RESET}")
            for url, count in sorted(self.url_requests.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"      {url[:60]}: {count}")
            print("")
        
        # Alerts
        if self.alerts:
            print(f"{Colors.BOLD}{Colors.RED}[🚨] ALERTS:{Colors.RESET}")
            for alert in self.alerts:
                severity_color = Colors.RED if alert['severity'] == 'CRITICAL' else Colors.YELLOW
                print(f"    {severity_color}[{alert['severity']}]{Colors.RESET} {alert['type']}")
                print(f"      {alert['description']}")
                if alert.get('success_count', 0) > 0:
                    print(f"      ⚠️ {alert['success_count']} successful logins after brute force")
            print("")
        else:
            print(f"{Colors.BOLD}{Colors.GREEN}[🚨] ALERTS:{Colors.RESET} None detected\n")
        
        # Save report
        self.save_report()
    
    def save_report(self):
        """Save report to file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("LOG ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"File:           {self.log_file}\n")
            f.write(f"Total Lines:    {self.total_lines}\n")
            f.write(f"Parsed Entries: {self.parsed_lines}\n")
            f.write(f"Report Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Attack summary
            attack_summary = defaultdict(int)
            for ip, attacks in self.attackers.items():
                for attack_type, count in attacks.items():
                    attack_summary[attack_type] += count
            
            if attack_summary:
                f.write("ATTACK DETECTIONS\n")
                f.write("-" * 40 + "\n")
                for attack_type, count in sorted(attack_summary.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {attack_type.replace('_', ' ').title()}: {count}\n")
                f.write("\n")
            
            # Top attackers
            if self.attackers:
                f.write("TOP ATTACKERS\n")
                f.write("-" * 40 + "\n")
                attackers_list = []
                for ip, attacks in self.attackers.items():
                    total = sum(attacks.values())
                    main_attack = max(attacks.items(), key=lambda x: x[1])
                    attackers_list.append((ip, total, main_attack[0]))
                
                for idx, (ip, total, attack_type) in enumerate(sorted(attackers_list, key=lambda x: x[1], reverse=True)[:10], 1):
                    f.write(f"  {idx}. {ip} - {total} attempts ({attack_type.replace('_', ' ').title()})\n")
                f.write("\n")
            
            # Statistics
            f.write("STATISTICS\n")
            f.write("-" * 40 + "\n")
            f.write(f"  Total Requests: {self.parsed_lines}\n")
            f.write(f"  Unique IPs: {len(self.unique_ips)}\n")
            f.write("\n")
            
            # Status codes
            if self.status_codes:
                f.write("  Status Codes:\n")
                total = sum(self.status_codes.values())
                for status, count in sorted(self.status_codes.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / total) * 100 if total > 0 else 0
                    f.write(f"    {status}: {count} ({percentage:.1f}%)\n")
                f.write("\n")
            
            # Alerts
            if self.alerts:
                f.write("ALERTS\n")
                f.write("-" * 40 + "\n")
                for alert in self.alerts:
                    f.write(f"  [{alert['severity']}] {alert['type']}\n")
                    f.write(f"    {alert['description']}\n")
                    if alert.get('success_count', 0) > 0:
                        f.write(f"    ⚠️ {alert['success_count']} successful logins after brute force\n")
                f.write("\n")
            else:
                f.write("ALERTS: None detected\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("Report generated by Security Log Analyzer\n")
            f.write("Project #12: Log Analysis & Security Monitoring\n")
            f.write("=" * 80 + "\n")
        
        print(f"{Colors.GREEN}[✓] Report saved to: {self.output_file}{Colors.RESET}")

def generate_sample_logs():
    """Generate sample log file for testing"""
    sample_logs = [
        # Normal traffic
        '192.168.1.1 - - [08/Sep/2026:21:15:45 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '192.168.1.2 - - [08/Sep/2026:21:15:46 +0000] "GET /about.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        '192.168.1.3 - - [08/Sep/2026:21:15:47 +0000] "GET /contact.html HTTP/1.1" 200 256 "-" "Mozilla/5.0"',
        
        # SQL injection attempts
        '203.0.113.45 - - [08/Sep/2026:21:15:50 +0000] "GET /search.php?q=SELECT * FROM users HTTP/1.1" 200 435 "-" "Mozilla/5.0"',
        '203.0.113.45 - - [08/Sep/2026:21:15:52 +0000] "GET /search.php?q=UNION SELECT username,password FROM users HTTP/1.1" 200 435 "-" "Mozilla/5.0"',
        '203.0.113.45 - - [08/Sep/2026:21:15:54 +0000] "GET /search.php?q=DROP TABLE users-- HTTP/1.1" 200 435 "-" "Mozilla/5.0"',
        
        # XSS attempts
        '198.51.100.23 - - [08/Sep/2026:21:16:00 +0000] "GET /search.php?q=<script>alert(1)</script> HTTP/1.1" 200 435 "-" "Mozilla/5.0"',
        '198.51.100.23 - - [08/Sep/2026:21:16:01 +0000] "GET /search.php?q=<img src=x onerror=alert(1)> HTTP/1.1" 200 435 "-" "Mozilla/5.0"',
        '198.51.100.23 - - [08/Sep/2026:21:16:02 +0000] "GET /search.php?q=javascript:alert(1) HTTP/1.1" 200 435 "-" "Mozilla/5.0"',
        
        # Brute force attempts
        '192.168.1.5 - - [08/Sep/2026:21:16:10 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '192.168.1.5 - - [08/Sep/2026:21:16:11 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '192.168.1.5 - - [08/Sep/2026:21:16:12 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '192.168.1.5 - - [08/Sep/2026:21:16:13 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '192.168.1.5 - - [08/Sep/2026:21:16:14 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '192.168.1.5 - - [08/Sep/2026:21:16:15 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '192.168.1.5 - - [08/Sep/2026:21:16:16 +0000] "POST /wp-login.php HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '192.168.1.5 - - [08/Sep/2026:21:16:17 +0000] "POST /wp-login.php HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        
        # Directory traversal
        '192.168.1.10 - - [08/Sep/2026:21:17:00 +0000] "GET /download.php?file=../../../etc/passwd HTTP/1.1" 403 512 "-" "Mozilla/5.0"',
        '192.168.1.10 - - [08/Sep/2026:21:17:01 +0000] "GET /download.php?file=../../../../etc/shadow HTTP/1.1" 403 512 "-" "Mozilla/5.0"',
        '192.168.1.10 - - [08/Sep/2026:21:17:02 +0000] "GET /download.php?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1" 403 512 "-" "Mozilla/5.0"',
        
        # More normal traffic
        '192.168.1.1 - - [08/Sep/2026:21:20:00 +0000] "GET /images/logo.png HTTP/1.1" 200 2048 "http://example.com/index.html" "Mozilla/5.0"',
        '192.168.1.2 - - [08/Sep/2026:21:20:01 +0000] "GET /css/style.css HTTP/1.1" 200 1024 "http://example.com/index.html" "Mozilla/5.0"',
        '192.168.1.3 - - [08/Sep/2026:21:20:02 +0000] "GET /js/script.js HTTP/1.1" 200 512 "http://example.com/index.html" "Mozilla/5.0"',
        '192.168.1.4 - - [08/Sep/2026:21:20:03 +0000] "GET /favicon.ico HTTP/1.1" 404 256 "-" "Mozilla/5.0"',
        '192.168.1.5 - - [08/Sep/2026:21:20:04 +0000] "GET /admin HTTP/1.1" 404 256 "-" "Mozilla/5.0"',
    ]
    
    # Write sample logs
    with open('sample_access.log', 'w') as f:
        for log in sample_logs:
            f.write(log + '\n')
    
    print(f"{Colors.GREEN}[✓] Created sample log file: sample_access.log ({len(sample_logs)} entries){Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a log file
  python log_analyzer.py access.log
  
  # Generate sample logs for testing
  python log_analyzer.py --generate-sample
  
  # Analyze with verbose output
  python log_analyzer.py access.log -v
  
  # Custom output file
  python log_analyzer.py access.log -o my_report.txt
        """
    )
    
    parser.add_argument('log_file', nargs='?', help='Path to log file (access.log)')
    parser.add_argument('-o', '--output', default='log_analysis_report.txt', help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--generate-sample', action='store_true', help='Generate sample log file for testing')
    
    args = parser.parse_args()
    
    # Display banner
    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    SECURITY LOG ANALYZER")
    print("    Project #12: Log Analysis & Security Monitoring")
    print("=" * 70 + f"{Colors.RESET}\n")
    
    if args.generate_sample:
        generate_sample_logs()
        return
    
    if not args.log_file:
        print(f"{Colors.RED}[!] Please specify a log file{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Or use --generate-sample to create sample logs{Colors.RESET}")
        sys.exit(1)
    
    if not os.path.exists(args.log_file):
        print(f"{Colors.RED}[!] Log file not found: {args.log_file}{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Generate sample logs with: python log_analyzer.py --generate-sample{Colors.RESET}")
        sys.exit(1)
    
    # Create and run analyzer
    analyzer = LogAnalyzer(
        log_file=args.log_file,
        output_file=args.output,
        verbose=args.verbose
    )
    
    analyzer.generate_report()

if __name__ == "__main__":
    main()