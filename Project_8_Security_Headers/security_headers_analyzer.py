#!/usr/bin/env python3
"""
HTTP Security Headers Analyzer
Project #8: Security Headers Audit Tool
"""

import requests
import sys
import time
import re
import json
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
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

class SecurityHeadersAnalyzer:
    def __init__(self, targets, timeout=10, output_file="security_headers_report.txt", verbose=False):
        """
        Initialize the Security Headers Analyzer
        
        Args:
            targets: List of target URLs
            timeout: Request timeout in seconds
            output_file: Output file name
            verbose: Enable verbose output
        """
        self.targets = targets if isinstance(targets, list) else [targets]
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        
        # Define security headers with their configurations
        self.security_headers = {
            'Strict-Transport-Security': {
                'name': 'HSTS',
                'description': 'Enforces HTTPS connections',
                'critical': True,
                'weight': 10,
                'validation': self.validate_hsts,
                'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
            },
            'Content-Security-Policy': {
                'name': 'CSP',
                'description': 'Prevents XSS and data injection',
                'critical': True,
                'weight': 10,
                'validation': self.validate_csp,
                'recommendation': 'Add: Content-Security-Policy: default-src \'self\''
            },
            'X-Frame-Options': {
                'name': 'Clickjacking Protection',
                'description': 'Prevents clickjacking attacks',
                'critical': True,
                'weight': 10,
                'validation': self.validate_xframe,
                'recommendation': 'Add: X-Frame-Options: DENY'
            },
            'X-Content-Type-Options': {
                'name': 'MIME Sniffing Protection',
                'description': 'Prevents MIME type sniffing',
                'critical': True,
                'weight': 10,
                'validation': self.validate_xcontenttype,
                'recommendation': 'Add: X-Content-Type-Options: nosniff'
            },
            'Referrer-Policy': {
                'name': 'Referrer Policy',
                'description': 'Controls referrer information',
                'critical': False,
                'weight': 5,
                'validation': self.validate_referrer,
                'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'name': 'Feature Policy',
                'description': 'Controls browser features',
                'critical': False,
                'weight': 5,
                'validation': self.validate_permissions,
                'recommendation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'
            },
            'X-XSS-Protection': {
                'name': 'XSS Protection',
                'description': 'Legacy XSS protection',
                'critical': False,
                'weight': 5,
                'validation': self.validate_xss,
                'recommendation': 'Add: X-XSS-Protection: 1; mode=block'
            },
            'Cache-Control': {
                'name': 'Caching Policy',
                'description': 'Controls caching behavior',
                'critical': False,
                'weight': 5,
                'validation': self.validate_cache,
                'recommendation': 'Add: Cache-Control: no-cache, no-store, must-revalidate'
            },
            'Set-Cookie': {
                'name': 'Cookie Security',
                'description': 'Cookie security attributes',
                'critical': False,
                'weight': 5,
                'validation': self.validate_cookie,
                'recommendation': 'Add Secure, HttpOnly, SameSite attributes to cookies'
            }
        }
        
        self.results = []
    
    def validate_hsts(self, value):
        """Validate HSTS header"""
        score = 0
        issues = []
        
        if not value:
            return 0, ["Missing HSTS header"]
        
        # Check for max-age
        max_age_match = re.search(r'max-age=(\d+)', value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age >= 31536000:  # 1 year
                score = 10
                issues.append("Good: max-age set to 1 year")
            elif max_age >= 2592000:  # 30 days
                score = 7
                issues.append("Warning: max-age less than 1 year")
            else:
                score = 3
                issues.append(f"Warning: max-age too short ({max_age} seconds)")
        else:
            issues.append("Error: No max-age specified")
        
        # Check for includeSubDomains
        if 'includeSubDomains' in value or 'includeSubdomains' in value:
            score += 2
            issues.append("Good: includeSubDomains enabled")
        
        # Check for preload
        if 'preload' in value:
            score += 3
            issues.append("Good: preload enabled")
        
        return min(score, 10), issues
    
    def validate_csp(self, value):
        """Validate CSP header"""
        score = 0
        issues = []
        
        if not value:
            return 0, ["Missing CSP header"]
        
        # Check for important directives
        directives = value.split(';')
        has_default_src = any('default-src' in d for d in directives)
        has_script_src = any('script-src' in d for d in directives)
        has_style_src = any('style-src' in d for d in directives)
        
        if has_default_src:
            score += 3
            issues.append("Good: default-src defined")
        
        if has_script_src:
            score += 3
            issues.append("Good: script-src defined")
        
        if has_style_src:
            score += 2
            issues.append("Good: style-src defined")
        
        # Check for unsafe-inline (bad)
        if 'unsafe-inline' in value:
            issues.append("Warning: unsafe-inline detected (consider using nonce or hash)")
        
        # Check for unsafe-eval (bad)
        if 'unsafe-eval' in value:
            issues.append("Warning: unsafe-eval detected (consider removing)")
        
        # Check if it's using 'self' or specific domains
        if "'self'" in value:
            score += 2
            issues.append("Good: using 'self' for CSP")
        
        return min(score, 10), issues
    
    def validate_xframe(self, value):
        """Validate X-Frame-Options header"""
        score = 0
        issues = []
        
        if not value:
            return 0, ["Missing X-Frame-Options header"]
        
        if value.lower() == 'deny':
            score = 10
            issues.append("Good: DENY prevents all framing")
        elif value.lower() == 'sameorigin':
            score = 7
            issues.append("Warning: SAMEORIGIN allows same-origin framing")
        else:
            score = 3
            issues.append(f"Warning: Weak value: {value}")
        
        return score, issues
    
    def validate_xcontenttype(self, value):
        """Validate X-Content-Type-Options header"""
        if not value:
            return 0, ["Missing X-Content-Type-Options header"]
        
        if value.lower() == 'nosniff':
            return 10, ["Good: nosniff prevents MIME sniffing"]
        else:
            return 5, [f"Warning: Unknown value: {value}"]
    
    def validate_referrer(self, value):
        """Validate Referrer-Policy header"""
        score = 0
        issues = []
        
        if not value:
            return 0, ["Missing Referrer-Policy header"]
        
        # Best practices for referrer policy
        if value in ['strict-origin-when-cross-origin', 'no-referrer-when-downgrade']:
            score = 10
            issues.append(f"Good: Secure policy: {value}")
        elif value in ['same-origin', 'strict-origin']:
            score = 7
            issues.append(f"Good: {value}")
        elif value == 'no-referrer':
            score = 5
            issues.append("Warning: no-referrer may break functionality")
        else:
            score = 3
            issues.append(f"Warning: Weak policy: {value}")
        
        return score, issues
    
    def validate_permissions(self, value):
        """Validate Permissions-Policy header"""
        if not value:
            return 0, ["Missing Permissions-Policy header"]
        
        # Check if it restricts sensitive features
        restricted = ['geolocation', 'microphone', 'camera', 'payment']
        found_restrictions = sum(1 for feature in restricted if feature in value.lower())
        
        if found_restrictions >= 3:
            return 10, ["Good: Restricted sensitive features"]
        elif found_restrictions >= 1:
            return 7, ["Warning: Some features restricted"]
        else:
            return 3, ["Warning: No feature restrictions found"]
    
    def validate_xss(self, value):
        """Validate X-XSS-Protection header"""
        if not value:
            return 0, ["Missing X-XSS-Protection header"]
        
        if value.lower() == '0':
            return 5, ["Warning: XSS protection disabled"]
        elif value.lower() == '1; mode=block':
            return 10, ["Good: XSS protection enabled with block mode"]
        else:
            return 7, [f"Unknown configuration: {value}"]
    
    def validate_cache(self, value):
        """Validate Cache-Control header"""
        score = 0
        issues = []
        
        if not value:
            return 0, ["Missing Cache-Control header"]
        
        if 'no-cache' in value.lower():
            score += 3
            issues.append("Good: no-cache specified")
        
        if 'no-store' in value.lower():
            score += 3
            issues.append("Good: no-store specified")
        
        if 'must-revalidate' in value.lower():
            score += 2
            issues.append("Good: must-revalidate specified")
        
        if 'private' in value.lower():
            issues.append("Warning: private caching allowed")
        
        return min(score, 10), issues if issues else ["Cache-Control: Default settings"]
    
    def validate_cookie(self, value):
        """Validate Set-Cookie header"""
        score = 0
        issues = []
        
        if not value:
            return 0, ["No cookies set"]
        
        # Check multiple cookies (if multiple Set-Cookie headers)
        cookies = value if isinstance(value, list) else [value]
        total_cookies = len(cookies)
        
        secure_count = 0
        httponly_count = 0
        samesite_count = 0
        
        for cookie in cookies:
            if 'Secure' in cookie:
                secure_count += 1
            
            if 'HttpOnly' in cookie:
                httponly_count += 1
            
            if 'SameSite' in cookie:
                samesite_count += 1
        
        # Calculate scores based on percentage of secure cookies
        if total_cookies > 0:
            secure_pct = secure_count / total_cookies * 100
            httponly_pct = httponly_count / total_cookies * 100
            samesite_pct = samesite_count / total_cookies * 100
            
            if secure_pct == 100:
                score += 3
                issues.append("Good: All cookies have Secure flag")
            elif secure_pct >= 50:
                score += 1
                issues.append("Warning: Some cookies missing Secure flag")
            
            if httponly_pct == 100:
                score += 3
                issues.append("Good: All cookies have HttpOnly flag")
            elif httponly_pct >= 50:
                score += 1
                issues.append("Warning: Some cookies missing HttpOnly flag")
            
            if samesite_pct == 100:
                score += 4
                issues.append("Good: All cookies have SameSite attribute")
            elif samesite_pct >= 50:
                score += 2
                issues.append("Warning: Some cookies missing SameSite attribute")
        
        return min(score, 10), issues if issues else ["No security issues found with cookies"]
    
    def analyze_headers(self, headers):
        """Analyze all security headers"""
        results = {}
        total_score = 0
        max_score = 0
        
        for header_name, config in self.security_headers.items():
            value = headers.get(header_name)
            
            # Handle multiple Set-Cookie headers
            if header_name == 'Set-Cookie' and 'Set-Cookie' in headers:
                # requests stores multiple Set-Cookie as a list
                value = headers.get('Set-Cookie')
            elif header_name == 'Set-Cookie':
                value = headers.get(header_name)
            
            # Validate the header
            if value:
                score, issues = config['validation'](value)
            else:
                score = 0
                issues = ["Missing header"]
                value = None
            
            # Calculate scores
            max_score += config['weight']
            total_score += score
            
            results[header_name] = {
                'name': config['name'],
                'description': config['description'],
                'critical': config['critical'],
                'weight': config['weight'],
                'value': value,
                'score': score,
                'max_score': config['weight'],
                'issues': issues,
                'recommendation': config['recommendation'] if not value else None
            }
        
        # Calculate percentage score
        if max_score > 0:
            percentage = (total_score / max_score) * 100
        else:
            percentage = 0
        
        results['_summary'] = {
            'total_score': total_score,
            'max_score': max_score,
            'percentage': percentage,
            'grade': self.get_grade(percentage)
        }
        
        return results
    
    def get_grade(self, percentage):
        """Get grade based on percentage"""
        if percentage >= 90:
            return 'A'
        elif percentage >= 80:
            return 'B'
        elif percentage >= 70:
            return 'C'
        elif percentage >= 60:
            return 'D'
        else:
            return 'F'
    
    def scan_target(self, target):
        """Scan a single target"""
        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}[*] Analyzing: {target}{Colors.RESET}")
        
        try:
            start_time = time.time()
            response = self.session.get(
                target,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            response_time = time.time() - start_time
            
            # Analyze headers
            analysis = self.analyze_headers(response.headers)
            
            result = {
                'url': target,
                'status_code': response.status_code,
                'response_time': response_time,
                'analysis': analysis,
                'headers': response.headers,
                'success': True
            }
            
            return result
            
        except requests.exceptions.SSLError:
            print(f"{Colors.YELLOW}[!] SSL Error, trying without verification...{Colors.RESET}")
            return self.scan_target_no_ssl(target)
        except requests.exceptions.ConnectionError:
            print(f"{Colors.RED}[!] Connection Error: Cannot reach {target}{Colors.RESET}")
            return {'url': target, 'success': False, 'error': 'Connection Error'}
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}[!] Timeout Error: {target} took too long to respond{Colors.RESET}")
            return {'url': target, 'success': False, 'error': 'Timeout'}
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {str(e)[:50]}{Colors.RESET}")
            return {'url': target, 'success': False, 'error': str(e)}
    
    def scan_target_no_ssl(self, target):
        """Scan target without SSL verification"""
        try:
            response = self.session.get(
                target,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            analysis = self.analyze_headers(response.headers)
            
            return {
                'url': target,
                'status_code': response.status_code,
                'response_time': 0,
                'analysis': analysis,
                'headers': response.headers,
                'success': True,
                'ssl_issue': True
            }
            
        except Exception as e:
            return {'url': target, 'success': False, 'error': str(e)}
    
    def print_results(self, result):
        """Print results for a single target"""
        if not result['success']:
            print(f"{Colors.RED}✗ Failed to analyze: {result.get('error', 'Unknown error')}{Colors.RESET}")
            return
        
        analysis = result['analysis']
        summary = analysis['_summary']
        
        print(f"\n{Colors.GREEN}✓ Target: {result['url']}{Colors.RESET}")
        print(f"  Status: {result['status_code']}")
        print(f"  Response Time: {result['response_time']:.2f}s")
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}SECURITY HEADERS ANALYSIS:{Colors.RESET}")
        print("-" * 60)
        
        for header_name, config in self.security_headers.items():
            if header_name in analysis:
                data = analysis[header_name]
                
                if data['value']:
                    status = f"{Colors.GREEN}✓{Colors.RESET}"
                else:
                    status = f"{Colors.RED}✗{Colors.RESET}"
                
                # Color code based on score
                if data['score'] >= data['max_score'] * 0.8:
                    score_color = Colors.GREEN
                elif data['score'] >= data['max_score'] * 0.5:
                    score_color = Colors.YELLOW
                else:
                    score_color = Colors.RED
                
                # Truncate long values
                display_value = data['value']
                if display_value and len(display_value) > 80:
                    display_value = display_value[:77] + '...'
                
                print(f"{status} {data['name']}: {display_value if data['value'] else 'MISSING'}")
                print(f"  Score: {score_color}{data['score']}/{data['max_score']}{Colors.RESET}")
                print(f"  Issues: {', '.join(data['issues'][:3])}")
                if data.get('recommendation'):
                    print(f"  Recommendation: {Colors.YELLOW}{data['recommendation']}{Colors.RESET}")
                print("")
        
        # Print summary
        grade_color = Colors.GREEN if summary['percentage'] >= 80 else Colors.YELLOW if summary['percentage'] >= 60 else Colors.RED
        
        print(f"{Colors.BOLD}SECURITY SCORE:{Colors.RESET}")
        print(f"  Score: {summary['total_score']}/{summary['max_score']}")
        print(f"  Percentage: {grade_color}{summary['percentage']:.1f}%{Colors.RESET}")
        print(f"  Grade: {grade_color}{summary['grade']}{Colors.RESET}")
        
        # Print critical missing headers
        critical_missing = []
        for header_name, data in analysis.items():
            if header_name != '_summary':
                if data['critical'] and not data['value']:
                    critical_missing.append(header_name)
        
        if critical_missing:
            print(f"\n{Colors.RED}⚠️ Critical Missing Headers:{Colors.RESET}")
            for header in critical_missing:
                print(f"  - {header} ({self.security_headers[header]['description']})")
                print(f"    Fix: {Colors.YELLOW}{self.security_headers[header]['recommendation']}{Colors.RESET}")
    
    def generate_report(self, results):
        """Generate a detailed report file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SECURITY HEADERS AUDIT REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Targets Scanned: {len(results)}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if not result['success']:
                    f.write(f"\n[FAILED] {result['url']}\n")
                    f.write(f"Error: {result.get('error', 'Unknown error')}\n")
                    continue
                
                f.write(f"\n{'=' * 80}\n")
                f.write(f"TARGET: {result['url']}\n")
                f.write(f"{'=' * 80}\n")
                f.write(f"Status: {result['status_code']}\n")
                f.write(f"Response Time: {result['response_time']:.2f}s\n\n")
                
                analysis = result['analysis']
                summary = analysis['_summary']
                
                f.write("HEADER ANALYSIS\n")
                f.write("-" * 60 + "\n")
                
                for header_name, config in self.security_headers.items():
                    if header_name in analysis:
                        data = analysis[header_name]
                        status = "✓" if data['value'] else "✗"
                        display_value = data['value'] if data['value'] else 'MISSING'
                        if display_value and len(display_value) > 100:
                            display_value = display_value[:97] + '...'
                        f.write(f"{status} {data['name']}: {display_value}\n")
                        f.write(f"  Score: {data['score']}/{data['max_score']}\n")
                        f.write(f"  Issues: {', '.join(data['issues'])}\n")
                        if data.get('recommendation'):
                            f.write(f"  Recommendation: {data['recommendation']}\n")
                        f.write("\n")
                
                f.write("SUMMARY\n")
                f.write("-" * 60 + "\n")
                f.write(f"Total Score: {summary['total_score']}/{summary['max_score']}\n")
                f.write(f"Percentage: {summary['percentage']:.1f}%\n")
                f.write(f"Grade: {summary['grade']}\n")
                f.write("\n")
                
                # Critical missing headers
                critical_missing = []
                for header_name, data in analysis.items():
                    if header_name != '_summary':
                        if data['critical'] and not data['value']:
                            critical_missing.append(header_name)
                
                if critical_missing:
                    f.write("CRITICAL MISSING HEADERS\n")
                    f.write("-" * 60 + "\n")
                    for header in critical_missing:
                        f.write(f"  - {header} ({self.security_headers[header]['description']})\n")
                        f.write(f"    Fix: {self.security_headers[header]['recommendation']}\n")
                    f.write("\n")
                
                f.write("RECOMMENDATIONS\n")
                f.write("-" * 60 + "\n")
                
                # Generate recommendations - FIXED SECTION
                recommendations = []
                for header_name, data in analysis.items():
                    if header_name != '_summary':
                        if not data['value']:
                            recommendations.append(data['recommendation'])
                        elif data['score'] < data['max_score'] * 0.7:
                            # Score is low, provide improvement recommendations
                            issues_text = ' '.join(data['issues']).lower()
                            if 'weak' in issues_text or 'warning' in issues_text:
                                recommendations.append(f"Improve {header_name}: {self.security_headers[header_name]['recommendation']}")
                
                if recommendations:
                    for rec in recommendations[:5]:  # Limit to top 5
                        f.write(f"  - {rec}\n")
                else:
                    f.write("  - No recommendations - all headers are well configured!\n")
                
                f.write("\n" + "=" * 80 + "\n")
        
        print(f"\n{Colors.GREEN}[✓] Report saved to: {self.output_file}{Colors.RESET}")
    
    def generate_comparison_table(self, results):
        """Generate a comparison table of all targets"""
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}" + "=" * 70)
        print("    COMPARISON TABLE")
        print("=" * 70 + f"{Colors.RESET}\n")
        
        # Table header
        print(f"{Colors.BOLD}{'Target':<35} {'Score':<10} {'Grade':<6} {'HSTS':<6} {'CSP':<6} {'XFO':<6} {'XCTO':<6}{Colors.RESET}")
        print("-" * 80)
        
        for result in results:
            if not result['success']:
                print(f"{result['url'][:35]:<35} {Colors.RED}ERROR{Colors.RESET}")
                continue
            
            analysis = result['analysis']
            summary = analysis['_summary']
            
            # Get header statuses
            hsts = "✓" if analysis.get('Strict-Transport-Security', {}).get('value') else "✗"
            csp = "✓" if analysis.get('Content-Security-Policy', {}).get('value') else "✗"
            xfo = "✓" if analysis.get('X-Frame-Options', {}).get('value') else "✗"
            xcto = "✓" if analysis.get('X-Content-Type-Options', {}).get('value') else "✗"
            
            grade_color = Colors.GREEN if summary['grade'] == 'A' else Colors.YELLOW if summary['grade'] == 'B' else Colors.RED
            
            print(f"{result['url'][:35]:<35} {summary['percentage']:>6.1f}%  {grade_color}{summary['grade']:>4}{Colors.RESET}  {hsts:>4}  {csp:>4}  {xfo:>4}  {xcto:>4}")
        
        print("-" * 80)
        
        # Save comparison table
        with open('comparison_table.txt', 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SECURITY HEADERS COMPARISON TABLE\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"{'Target':<35} {'Score':<10} {'Grade':<6} {'HSTS':<6} {'CSP':<6} {'XFO':<6} {'XCTO':<6}\n")
            f.write("-" * 80 + "\n")
            
            for result in results:
                if not result['success']:
                    f.write(f"{result['url'][:35]:<35} ERROR\n")
                    continue
                
                analysis = result['analysis']
                summary = analysis['_summary']
                
                hsts = "✓" if analysis.get('Strict-Transport-Security', {}).get('value') else "✗"
                csp = "✓" if analysis.get('Content-Security-Policy', {}).get('value') else "✗"
                xfo = "✓" if analysis.get('X-Frame-Options', {}).get('value') else "✗"
                xcto = "✓" if analysis.get('X-Content-Type-Options', {}).get('value') else "✗"
                
                f.write(f"{result['url'][:35]:<35} {summary['percentage']:>6.1f}%  {summary['grade']:>4}     {hsts:>4}  {csp:>4}  {xfo:>4}  {xcto:>4}\n")
            
            f.write("-" * 80 + "\n")
        
        print(f"\n{Colors.GREEN}[✓] Comparison table saved to: comparison_table.txt{Colors.RESET}")
    
    def scan(self):
        """Main scan method"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] HTTP Security Headers Analyzer{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Targets: {len(self.targets)}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Headers Checked: {len(self.security_headers)}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print("")
        
        results = []
        
        for target in self.targets:
            result = self.scan_target(target)
            results.append(result)
            
            if result['success']:
                self.print_results(result)
            else:
                print(f"{Colors.RED}✗ Failed to analyze {target}{Colors.RESET}")
        
        # Generate reports
        if results:
            self.generate_report(results)
            if len(results) > 1:
                self.generate_comparison_table(results)
        
        self.results = results
        return results

def main():
    parser = argparse.ArgumentParser(
        description="HTTP Security Headers Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single target
  python security_headers_analyzer.py example.com
  
  # Analyze multiple targets
  python security_headers_analyzer.py example.com google.com github.com
  
  # Use full URLs
  python security_headers_analyzer.py https://example.com https://google.com
  
  # Save report to custom file
  python security_headers_analyzer.py example.com -o my_report.txt
        """
    )
    
    parser.add_argument('targets', nargs='+', help='Target URLs or domains to analyze')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', default='security_headers_report.txt', help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Display banner
    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    HTTP SECURITY HEADERS ANALYZER")
    print("    Project #8: Security Headers Audit Tool")
    print("=" * 70 + f"{Colors.RESET}\n")
    
    # Create and run analyzer
    analyzer = SecurityHeadersAnalyzer(
        targets=args.targets,
        timeout=args.timeout,
        output_file=args.output,
        verbose=args.verbose
    )
    
    analyzer.scan()

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()