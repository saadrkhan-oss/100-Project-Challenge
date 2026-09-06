#!/usr/bin/env python3
"""
WordPress Vulnerability Scanner
Project #9: WordPress Security Scanner
"""

import requests
import sys
import re
import time
import json
from urllib.parse import urljoin, urlparse
from datetime import datetime
import argparse

# Try to import BeautifulSoup, fallback if not available
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

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

# Vulnerability Database (simplified)
WP_VULNERABILITIES = {
    '5.8.2': {
        'cves': ['CVE-2021-23452'],
        'description': 'Reflected XSS in block editor',
        'severity': 'HIGH',
        'fixed_version': '5.8.3'
    },
    '5.7.2': {
        'cves': ['CVE-2021-29450'],
        'description': 'SQL injection vulnerability',
        'severity': 'CRITICAL',
        'fixed_version': '5.7.3'
    },
    '5.6.2': {
        'cves': ['CVE-2021-21283'],
        'description': 'Cross-site scripting in media library',
        'severity': 'MEDIUM',
        'fixed_version': '5.6.3'
    },
    '4.9.8': {
        'cves': ['CVE-2018-12895'],
        'description': 'Authenticated arbitrary file deletion',
        'severity': 'CRITICAL',
        'fixed_version': '4.9.9'
    },
    '4.7.5': {
        'cves': ['CVE-2017-9066'],
        'description': 'SQL injection in REST API',
        'severity': 'CRITICAL',
        'fixed_version': '4.7.6'
    }
}

PLUGIN_VULNERABILITIES = {
    'akismet': {
        '4.1.9': {'cves': [], 'description': 'No known vulnerabilities', 'severity': 'LOW'}
    },
    'wordpress-seo': {
        '17.2': {'cves': ['CVE-2021-34375'], 'description': 'Authenticated XSS', 'severity': 'HIGH', 'fixed_version': '17.5'}
    },
    'elementor': {
        '3.5.0': {'cves': ['CVE-2021-34583'], 'description': 'Authenticated stored XSS', 'severity': 'HIGH', 'fixed_version': '3.5.1'}
    },
    'woocommerce': {
        '5.5.0': {'cves': ['CVE-2021-34661'], 'description': 'Unauthenticated SQL injection', 'severity': 'CRITICAL', 'fixed_version': '5.5.1'}
    }
}

THEME_VULNERABILITIES = {
    'twentytwenty': {
        '1.5': {'cves': ['CVE-2020-27041'], 'description': 'XSS in comments', 'severity': 'MEDIUM', 'fixed_version': '1.6'}
    },
    'astra': {
        '3.0.0': {'cves': ['CVE-2021-24156'], 'description': 'SQL injection', 'severity': 'HIGH', 'fixed_version': '3.0.1'}
    }
}

def get_wp_vulnerability(version):
    if version in WP_VULNERABILITIES:
        return WP_VULNERABILITIES[version]
    return None

def get_plugin_vulnerability(plugin, version):
    if plugin in PLUGIN_VULNERABILITIES:
        if version in PLUGIN_VULNERABILITIES[plugin]:
            return PLUGIN_VULNERABILITIES[plugin][version]
    return None

def get_theme_vulnerability(theme, version):
    if theme in THEME_VULNERABILITIES:
        if version in THEME_VULNERABILITIES[theme]:
            return THEME_VULNERABILITIES[theme][version]
    return None

class WordPressScanner:
    def __init__(self, target, timeout=10, output_file="wordpress_vuln_report.txt", verbose=False):
        """
        Initialize the WordPress Vulnerability Scanner
        """
        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        
        # WordPress detection patterns
        self.wp_patterns = {
            'generator': r'<meta name="generator" content="WordPress ([0-9.]+)"',
            'style_ver': r'/wp-content/themes/[^/]+/style\.css\?ver=([0-9.]+)',
            'wp_embed': r'/wp-includes/js/wp-embed\.min\.js\?ver=([0-9.]+)',
        }
        
        # Common plugins and themes
        self.common_plugins = [
            'akismet', 'wordpress-seo', 'elementor', 'woocommerce',
            'contact-form-7', 'jetpack', 'wpforms-lite', 'yoast-seo',
            'all-in-one-seo-pack', 'rank-math', 'w3-total-cache',
            'wp-super-cache', 'wordfence', 'sucuri-scanner'
        ]
        
        self.common_themes = [
            'twentytwenty', 'twentytwentyone', 'twentytwentytwo',
            'astra', 'generatepress', 'oceanwp', 'hello-elementor',
            'kadence', 'neve', 'blocksy'
        ]
        
        self.results = {
            'url': self.target,
            'is_wordpress': False,
            'version': None,
            'plugins': {},
            'themes': {},
            'vulnerabilities': [],
            'security_issues': [],
            'recommendations': []
        }
    
    def test_connection(self):
        """Test if target is reachable"""
        print(f"{Colors.BOLD}[*] Testing connection to {self.target}...{Colors.RESET}")
        
        # Try HTTPS first, then HTTP
        for protocol in ['https', 'http']:
            test_url = self.target.replace('http://', f'{protocol}://').replace('https://', f'{protocol}://')
            if not test_url.startswith(('http://', 'https://')):
                test_url = f'{protocol}://{test_url}'
            
            try:
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                self.target = test_url
                print(f"{Colors.GREEN}[✓] Target is reachable! Status: {response.status_code} ({protocol}){Colors.RESET}")
                return True, response
                
            except requests.exceptions.ConnectionError:
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] Connection failed on {protocol}{Colors.RESET}")
                continue
            except requests.exceptions.Timeout:
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] Timeout on {protocol}{Colors.RESET}")
                continue
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] Error on {protocol}: {str(e)[:30]}{Colors.RESET}")
                continue
        
        print(f"{Colors.RED}[!] Cannot reach {self.target} on any protocol{Colors.RESET}")
        return False, None
    
    def detect_wordpress(self, response):
        """Detect if target is running WordPress"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Detecting WordPress...{Colors.RESET}")
        
        html = response.text
        
        # Check for WordPress indicators
        indicators = []
        
        # Check meta generator
        generator_match = re.search(self.wp_patterns['generator'], html, re.IGNORECASE)
        if generator_match:
            version = generator_match.group(1)
            indicators.append(f"meta generator: WordPress {version}")
            self.results['version'] = version
        
        # Check for wp-content
        if '/wp-content/' in html:
            indicators.append("wp-content path found")
        
        # Check for wp-includes
        if '/wp-includes/' in html:
            indicators.append("wp-includes path found")
        
        # Check for stylesheet version
        style_match = re.search(self.wp_patterns['style_ver'], html, re.IGNORECASE)
        if style_match and not self.results['version']:
            version = style_match.group(1)
            self.results['version'] = version
            indicators.append(f"style.css version: {version}")
        
        # Check for wp-embed
        embed_match = re.search(self.wp_patterns['wp_embed'], html, re.IGNORECASE)
        if embed_match and not self.results['version']:
            version = embed_match.group(1)
            self.results['version'] = version
            indicators.append(f"wp-embed version: {version}")
        
        if indicators:
            self.results['is_wordpress'] = True
            print(f"{Colors.GREEN}[✓] WordPress detected!{Colors.RESET}")
            for indicator in indicators[:3]:
                print(f"  {Colors.CYAN}•{Colors.RESET} {indicator}")
            return True
        
        print(f"{Colors.YELLOW}[!] No WordPress indicators found{Colors.RESET}")
        return False
    
    def detect_version(self, response):
        """Detect WordPress version"""
        if self.results['version']:
            print(f"\n{Colors.GREEN}[✓] WordPress Version: {self.results['version']}{Colors.RESET}")
            return self.results['version']
        
        html = response.text
        
        patterns = [
            r'<meta name="generator" content="WordPress ([0-9.]+)"',
            r'/wp-content/themes/[^/]+/style\.css\?ver=([0-9.]+)',
            r'/wp-includes/js/wp-embed\.min\.js\?ver=([0-9.]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = match.group(1)
                self.results['version'] = version
                print(f"\n{Colors.GREEN}[✓] WordPress Version: {version}{Colors.RESET}")
                return version
        
        print(f"\n{Colors.YELLOW}[!] Could not detect WordPress version{Colors.RESET}")
        return None
    
    def detect_plugins(self, response):
        """Detect installed plugins"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Detecting plugins...{Colors.RESET}")
        
        html = response.text
        found_plugins = {}
        
        for plugin in self.common_plugins:
            plugin_path = f'/wp-content/plugins/{plugin}/'
            if plugin_path in html:
                version = self.extract_plugin_version(html, plugin)
                found_plugins[plugin] = version
                print(f"  {Colors.GREEN}✓{Colors.RESET} {plugin} (v{version if version else 'unknown'})")
        
        # Check plugin readme files
        for plugin in self.common_plugins:
            if plugin not in found_plugins:
                readme_url = urljoin(self.target, f'/wp-content/plugins/{plugin}/readme.txt')
                try:
                    readme_response = self.session.get(readme_url, timeout=self.timeout, verify=False)
                    if readme_response.status_code == 200:
                        version_match = re.search(r'Stable tag: ([0-9.]+)', readme_response.text)
                        version = version_match.group(1) if version_match else None
                        found_plugins[plugin] = version
                        print(f"  {Colors.GREEN}✓{Colors.RESET} {plugin} (v{version if version else 'unknown'})")
                except:
                    pass
        
        self.results['plugins'] = found_plugins
        
        if not found_plugins:
            print(f"  {Colors.YELLOW}No plugins detected{Colors.RESET}")
        
        return found_plugins
    
    def extract_plugin_version(self, html, plugin):
        """Extract plugin version from HTML"""
        patterns = [
            f'/wp-content/plugins/{plugin}/[^"]+\\?ver=([0-9.]+)',
            f'<link[^>]+plugins/{plugin}/[^>]+\\?ver=([0-9.]+)',
            f'<script[^>]+plugins/{plugin}/[^>]+\\?ver=([0-9.]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def detect_themes(self, response):
        """Detect installed themes"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Detecting themes...{Colors.RESET}")
        
        html = response.text
        found_themes = {}
        
        for theme in self.common_themes:
            theme_path = f'/wp-content/themes/{theme}/'
            if theme_path in html:
                version = self.extract_theme_version(html, theme)
                found_themes[theme] = version
                print(f"  {Colors.GREEN}✓{Colors.RESET} {theme} (v{version if version else 'unknown'})")
        
        # Check theme stylesheets
        for theme in self.common_themes:
            if theme not in found_themes:
                style_url = urljoin(self.target, f'/wp-content/themes/{theme}/style.css')
                try:
                    style_response = self.session.get(style_url, timeout=self.timeout, verify=False)
                    if style_response.status_code == 200:
                        version_match = re.search(r'Version: ([0-9.]+)', style_response.text)
                        version = version_match.group(1) if version_match else None
                        found_themes[theme] = version
                        print(f"  {Colors.GREEN}✓{Colors.RESET} {theme} (v{version if version else 'unknown'})")
                except:
                    pass
        
        self.results['themes'] = found_themes
        
        if not found_themes:
            print(f"  {Colors.YELLOW}No themes detected{Colors.RESET}")
        
        return found_themes
    
    def extract_theme_version(self, html, theme):
        """Extract theme version from HTML"""
        patterns = [
            f'/wp-content/themes/{theme}/[^"]+\\?ver=([0-9.]+)',
            f'<link[^>]+themes/{theme}/[^>]+\\?ver=([0-9.]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def check_vulnerabilities(self):
        """Check for known vulnerabilities"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Checking vulnerabilities...{Colors.RESET}")
        
        vulnerabilities = []
        
        # Check WordPress version
        if self.results['version']:
            wp_vuln = get_wp_vulnerability(self.results['version'])
            if wp_vuln:
                vuln = {
                    'component': 'WordPress',
                    'version': self.results['version'],
                    'cves': wp_vuln.get('cves', []),
                    'description': wp_vuln.get('description', ''),
                    'severity': wp_vuln.get('severity', 'MEDIUM'),
                    'fixed_version': wp_vuln.get('fixed_version', 'Update to latest')
                }
                vulnerabilities.append(vuln)
                severity_color = Colors.RED if vuln['severity'] == 'CRITICAL' else Colors.YELLOW
                print(f"  {Colors.RED}⚠{Colors.RESET} WordPress {self.results['version']}: {severity_color}{vuln['severity']}{Colors.RESET}")
                print(f"    {vuln['description']}")
                print(f"    Fixed in: {vuln['fixed_version']}")
        
        # Check plugins
        for plugin, version in self.results['plugins'].items():
            if version:
                plugin_vuln = get_plugin_vulnerability(plugin, version)
                if plugin_vuln and plugin_vuln.get('cves'):
                    vuln = {
                        'component': f"Plugin: {plugin}",
                        'version': version,
                        'cves': plugin_vuln.get('cves', []),
                        'description': plugin_vuln.get('description', ''),
                        'severity': plugin_vuln.get('severity', 'MEDIUM'),
                        'fixed_version': plugin_vuln.get('fixed_version', 'Update to latest')
                    }
                    vulnerabilities.append(vuln)
                    severity_color = Colors.RED if vuln['severity'] == 'CRITICAL' else Colors.YELLOW
                    print(f"  {Colors.RED}⚠{Colors.RESET} {plugin} {version}: {severity_color}{vuln['severity']}{Colors.RESET}")
                    print(f"    {vuln['description']}")
                    print(f"    Fixed in: {vuln['fixed_version']}")
        
        # Check themes
        for theme, version in self.results['themes'].items():
            if version:
                theme_vuln = get_theme_vulnerability(theme, version)
                if theme_vuln and theme_vuln.get('cves'):
                    vuln = {
                        'component': f"Theme: {theme}",
                        'version': version,
                        'cves': theme_vuln.get('cves', []),
                        'description': theme_vuln.get('description', ''),
                        'severity': theme_vuln.get('severity', 'MEDIUM'),
                        'fixed_version': theme_vuln.get('fixed_version', 'Update to latest')
                    }
                    vulnerabilities.append(vuln)
                    severity_color = Colors.RED if vuln['severity'] == 'CRITICAL' else Colors.YELLOW
                    print(f"  {Colors.RED}⚠{Colors.RESET} {theme} {version}: {severity_color}{vuln['severity']}{Colors.RESET}")
                    print(f"    {vuln['description']}")
                    print(f"    Fixed in: {vuln['fixed_version']}")
        
        self.results['vulnerabilities'] = vulnerabilities
        
        if not vulnerabilities:
            print(f"  {Colors.GREEN}✓ No known vulnerabilities detected{Colors.RESET}")
        
        return vulnerabilities
    
    def check_security_issues(self):
        """Check for WordPress security issues"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[*] Checking security issues...{Colors.RESET}")
        
        issues = []
        
        # Check admin exposure
        admin_url = urljoin(self.target, '/wp-admin/')
        try:
            admin_response = self.session.get(admin_url, timeout=self.timeout, verify=False)
            if admin_response.status_code == 200 or admin_response.status_code == 302:
                issues.append({
                    'issue': 'Admin exposure',
                    'description': '/wp-admin/ is accessible',
                    'risk': 'MEDIUM',
                    'recommendation': 'Consider restricting admin access or adding 2FA'
                })
                print(f"  {Colors.YELLOW}⚠{Colors.RESET} Admin login exposed at /wp-admin/")
        except:
            pass
        
        # Check XML-RPC
        xmlrpc_url = urljoin(self.target, '/xmlrpc.php')
        try:
            xmlrpc_response = self.session.get(xmlrpc_url, timeout=self.timeout, verify=False)
            if xmlrpc_response.status_code == 200:
                issues.append({
                    'issue': 'XML-RPC enabled',
                    'description': 'XML-RPC endpoint is active',
                    'risk': 'MEDIUM',
                    'recommendation': 'Disable XML-RPC if not needed'
                })
                print(f"  {Colors.YELLOW}⚠{Colors.RESET} XML-RPC enabled at /xmlrpc.php")
        except:
            pass
        
        self.results['security_issues'] = issues
        
        if not issues:
            print(f"  {Colors.GREEN}✓ No security issues detected{Colors.RESET}")
        
        return issues
    
    def generate_recommendations(self):
        """Generate recommendations based on findings"""
        recommendations = []
        
        # WordPress version recommendations
        if self.results['version']:
            wp_vuln = get_wp_vulnerability(self.results['version'])
            if wp_vuln:
                recommendations.append(f"Update WordPress from {self.results['version']} to {wp_vuln.get('fixed_version', 'latest')}")
        
        # Plugin recommendations
        for plugin, version in self.results['plugins'].items():
            if version:
                plugin_vuln = get_plugin_vulnerability(plugin, version)
                if plugin_vuln and plugin_vuln.get('fixed_version'):
                    recommendations.append(f"Update {plugin} from {version} to {plugin_vuln.get('fixed_version')}")
        
        # Security issues recommendations
        for issue in self.results['security_issues']:
            recommendations.append(issue['recommendation'])
        
        self.results['recommendations'] = list(set(recommendations))
        
        # Print recommendations
        print(f"\n{Colors.BOLD}{Colors.GREEN}[📋] RECOMMENDATIONS:{Colors.RESET}")
        if self.results['recommendations']:
            for rec in self.results['recommendations'][:10]:
                print(f"  {Colors.CYAN}•{Colors.RESET} {rec}")
        else:
            print(f"  {Colors.GREEN}✓ No recommendations needed{Colors.RESET}")
        
        return recommendations
    
    def print_summary(self):
        """Print scan summary"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.GREEN}[✓] SCAN SUMMARY{Colors.RESET}")
        print("=" * 70)
        
        print(f"{Colors.BOLD}WordPress: {self.results['version'] if self.results['version'] else 'Unknown'}{Colors.RESET}")
        print(f"{Colors.BOLD}Plugins: {len(self.results['plugins'])} detected{Colors.RESET}")
        print(f"{Colors.BOLD}Themes: {len(self.results['themes'])} detected{Colors.RESET}")
        print(f"{Colors.BOLD}Vulnerabilities: {len(self.results['vulnerabilities'])} found{Colors.RESET}")
        print(f"{Colors.BOLD}Security Issues: {len(self.results['security_issues'])} found{Colors.RESET}")
        
        if self.results['vulnerabilities']:
            print(f"\n{Colors.RED}⚠️ Vulnerable Components:{Colors.RESET}")
            for vuln in self.results['vulnerabilities']:
                severity_color = Colors.RED if vuln['severity'] == 'CRITICAL' else Colors.YELLOW
                print(f"  {severity_color}•{Colors.RESET} {vuln['component']} ({vuln['version']}) - {vuln['severity']}")
    
    def save_report(self):
        """Save report to file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("WORDPRESS VULNERABILITY SCAN REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:         {self.target}\n")
            f.write(f"Scan Date:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if hasattr(self, 'scan_time'):
                f.write(f"Scan Duration:  {self.scan_time:.2f} seconds\n")
            f.write(f"Is WordPress:   {self.results['is_wordpress']}\n")
            f.write("=" * 80 + "\n\n")
            
            # WordPress version
            f.write("WORDPRESS VERSION\n")
            f.write("-" * 50 + "\n")
            f.write(f"Version: {self.results['version'] if self.results['version'] else 'Unknown'}\n\n")
            
            # Plugins
            f.write("DETECTED PLUGINS\n")
            f.write("-" * 50 + "\n")
            if self.results['plugins']:
                for plugin, version in self.results['plugins'].items():
                    f.write(f"  {plugin}: {version if version else 'Unknown version'}\n")
            else:
                f.write("  No plugins detected\n")
            f.write("\n")
            
            # Themes
            f.write("DETECTED THEMES\n")
            f.write("-" * 50 + "\n")
            if self.results['themes']:
                for theme, version in self.results['themes'].items():
                    f.write(f"  {theme}: {version if version else 'Unknown version'}\n")
            else:
                f.write("  No themes detected\n")
            f.write("\n")
            
            # Vulnerabilities
            f.write("VULNERABILITIES\n")
            f.write("-" * 50 + "\n")
            if self.results['vulnerabilities']:
                for vuln in self.results['vulnerabilities']:
                    f.write(f"  Component: {vuln['component']}\n")
                    f.write(f"  Version: {vuln['version']}\n")
                    f.write(f"  CVEs: {', '.join(vuln.get('cves', ['No CVEs']))}\n")
                    f.write(f"  Description: {vuln['description']}\n")
                    f.write(f"  Severity: {vuln['severity']}\n")
                    f.write(f"  Fixed in: {vuln.get('fixed_version', 'Update to latest')}\n")
                    f.write("  " + "-" * 30 + "\n")
            else:
                f.write("  No vulnerabilities detected\n")
            f.write("\n")
            
            # Security Issues
            f.write("SECURITY ISSUES\n")
            f.write("-" * 50 + "\n")
            if self.results['security_issues']:
                for issue in self.results['security_issues']:
                    f.write(f"  Issue: {issue['issue']}\n")
                    f.write(f"  Description: {issue['description']}\n")
                    f.write(f"  Risk: {issue['risk']}\n")
                    f.write(f"  Recommendation: {issue['recommendation']}\n")
                    f.write("  " + "-" * 30 + "\n")
            else:
                f.write("  No security issues detected\n")
            f.write("\n")
            
            # Recommendations
            f.write("RECOMMENDATIONS\n")
            f.write("-" * 50 + "\n")
            if self.results['recommendations']:
                for rec in self.results['recommendations']:
                    f.write(f"  • {rec}\n")
            else:
                f.write("  No recommendations needed\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("Report generated by WordPress Vulnerability Scanner\n")
            f.write("Project #9: WordPress Security Scanner\n")
            f.write("=" * 80 + "\n")
        
        print(f"\n{Colors.GREEN}[✓] Report saved to: {self.output_file}{Colors.RESET}")
    
    def scan(self):
        """Main scan method"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] WordPress Vulnerability Scanner{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Target: {self.target}{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print("")
        
        start_time = time.time()
        
        # Test connection
        connected, response = self.test_connection()
        if not connected:
            print(f"{Colors.RED}[!] Cannot proceed with scan - target unreachable{Colors.RESET}")
            print(f"\n{Colors.YELLOW}[!] Try these working targets:{Colors.RESET}")
            print(f"  {Colors.CYAN}• https://wordpress.org{Colors.RESET}")
            print(f"  {Colors.CYAN}• https://techcrunch.com{Colors.RESET}")
            print(f"  {Colors.CYAN}• http://localhost (if running locally){Colors.RESET}")
            self.save_report()
            return
        
        # Detect WordPress
        if not self.detect_wordpress(response):
            print(f"{Colors.YELLOW}[!] Target does not appear to be running WordPress{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] This scan is designed for WordPress sites{Colors.RESET}")
            self.save_report()
            return
        
        # Perform scans
        self.detect_version(response)
        self.detect_plugins(response)
        self.detect_themes(response)
        self.check_vulnerabilities()
        self.check_security_issues()
        self.generate_recommendations()
        
        # Print summary
        self.print_summary()
        
        # Save report
        self.save_report()
        
        self.scan_time = time.time() - start_time
        print(f"\n{Colors.GREEN}[✓] Scan completed in {self.scan_time:.2f} seconds{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="WordPress Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a WordPress site
  python wordpress_scanner.py https://wordpress.org
  
  # Scan with verbose output
  python wordpress_scanner.py https://wordpress.org -v
  
  # Custom output file
  python wordpress_scanner.py https://wordpress.org -o my_report.txt
  
  # Try a known WordPress site
  python wordpress_scanner.py https://techcrunch.com
        """
    )
    
    parser.add_argument('target', help='Target URL (e.g., https://wordpress.org)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', default='wordpress_vuln_report.txt', help='Output file name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Display banner
    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    WORDPRESS VULNERABILITY SCANNER")
    print("    Project #9: WordPress Security Scanner")
    print("=" * 70 + f"{Colors.RESET}\n")
    
    # Create and run scanner
    scanner = WordPressScanner(
        target=args.target,
        timeout=args.timeout,
        output_file=args.output,
        verbose=args.verbose
    )
    
    scanner.scan()

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()