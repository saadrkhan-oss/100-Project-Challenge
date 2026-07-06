#!/usr/bin/env python3
"""
Web Directory & File Discovery Tool
Project #4: Directory/File Brute-Forcing
"""

import requests
import sys
import time
import threading
import argparse
import os
import re
from urllib.parse import urljoin, urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

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

class DirectoryBruteforcer:
    def __init__(self, target, wordlist_path=None, extensions=None, threads=10, 
                 timeout=3, delay=0.2, follow_redirects=True, verbose=False,
                 respect_robots=True, output_file="directory_scan_results.txt"):
        """
        Initialize the directory bruteforcer
        """
        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # Remove trailing slash
        self.target = target.rstrip('/')
        self.wordlist_path = wordlist_path
        self.extensions = extensions or ['.php', '.html', '.txt', '.zip', '.sql', '.bak', '.old', '.xml', '.json', '.ini', '.config']
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.follow_redirects = follow_redirects
        self.verbose = verbose
        self.respect_robots = respect_robots
        self.output_file = output_file
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        self.results = defaultdict(list)
        self.found_paths = []
        self.robots_disallowed = []
        self.lock = threading.Lock()
        self.total_requests = 0
        self.start_time = None
        self.working_target = False
        
        # Load wordlist
        self.wordlist = self.load_wordlist()
        
        # Common false positive patterns
        self.false_positives = [
            r'404', r'not found', r'page not found', r'error 404',
            r'no such file', r'does not exist', r'not exist',
            r'cant find', r"can't find", r'unable to find',
            r'sorry, the page you are looking for',
            r'the requested url was not found',
            r'no input file specified',
            r'file not found',
            r'not found on this server'
        ]
        
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Initialized bruteforcer{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Target: {self.target}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Wordlist: {len(self.wordlist)} entries{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Extensions: {', '.join(self.extensions)}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Threads: {self.threads}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Timeout: {self.timeout}s{Colors.RESET}")
    
    def load_wordlist(self):
        """Load wordlist from file or use default"""
        wordlist = []
        
        # Default directories (reduced for speed)
        default_dirs = [
            'admin', 'backup', 'config', 'css', 'data', 'db', 'dev', 
            'download', 'files', 'images', 'img', 'include', 'js', 
            'lib', 'logs', 'media', 'old', 'pma', 'sql', 'src', 'temp',
            'tmp', 'upload', 'uploads', 'user', 'web', 'wp-admin', 
            'wp-content', 'wp-includes', 'xmlrpc'
        ]
        
        # Default files
        default_files = [
            'index', 'default', 'home', 'about', 'contact', 'help',
            'error', 'test', 'info', 'config', 'setup', 'install', 
            'readme', 'license', 'robots', 'sitemap', 'backup',
            'auth', 'login', 'register', 'api', 'rest', 'graphql'
        ]
        
        # Try to load from file
        if self.wordlist_path and os.path.exists(self.wordlist_path):
            try:
                with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                print(f"{Colors.GREEN}[✓] Loaded {len(wordlist)} entries from {self.wordlist_path}{Colors.RESET}")
                return wordlist
            except Exception as e:
                print(f"{Colors.RED}[!] Error loading wordlist: {e}{Colors.RESET}")
        
        # Use default wordlist
        wordlist = default_dirs + default_files
        print(f"{Colors.YELLOW}[!] Using default wordlist ({len(wordlist)} entries){Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Create a wordlist.txt file for better results{Colors.RESET}")
        return wordlist
    
    def test_connection(self):
        """Test if target is reachable"""
        try:
            print(f"{Colors.BOLD}[*] Testing connection to {self.target}...{Colors.RESET}")
            response = self.session.get(
                self.target,
                timeout=5,
                verify=False,
                allow_redirects=True
            )
            
            if response.status_code < 400:
                print(f"{Colors.GREEN}[✓] Target is reachable! Status: {response.status_code}{Colors.RESET}")
                self.working_target = True
                return True
            else:
                print(f"{Colors.YELLOW}[!] Target returned status: {response.status_code}{Colors.RESET}")
                self.working_target = True
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"{Colors.RED}[!] Cannot connect to {self.target}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] The target may be down or unreachable{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Try: http://scanme.nmap.org or http://example.com{Colors.RESET}")
            self.working_target = False
            return False
        except Exception as e:
            print(f"{Colors.RED}[!] Connection error: {str(e)[:50]}{Colors.RESET}")
            self.working_target = False
            return False
    
    def check_robots(self):
        """Check robots.txt for disallowed paths"""
        if not self.respect_robots or not self.working_target:
            return
        
        try:
            robots_url = urljoin(self.target, '/robots.txt')
            response = self.session.get(robots_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                print(f"{Colors.GREEN}[✓] robots.txt found!{Colors.RESET}")
                for line in response.text.splitlines():
                    line = line.strip().lower()
                    if line.startswith('disallow:'):
                        path = line.replace('disallow:', '').strip()
                        if path and path != '/':
                            self.robots_disallowed.append(path)
                            print(f"{Colors.YELLOW}[!] Disallowed in robots.txt: {path}{Colors.RESET}")
            else:
                if self.verbose:
                    print(f"{Colors.YELLOW}[!] No robots.txt found{Colors.RESET}")
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Could not fetch robots.txt: {e}{Colors.RESET}")
    
    def is_false_positive(self, content, status_code):
        """Check if the response is a false positive"""
        if not content:
            return True
        
        content_lower = content.lower()
        
        # Check common false positive patterns
        for pattern in self.false_positives:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        # Check if content is too short (might be a custom 404 page)
        if len(content) < 50:
            return True
        
        # Check if content is a 404 page that returns 200
        if status_code == 200:
            if '<title>404' in content or '<title>Page Not Found' in content:
                return True
        
        return False
    
    def make_request(self, path):
        """Make a request to a path"""
        # Skip if target isn't working
        if not self.working_target:
            return None
        
        url = urljoin(self.target, path)
        
        try:
            # Add delay between requests
            if self.delay > 0:
                time.sleep(self.delay)
            
            # Make request
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=False,
                stream=True
            )
            
            # Read limited content for false positive detection
            content = response.content[:500]
            
            # Determine status code type
            status = response.status_code
            is_directory = path.endswith('/')
            
            # Store result
            with self.lock:
                self.total_requests += 1
            
            # Check for false positives
            if status == 200:
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                    if self.is_false_positive(text_content, status):
                        if self.verbose:
                            print(f"{Colors.YELLOW}[?] {status} {path} (False positive){Colors.RESET}")
                        return None
                except:
                    pass
            
            # Determine status code category
            status_color = Colors.RED
            status_label = "STATUS"
            
            if status == 200:
                status_color = Colors.GREEN
                status_label = "FOUND"
            elif status in [301, 302, 303, 307, 308]:
                status_color = Colors.CYAN
                status_label = "REDIRECT"
            elif status == 403:
                status_color = Colors.YELLOW
                status_label = "FORBIDDEN"
            elif status == 401:
                status_color = Colors.YELLOW
                status_label = "UNAUTHORIZED"
            elif status == 404:
                status_color = Colors.RED
                status_label = "NOT FOUND"
            
            # Store result
            result_data = {
                'path': path,
                'url': url,
                'status': status,
                'status_label': status_label,
                'content_length': len(response.content),
                'is_directory': is_directory,
                'redirect_url': response.url if response.history else None
            }
            
            with self.lock:
                self.results[status].append(result_data)
                if status in [200, 301, 302, 303, 307, 308, 403, 401]:
                    self.found_paths.append(result_data)
                    print(f"{status_color}[{status}] {path} ({status_label})")
                    if self.verbose and status in [301, 302]:
                        location = response.headers.get('Location', '')
                        print(f"  → {location}")
            
            return result_data
            
        except requests.exceptions.Timeout:
            if self.verbose:
                print(f"{Colors.RED}[TIMEOUT] {path}{Colors.RESET}")
            with self.lock:
                self.results['TIMEOUT'].append({'path': path, 'url': url})
            return None
        except requests.exceptions.ConnectionError:
            if self.verbose:
                print(f"{Colors.RED}[CONN ERR] {path}{Colors.RESET}")
            with self.lock:
                self.results['ERROR'].append({'path': path, 'url': url})
            return None
        except Exception as e:
            if self.verbose:
                print(f"{Colors.RED}[ERROR] {path}: {str(e)[:30]}{Colors.RESET}")
            with self.lock:
                self.results['ERROR'].append({'path': path, 'url': url, 'error': str(e)})
            return None
    
    def generate_paths(self):
        """Generate all paths to test"""
        paths = []
        
        # Add directories and files from wordlist
        for item in self.wordlist:
            # Skip if disallowed by robots.txt
            if self.respect_robots and any(item.startswith(dis) or dis in item for dis in self.robots_disallowed):
                continue
            
            # Test as directory
            paths.append(f"{item}/")
            
            # Test as file (without extension)
            paths.append(item)
            
            # Test with extensions
            for ext in self.extensions:
                paths.append(f"{item}{ext}")
        
        # Remove duplicates
        paths = list(set(paths))
        
        return paths
    
    def scan(self):
        """Start the directory scan"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] Starting Directory Scan{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print("")
        
        # Test connection first
        if not self.test_connection():
            print(f"{Colors.RED}[!] Cannot proceed with scan - target unreachable{Colors.RESET}")
            return
        
        # Check robots.txt
        self.check_robots()
        
        # Generate paths
        paths = self.generate_paths()
        total_paths = len(paths)
        print(f"{Colors.BOLD}[*] Testing {total_paths} paths{Colors.RESET}\n")
        
        # Start scanning
        self.start_time = time.time()
        completed = 0
        found = 0
        
        # Use smaller thread pool for stability
        thread_count = min(self.threads, 10)
        
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            # Submit all tasks
            futures = {executor.submit(self.make_request, path): path for path in paths}
            
            # Process results
            for future in as_completed(futures):
                completed += 1
                result = future.result()
                if result:
                    found += 1
                
                # Show progress
                if completed % 25 == 0 or completed == total_paths:
                    progress = (completed / total_paths) * 100
                    print(f"\r{Colors.YELLOW}[*] Progress: {completed}/{total_paths} ({progress:.1f}%) | Found: {found}{Colors.RESET}", end='')
        
        print()  # New line after progress
        self.scan_time = time.time() - self.start_time
    
    def generate_report(self):
        """Generate a detailed report"""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.GREEN}[✓] SCAN COMPLETE{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}[*] Duration: {self.scan_time:.2f} seconds{Colors.RESET}")
        print(f"{Colors.BOLD}[*] Total Requests: {self.total_requests}{Colors.RESET}")
        
        # Summary by status code
        print("\n" + f"{Colors.BOLD}{Colors.BLUE}[📊] RESULTS SUMMARY:{Colors.RESET}")
        print("-" * 50)
        
        status_codes = {
            200: f"{Colors.GREEN}200 OK{Colors.RESET}",
            301: f"{Colors.CYAN}301 Moved{Colors.RESET}",
            302: f"{Colors.CYAN}302 Found{Colors.RESET}",
            303: f"{Colors.CYAN}303 See Other{Colors.RESET}",
            307: f"{Colors.CYAN}307 Redirect{Colors.RESET}",
            308: f"{Colors.CYAN}308 Redirect{Colors.RESET}",
            401: f"{Colors.YELLOW}401 Unauthorized{Colors.RESET}",
            403: f"{Colors.YELLOW}403 Forbidden{Colors.RESET}",
        }
        
        has_results = False
        for status in [200, 301, 302, 303, 307, 308, 401, 403]:
            count = len(self.results.get(status, []))
            if count > 0:
                has_results = True
                label = status_codes.get(status, f"{status}")
                print(f"  {label}: {count}")
        
        # Timeout and errors
        timeout_count = len(self.results.get('TIMEOUT', []))
        error_count = len(self.results.get('ERROR', []))
        if timeout_count > 0:
            print(f"  {Colors.RED}Timeout: {timeout_count}{Colors.RESET}")
        if error_count > 0:
            print(f"  {Colors.RED}Errors: {error_count}{Colors.RESET}")
        
        if not has_results and self.working_target:
            print(f"  {Colors.YELLOW}No resources found. Try a larger wordlist.{Colors.RESET}")
        elif not self.working_target:
            print(f"  {Colors.RED}Target unreachable. Check your connection.{Colors.RESET}")
        
        # Save results to file
        self.save_results()
        
        # Print found paths
        if self.found_paths:
            print("\n" + f"{Colors.BOLD}{Colors.GREEN}[📁] FOUND PATHS:{Colors.RESET}")
            print("-" * 50)
            
            # Group by status code
            found_by_status = defaultdict(list)
            for path in self.found_paths:
                found_by_status[path['status']].append(path)
            
            for status in [200, 301, 302, 403, 401]:
                if status in found_by_status:
                    print(f"\n{Colors.BOLD}{'Status ' + str(status)}{Colors.RESET}")
                    for path in found_by_status[status]:
                        path_type = "Directory" if path['is_directory'] else "File"
                        print(f"  {path['path']} ({path_type})")
                        if status in [301, 302] and path['redirect_url']:
                            print(f"    → {path['redirect_url']}")
        
        print("\n" + "=" * 70)
        print(f"{Colors.GREEN}[✓] Results saved to: {self.output_file}{Colors.RESET}")
        print("=" * 70)
    
    def save_results(self):
        """Save results to file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("DIRECTORY SCAN RESULTS\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:        {self.target}\n")
            f.write(f"Scan Started:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if hasattr(self, 'scan_time'):
                f.write(f"Scan Duration: {self.scan_time:.2f} seconds\n")
            f.write(f"Total Requests: {self.total_requests}\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary
            f.write("SUMMARY BY STATUS CODE\n")
            f.write("-" * 50 + "\n")
            for status in [200, 301, 302, 303, 307, 308, 401, 403]:
                count = len(self.results.get(status, []))
                if count > 0:
                    f.write(f"{status}: {count}\n")
            
            # Found paths
            if self.found_paths:
                f.write("\nFOUND PATHS\n")
                f.write("-" * 50 + "\n")
                
                found_by_status = defaultdict(list)
                for path in self.found_paths:
                    found_by_status[path['status']].append(path)
                
                for status in sorted(found_by_status.keys()):
                    f.write(f"\nStatus {status}:\n")
                    for path in found_by_status[status]:
                        path_type = "Directory" if path['is_directory'] else "File"
                        f.write(f"  {path['path']} ({path_type}) - Length: {path['content_length']}\n")
                        if status in [301, 302] and path['redirect_url']:
                            f.write(f"    Redirects to: {path['redirect_url']}\n")
            else:
                f.write("\nNo paths found.\n")
            
            # Errors
            timeout_count = len(self.results.get('TIMEOUT', []))
            error_count = len(self.results.get('ERROR', []))
            if timeout_count > 0:
                f.write(f"\nTimeouts: {timeout_count}\n")
            if error_count > 0:
                f.write(f"Errors: {error_count}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n")
    
    def run(self):
        """Main execution method"""
        try:
            self.scan()
            self.generate_report()
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
        description="Web Directory & File Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test on working targets
  python directory_bruteforcer.py http://scanme.nmap.org
  python directory_bruteforcer.py http://example.com
  
  # With custom wordlist
  python directory_bruteforcer.py http://scanme.nmap.org -w wordlist.txt
  
  # With specific extensions
  python directory_bruteforcer.py http://scanme.nmap.org -e .php,.html,.txt
  
  # Local web app
  python directory_bruteforcer.py http://localhost:8080 -w wordlist.txt
        """
    )
    
    parser.add_argument('target', help='Target URL (e.g., http://example.com)')
    parser.add_argument('-w', '--wordlist', help='Wordlist file path')
    parser.add_argument('-e', '--extensions', help='Comma-separated extensions (e.g., .php,.html,.txt)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=3, help='Request timeout in seconds (default: 3)')
    parser.add_argument('--delay', type=float, default=0.2, help='Delay between requests in seconds (default: 0.2)')
    parser.add_argument('--no-follow', action='store_true', help='Do not follow redirects')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--no-robots', action='store_true', help='Do not respect robots.txt')
    parser.add_argument('-o', '--output', default='directory_scan_results.txt', help='Output file name')
    
    args = parser.parse_args()
    
    # Parse extensions
    extensions = None
    if args.extensions:
        extensions = [ext.strip() for ext in args.extensions.split(',') if ext.strip()]
    
    # Display banner
    print(f"{Colors.CYAN}{Colors.BOLD}" + "=" * 70)
    print("    WEB DIRECTORY & FILE DISCOVERY TOOL")
    print("    Project #4: Directory/File Brute-Forcing")
    print("=" * 70 + f"{Colors.RESET}\n")
    
    # Create and run scanner
    scanner = DirectoryBruteforcer(
        target=args.target,
        wordlist_path=args.wordlist,
        extensions=extensions,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        follow_redirects=not args.no_follow,
        verbose=args.verbose,
        respect_robots=not args.no_robots,
        output_file=args.output
    )
    
    scanner.run()

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()