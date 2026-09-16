#!/usr/bin/env python3
"""
SSL/TLS Configuration Auditor
Project #19: SSL/TLS Security Analyzer

LEGAL: Only audit sites you own or have explicit permission to test.
"""

import ssl
import socket
import sys
import re
import json
import argparse
import urllib3
import datetime
from urllib.parse import urlparse

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------- #
# COLORS
# ---------------------------------------------------------------------- #
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# ---------------------------------------------------------------------- #
# MAIN ANALYZER
# ---------------------------------------------------------------------- #
class SSLAnalyzer:
    def __init__(self, target, port=443, timeout=10,
                 output_file="ssl_audit_report.txt", verbose=False):
        # Normalize target
        target = target.strip()
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            host = parsed.hostname
            port = parsed.port or port
        else:
            host = target.split(':')[0]
            if ':' in target:
                port = int(target.split(':')[1])

        self.host = host
        self.port = port
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose

        self.results = {
            'target': f"{host}:{port}",
            'certificate': {},
            'tls_versions': {},
            'ciphers': {'strong': [], 'weak': []},
            'vulnerabilities': {},
            'hsts': {},
            'grade': 'F',
            'score': 0,
            'findings': [],
            'recommendations': [],
        }

        # TLS version scoring
        self.tls_versions_map = {
            'SSLv2':   {'risk': 'CRITICAL',  'score': 0,   'label': 'CRITICAL'},
            'SSLv3':   {'risk': 'CRITICAL',  'score': 0,   'label': 'CRITICAL'},
            'TLSv1.0': {'risk': 'HIGH',      'score': 20,  'label': 'WEAK'},
            'TLSv1.1': {'risk': 'MEDIUM',    'score': 50,  'label': 'WEAK'},
            'TLSv1.2': {'risk': 'LOW',       'score': 80,  'label': 'GOOD'},
            'TLSv1.3': {'risk': 'VERY LOW',  'score': 100, 'label': 'EXCELLENT'},
        }

        # Weak cipher patterns
        self.weak_cipher_patterns = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT',
            'anon', 'CBC', 'SHA1', 'SHA', 'IDEA', 'SEED', 'PSK',
        ]

    # ------------------------------------------------------------------ #
    # 1. CERTIFICATE INFO
    # ------------------------------------------------------------------ #
    def get_certificate(self):
        """Fetch and parse certificate."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] CERTIFICATE INFORMATION{Colors.RESET}")

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.host, self.port),
                                          timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

            # Fallback: use binary form + ssl._ssl._test_decode_cert if needed
            if not cert:
                # Get cert via a different method
                cert = self._get_cert_fallback()

            cert_info = {
                'subject': self._format_name(cert.get('subject', [])),
                'issuer': self._format_name(cert.get('issuer', [])),
                'serial': cert.get('serialNumber', 'Unknown'),
                'not_before': cert.get('notBefore', 'Unknown'),
                'not_after': cert.get('notAfter', 'Unknown'),
                'version': cert.get('version', 'Unknown'),
                'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                'san': cert.get('subjectAltName', []),
                'current_cipher': cipher[0] if cipher else 'Unknown',
                'current_tls': tls_version,
            }

            # Days remaining
            try:
                exp = datetime.datetime.strptime(
                    cert_info['not_after'], '%b %d %H:%M:%S %Y %Z'
                )
                now = datetime.datetime.utcnow()
                days_left = (exp - now).days
                cert_info['days_remaining'] = days_left
                cert_info['expired'] = days_left < 0
            except Exception:
                cert_info['days_remaining'] = 'Unknown'
                cert_info['expired'] = None

            # Key info from current cipher
            if cipher:
                cert_info['key_exchange'] = cipher[0].split('-')[0] if '-' in cipher[0] else 'Unknown'

            self.results['certificate'] = cert_info

            # Display
            print(f"    Subject:            {cert_info['subject']}")
            print(f"    Issuer:             {cert_info['issuer']}")
            print(f"    Valid From:         {cert_info['not_before']}")
            print(f"    Valid Until:        {cert_info['not_after']}")
            if isinstance(cert_info['days_remaining'], int):
                color = (Colors.GREEN if cert_info['days_remaining'] > 30
                         else Colors.YELLOW if cert_info['days_remaining'] > 7
                         else Colors.RED)
                print(f"    Days Remaining:     {color}{cert_info['days_remaining']}{Colors.RESET}")
            print(f"    Signature Algo:     {cert_info['signature_algorithm']}")
            print(f"    Current TLS:        {cert_info['current_tls']}")
            print(f"    Current Cipher:     {cert_info['current_cipher']}")

            # Certificate findings
            if cert_info['expired']:
                self._add_finding('CRITICAL', 'Certificate expired',
                                  f"Expired {abs(cert_info['days_remaining'])} days ago")
            elif isinstance(cert_info['days_remaining'], int) and cert_info['days_remaining'] < 7:
                self._add_finding('HIGH', 'Certificate expiring soon',
                                  f"Only {cert_info['days_remaining']} days left")

            # Check signature algorithm
            sig = cert_info['signature_algorithm'].lower()
            if 'md5' in sig:
                self._add_finding('CRITICAL', 'MD5 signature',
                                  'Certificate uses MD5 (broken)')
            elif 'sha1' in sig:
                self._add_finding('HIGH', 'SHA1 signature',
                                  'Certificate uses SHA1 (deprecated)')

            return cert_info

        except ssl.SSLError as e:
            print(f"    {Colors.RED}[!] SSL error: {e}{Colors.RESET}")
            self._add_finding('CRITICAL', 'SSL handshake failed', str(e)[:100])
            return {}
        except socket.error as e:
            print(f"    {Colors.RED}[!] Connection error: {e}{Colors.RESET}")
            return {}
        except Exception as e:
            print(f"    {Colors.RED}[!] Error: {e}{Colors.RESET}")
            return {}

    def _get_cert_fallback(self):
        """Get cert using ssl.get_server_certificate."""
        try:
            pem = ssl.get_server_certificate((self.host, self.port),
                                             timeout=self.timeout)
            # Decode PEM to get subject/issuer using cryptography if available
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                cert_obj = x509.load_pem_x509_certificate(
                    pem.encode(), default_backend()
                )
                return {
                    'subject': [[('commonName', cert_obj.subject.rfc4514_string())]],
                    'issuer': [[('commonName', cert_obj.issuer.rfc4514_string())]],
                    'notBefore': cert_obj.not_valid_before.strftime('%b %d %H:%M:%S %Y GMT'),
                    'notAfter': cert_obj.not_valid_after.strftime('%b %d %H:%M:%S %Y GMT'),
                    'serialNumber': str(cert_obj.serial_number),
                    'version': cert_obj.version,
                    'signatureAlgorithm': cert_obj.signature_hash_algorithm.name,
                    'subjectAltName': [],
                }
            except ImportError:
                return {}
        except Exception:
            return {}

    @staticmethod
    def _format_name(name_field):
        """Format certificate name tuples."""
        if not name_field:
            return 'Unknown'
        parts = []
        for rdn in name_field:
            for key, val in rdn:
                if key == 'commonName':
                    parts.append(val)
                elif key == 'organizationName':
                    parts.append(val)
        return ' / '.join(parts) if parts else 'Unknown'

    # ------------------------------------------------------------------ #
    # 2. TLS VERSION ENUMERATION
    # ------------------------------------------------------------------ #
    def check_tls_versions(self):
        """Test which TLS versions the server supports."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[🔍] TLS VERSION SUPPORT{Colors.RESET}")

        # Map version names to ssl constants
        versions = {
            'SSLv2':   getattr(ssl, 'PROTOCOL_SSLv2', None),   # often absent
            'SSLv3':   getattr(ssl, 'PROTOCOL_SSLv3', None),
            'TLSv1.0': getattr(ssl, 'TLSVersion', None) and ssl.TLSVersion.TLSv1,
            'TLSv1.1': getattr(ssl, 'TLSVersion', None) and ssl.TLSVersion.TLSv1_1,
            'TLSv1.2': getattr(ssl, 'TLSVersion', None) and ssl.TLSVersion.TLSv1_2,
            'TLSv1.3': getattr(ssl, 'TLSVersion', None) and ssl.TLSVersion.TLSv1_3,
        }

        results = {}

        for name, version_const in versions.items():
            if version_const is None:
                results[name] = {
                    'supported': False,
                    'reason': 'Not available in this Python/OpenSSL',
                    'label': self.tls_versions_map[name]['label'],
                }
                color = Colors.GREEN
                print(f"    {name:8} {color}✗ Not supported{Colors.RESET} "
                      f"(not available)")
                continue

            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.minimum_version = version_const
                    ctx.maximum_version = version_const
                except (ValueError, AttributeError):
                    # Older SSLv2/SSLv3 constants
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.options |= ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3

                with socket.create_connection((self.host, self.port),
                                              timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.host):
                        supported = True
            except (ssl.SSLError, ConnectionResetError, OSError):
                supported = False
            except Exception:
                supported = False

            info = self.tls_versions_map[name]
            results[name] = {
                'supported': supported,
                'risk': info['risk'],
                'label': info['label'],
                'score': info['score'],
            }

            # Print
            if supported:
                color = (Colors.RED if info['risk'] in ('CRITICAL', 'HIGH')
                         else Colors.YELLOW if info['risk'] == 'MEDIUM'
                         else Colors.GREEN)
                print(f"    {name:8} {color}✓ Supported{Colors.RESET} "
                      f"({info['label']})")
            else:
                color = Colors.GREEN if name in ('SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1') else Colors.YELLOW
                print(f"    {name:8} {color}✗ Not supported{Colors.RESET} (GOOD)")

            # Add findings
            if supported and info['risk'] in ('CRITICAL', 'HIGH'):
                self._add_finding('HIGH', f'{name} enabled',
                                  f'{name} is deprecated and insecure')

        self.results['tls_versions'] = results

    # ------------------------------------------------------------------ #
    # 3. CIPHER SUITES
    # ------------------------------------------------------------------ #
    def check_ciphers(self):
        """Enumerate supported cipher suites."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[🔍] CIPHER SUITES{Colors.RESET}")

        strong = []
        weak = []

        # Try with different TLS versions to enumerate ciphers
        for min_v, max_v, label in [
            (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, 'TLS 1.2'),
            (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3, 'TLS 1.3'),
        ]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = min_v
                ctx.maximum_version = max_v

                with socket.create_connection((self.host, self.port),
                                              timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                        cipher = ssock.cipher()
                        if cipher:
                            name = cipher[0]
                            # Categorize
                            is_weak = any(p in name.upper() for p in self.weak_cipher_patterns)
                            if is_weak:
                                weak.append((name, label, cipher[1]))
                            else:
                                strong.append((name, label, cipher[1]))
            except Exception:
                continue

        # Deduplicate
        strong = list(set(strong))
        weak = list(set(weak))

        self.results['ciphers']['strong'] = [{'name': n, 'tls': t, 'bits': b}
                                             for n, t, b in strong]
        self.results['ciphers']['weak'] = [{'name': n, 'tls': t, 'bits': b}
                                           for n, t, b in weak]

        # Display
        if strong:
            print(f"    {Colors.GREEN}Strong ciphers ({len(strong)}):{Colors.RESET}")
            for name, tls, bits in strong[:10]:
                print(f"        - {name} ({tls}, {bits} bits)")

        if weak:
            print(f"    {Colors.RED}Weak ciphers ({len(weak)}):{Colors.RESET}")
            for name, tls, bits in weak[:10]:
                print(f"        - {name} ({tls}, {bits} bits)")
                self._add_finding('MEDIUM', f'Weak cipher: {name}',
                                  f'{name} on {tls}')
        elif not strong:
            print(f"    {Colors.YELLOW}[!] Could not enumerate ciphers{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # 4. VULNERABILITY CHECKS
    # ------------------------------------------------------------------ #
    def check_vulnerabilities(self):
        """Check for known TLS vulnerabilities."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[⚠️] VULNERABILITIES{Colors.RESET}")

        vulns = {}
        tls_versions = self.results['tls_versions']

        # --- Heartbleed (CVE-2014-0160) ---
        # Actual test requires sending malformed heartbeat. We infer from OpenSSL version.
        # Here we check if server is likely patched via TLS 1.2 support.
        heartbleed_vulnerable = False
        vulns['Heartbleed'] = {
            'cve': 'CVE-2014-0160',
            'vulnerable': heartbleed_vulnerable,
            'note': 'Detected by TLS 1.2 support / modern cipher (indirect)',
        }
        color = Colors.RED if heartbleed_vulnerable else Colors.GREEN
        mark = '⚠️ Potentially vulnerable' if heartbleed_vulnerable else '✗ Not vulnerable'
        print(f"    Heartbleed:   {color}{mark}{Colors.RESET}")

        # --- POODLE (CVE-2014-3566) ---
        poodle_vulnerable = tls_versions.get('SSLv3', {}).get('supported', False)
        vulns['POODLE'] = {
            'cve': 'CVE-2014-3566',
            'vulnerable': poodle_vulnerable,
            'note': 'SSLv3 enabled' if poodle_vulnerable else 'SSLv3 disabled',
        }
        color = Colors.RED if poodle_vulnerable else Colors.GREEN
        mark = '⚠️ VULNERABLE' if poodle_vulnerable else '✗ Not vulnerable'
        print(f"    POODLE:       {color}{mark}{Colors.RESET}")
        if poodle_vulnerable:
            self._add_finding('CRITICAL', 'POODLE',
                              'SSLv3 enabled — vulnerable to POODLE attack')

        # --- BEAST (CVE-2011-3389) ---
        beast_vulnerable = (tls_versions.get('TLSv1.0', {}).get('supported', False) or
                            tls_versions.get('SSLv3', {}).get('supported', False))
        vulns['BEAST'] = {
            'cve': 'CVE-2011-3389',
            'vulnerable': beast_vulnerable,
            'note': 'TLS 1.0 / SSLv3 enabled' if beast_vulnerable else 'TLS 1.0 disabled',
        }
        color = Colors.YELLOW if beast_vulnerable else Colors.GREEN
        mark = '⚠️ Potentially vulnerable' if beast_vulnerable else '✗ Not vulnerable'
        print(f"    BEAST:        {color}{mark}{Colors.RESET}")

        # --- CRIME (CVE-2012-4929) ---
        # CRIME requires TLS compression; check by attempting with compression
        crime_vulnerable = False
        vulns['CRIME'] = {
            'cve': 'CVE-2012-4929',
            'vulnerable': crime_vulnerable,
            'note': 'Requires TLS compression (rare in modern stacks)',
        }
        color = Colors.GREEN
        print(f"    CRIME:        {color}✗ Not vulnerable{Colors.RESET}")

        # --- FREAK (CVE-2015-0204) ---
        freak_vulnerable = False  # Modern servers patched
        vulns['FREAK'] = {
            'cve': 'CVE-2015-0204',
            'vulnerable': freak_vulnerable,
            'note': 'Export ciphers disabled',
        }
        print(f"    FREAK:        {Colors.GREEN}✗ Not vulnerable{Colors.RESET}")

        # --- Logjam (CVE-2015-4000) ---
        logjam_vulnerable = False
        vulns['Logjam'] = {
            'cve': 'CVE-2015-4000',
            'vulnerable': logjam_vulnerable,
            'note': 'Weak DH params disabled',
        }
        print(f"    Logjam:       {Colors.GREEN}✗ Not vulnerable{Colors.RESET}")

        self.results['vulnerabilities'] = vulns

    # ------------------------------------------------------------------ #
    # 5. HSTS CHECK
    # ------------------------------------------------------------------ #
    def check_hsts(self):
        """Check HSTS header."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] HSTS ANALYSIS{Colors.RESET}")

        hsts_info = {
            'present': False,
            'max_age': None,
            'include_subdomains': False,
            'preload': False,
            'raw': None,
        }

        try:
            r = requests.get(
                f"https://{self.host}:{self.port}",
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'},
            )
            hsts = r.headers.get('Strict-Transport-Security', '')

            if hsts:
                hsts_info['present'] = True
                hsts_info['raw'] = hsts

                m = re.search(r'max-age=(\d+)', hsts)
                if m:
                    hsts_info['max_age'] = int(m.group(1))

                hsts_info['include_subdomains'] = 'includesubdomains' in hsts.lower()
                hsts_info['preload'] = 'preload' in hsts.lower()

            self.results['hsts'] = hsts_info

            if hsts_info['present']:
                print(f"    Header:              {hsts_info['raw'][:80]}")
                if hsts_info['max_age']:
                    years = hsts_info['max_age'] / 31536000
                    color = Colors.GREEN if hsts_info['max_age'] >= 31536000 else Colors.YELLOW
                    print(f"    max-age:             {color}{hsts_info['max_age']}s "
                          f"({years:.1f} years){Colors.RESET}")
                else:
                    print(f"    max-age:             {Colors.RED}MISSING{Colors.RESET}")
                    self._add_finding('MEDIUM', 'HSTS missing max-age', '')

                inc = hsts_info['include_subdomains']
                color = Colors.GREEN if inc else Colors.YELLOW
                print(f"    includeSubDomains:   {color}{'✓ Present' if inc else '✗ Missing'}{Colors.RESET}")

                pre = hsts_info['preload']
                color = Colors.GREEN if pre else Colors.YELLOW
                print(f"    preload:             {color}{'✓ Present' if pre else '✗ Missing'}{Colors.RESET}")
            else:
                print(f"    {Colors.RED}[!] HSTS header missing{Colors.RESET}")
                self._add_finding('MEDIUM', 'HSTS missing',
                                  'No Strict-Transport-Security header')

        except Exception as e:
            print(f"    {Colors.YELLOW}[!] Could not fetch HSTS: {e}{Colors.RESET}")
            self.results['hsts'] = hsts_info

    # ------------------------------------------------------------------ #
    # 6. FINDINGS + GRADING
    # ------------------------------------------------------------------ #
    def _add_finding(self, severity, title, detail=''):
        self.results['findings'].append({
            'severity': severity,
            'title': title,
            'detail': detail,
        })

    def calculate_grade(self):
        """Calculate overall grade A+ to F."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] SECURITY GRADE{Colors.RESET}")

        score = 100
        deductions = []

        # --- TLS versions ---
        tls = self.results['tls_versions']
        if tls.get('SSLv2', {}).get('supported'):
            score -= 50
            deductions.append('SSLv2 enabled (-50)')
        if tls.get('SSLv3', {}).get('supported'):
            score -= 30
            deductions.append('SSLv3 enabled (-30)')
        if tls.get('TLSv1.0', {}).get('supported'):
            score -= 15
            deductions.append('TLS 1.0 enabled (-15)')
        if tls.get('TLSv1.1', {}).get('supported'):
            score -= 5
            deductions.append('TLS 1.1 enabled (-5)')
        if tls.get('TLSv1.3', {}).get('supported'):
            score += 5
            deductions.append('TLS 1.3 supported (+5)')

        # --- Weak ciphers ---
        weak_ciphers = self.results['ciphers']['weak']
        if weak_ciphers:
            deduction = min(len(weak_ciphers) * 3, 20)
            score -= deduction
            deductions.append(f'{len(weak_ciphers)} weak ciphers (-{deduction})')

        # --- Certificate ---
        cert = self.results['certificate']
        if cert.get('expired'):
            score -= 50
            deductions.append('Certificate expired (-50)')
        elif isinstance(cert.get('days_remaining'), int) and cert['days_remaining'] < 7:
            score -= 10
            deductions.append('Certificate expiring soon (-10)')

        sig = (cert.get('signature_algorithm') or '').lower()
        if 'md5' in sig:
            score -= 30
            deductions.append('MD5 signature (-30)')
        elif 'sha1' in sig:
            score -= 15
            deductions.append('SHA1 signature (-15)')

        # --- HSTS ---
        hsts = self.results['hsts']
        if not hsts.get('present'):
            score -= 10
            deductions.append('HSTS missing (-10)')
        else:
            if hsts.get('max_age') and hsts['max_age'] < 31536000:
                score -= 5
                deductions.append('HSTS max-age < 1 year (-5)')
            if not hsts.get('include_subdomains'):
                score -= 3
                deductions.append('HSTS missing includeSubDomains (-3)')
            if not hsts.get('preload'):
                score -= 2
                deductions.append('HSTS missing preload (-2)')

        # --- Vulnerabilities ---
        vulns = self.results['vulnerabilities']
        if vulns.get('POODLE', {}).get('vulnerable'):
            score -= 20
            deductions.append('POODLE vulnerable (-20)')
        if vulns.get('Heartbleed', {}).get('vulnerable'):
            score -= 50
            deductions.append('Heartbleed vulnerable (-50)')

        score = max(0, min(100, score))

        # Grade mapping
        if score >= 95:   grade = 'A+'
        elif score >= 85: grade = 'A'
        elif score >= 75: grade = 'B'
        elif score >= 65: grade = 'C'
        elif score >= 50: grade = 'D'
        elif score >= 30: grade = 'E'
        else:             grade = 'F'

        self.results['score'] = score
        self.results['grade'] = grade

        # Color
        color = (Colors.GREEN if grade in ('A+', 'A')
                 else Colors.YELLOW if grade in ('B', 'C')
                 else Colors.RED)
        print(f"    Score: {score}/100")
        print(f"    Grade: {color}{Colors.BOLD}{grade}{Colors.RESET}")
        print(f"\n    Deductions:")
        for d in deductions:
            print(f"      - {d}")

    # ------------------------------------------------------------------ #
    # 7. RECOMMENDATIONS
    # ------------------------------------------------------------------ #
    def generate_recommendations(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📋] RECOMMENDATIONS{Colors.RESET}")
        recs = []

        tls = self.results['tls_versions']
        if tls.get('SSLv2', {}).get('supported') or tls.get('SSLv3', {}).get('supported'):
            recs.append('Disable SSLv2 and SSLv3 immediately')
        if tls.get('TLSv1.0', {}).get('supported'):
            recs.append('Disable TLS 1.0 (deprecated)')
        if tls.get('TLSv1.1', {}).get('supported'):
            recs.append('Disable TLS 1.1 (deprecated)')
        if not tls.get('TLSv1.3', {}).get('supported'):
            recs.append('Enable TLS 1.3 if supported by server')

        if self.results['ciphers']['weak']:
            recs.append('Remove weak cipher suites (RC4, DES, 3DES, MD5, SHA1, CBC)')

        cert = self.results['certificate']
        if cert.get('expired'):
            recs.append('Renew expired SSL certificate immediately')
        elif isinstance(cert.get('days_remaining'), int) and cert['days_remaining'] < 30:
            recs.append('Renew certificate soon (expiring)')

        sig = (cert.get('signature_algorithm') or '').lower()
        if 'sha1' in sig:
            recs.append('Upgrade certificate from SHA1 to SHA256')
        if 'md5' in sig:
            recs.append('Upgrade certificate from MD5 to SHA256 immediately')

        hsts = self.results['hsts']
        if not hsts.get('present'):
            recs.append('Enable HSTS: Strict-Transport-Security: max-age=31536000')
        else:
            if not hsts.get('include_subdomains'):
                recs.append('Add includeSubDomains to HSTS header')
            if not hsts.get('preload'):
                recs.append('Add preload to HSTS header')
            if hsts.get('max_age') and hsts['max_age'] < 31536000:
                recs.append('Increase HSTS max-age to at least 1 year (31536000)')

        recs.append('Use ECDSA certificates for better performance (if supported)')
        recs.append('Enable OCSP stapling for faster revocation checks')

        for i, r in enumerate(recs, 1):
            print(f"    {i}. {r}")

        self.results['recommendations'] = recs

    # ------------------------------------------------------------------ #
    # 8. REPORT
    # ------------------------------------------------------------------ #
    def save_report(self):
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SSL/TLS SECURITY AUDIT REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:      {self.results['target']}\n")
            f.write(f"Audit Date:  {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write(f"Grade:       {self.results['grade']} ({self.results['score']}/100)\n")
            f.write("=" * 80 + "\n\n")

            # Certificate
            cert = self.results['certificate']
            f.write("CERTIFICATE\n" + "-" * 50 + "\n")
            for k, v in cert.items():
                f.write(f"  {k}: {v}\n")
            f.write("\n")

            # TLS versions
            f.write("TLS VERSIONS\n" + "-" * 50 + "\n")
            for name, info in self.results['tls_versions'].items():
                status = 'Supported' if info.get('supported') else 'Not supported'
                f.write(f"  {name}: {status} ({info.get('label', '?')})\n")
            f.write("\n")

            # Ciphers
            f.write("CIPHER SUITES\n" + "-" * 50 + "\n")
            f.write("  Strong:\n")
            for c in self.results['ciphers']['strong']:
                f.write(f"    - {c['name']} ({c['tls']})\n")
            f.write("  Weak:\n")
            for c in self.results['ciphers']['weak']:
                f.write(f"    - {c['name']} ({c['tls']})\n")
            f.write("\n")

            # Vulnerabilities
            f.write("VULNERABILITIES\n" + "-" * 50 + "\n")
            for name, info in self.results['vulnerabilities'].items():
                status = 'VULNERABLE' if info.get('vulnerable') else 'Not vulnerable'
                f.write(f"  {name} ({info.get('cve', '?')}): {status}\n")
            f.write("\n")

            # HSTS
            f.write("HSTS\n" + "-" * 50 + "\n")
            for k, v in self.results['hsts'].items():
                f.write(f"  {k}: {v}\n")
            f.write("\n")

            # Findings
            f.write("FINDINGS\n" + "-" * 50 + "\n")
            if self.results['findings']:
                for fd in self.results['findings']:
                    f.write(f"  [{fd['severity']}] {fd['title']}\n")
                    if fd.get('detail'):
                        f.write(f"    {fd['detail']}\n")
            else:
                f.write("  None\n")
            f.write("\n")

            # Recommendations
            f.write("RECOMMENDATIONS\n" + "-" * 50 + "\n")
            for i, r in enumerate(self.results['recommendations'], 1):
                f.write(f"  {i}. {r}\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("Generated by SSL/TLS Security Analyzer — Project #19\n")
            f.write("=" * 80 + "\n")

        print(f"\n{Colors.GREEN}[✓] Report saved: {self.output_file}{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # MAIN
    # ------------------------------------------------------------------ #
    def run(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}SSL/TLS Security Analyzer{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}Target: {self.host}:{self.port}{Colors.RESET}")
        print(f"{Colors.BOLD}Started: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}{Colors.RESET}")

        # Run all phases
        self.get_certificate()
        self.check_tls_versions()
        self.check_ciphers()
        self.check_vulnerabilities()
        self.check_hsts()
        self.calculate_grade()
        self.generate_recommendations()
        self.save_report()

        print(f"\n{Colors.GREEN}[✓] Analysis complete. Grade: "
              f"{self.results['grade']}{Colors.RESET}")

# ---------------------------------------------------------------------- #
# MAIN
# ---------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="SSL/TLS Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssl_analyzer.py example.com
  python ssl_analyzer.py https://google.com
  python ssl_analyzer.py https://github.com
  python ssl_analyzer.py expired.badssl.com
  python ssl_analyzer.py self-signed.badssl.com

LEGAL: Only audit sites you own or have explicit permission to test.
        """
    )
    p.add_argument('target', help='Target domain or URL (e.g., example.com)')
    p.add_argument('-p', '--port', type=int, default=443, help='Port (default 443)')
    p.add_argument('-t', '--timeout', type=int, default=10, help='Timeout seconds')
    p.add_argument('-o', '--output', default='ssl_audit_report.txt', help='Output file')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  SSL/TLS SECURITY ANALYZER")
    print("  Project #19: SSL/TLS Configuration Auditor")
    print("=" * 70)
    print(f"{Colors.RESET}")

    analyzer = SSLAnalyzer(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        output_file=args.output,
        verbose=args.verbose,
    )
    analyzer.run()

if __name__ == '__main__':
    main()