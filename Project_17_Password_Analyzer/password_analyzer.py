#!/usr/bin/env python3
"""
Password Cracking & Hash Analysis Tool
Project #17: Password Security Analyzer (FIXED)

EDUCATIONAL USE ONLY — test only hashes you own!
"""

import hashlib
import itertools
import re
import sys
import time
import math
import argparse
import string
import os
from datetime import datetime

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
# BUILT-IN WORDLIST (expanded — 500+ entries)
# ---------------------------------------------------------------------- #
BUILTIN_WORDLIST = [
    # Top 100 most common passwords
    'password', '123456', '12345678', 'qwerty', 'abc123',
    'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
    'baseball', '111111', 'iloveyou', 'master', 'sunshine',
    'ashley', 'bailey', 'passw0rd', 'shadow', '123123',
    '654321', 'superman', 'qazwsx', 'michael', 'football',
    'welcome', 'jesus', 'ninja', 'mustang', 'password1',
    'admin', 'root', 'toor', 'test', 'guest', 'user', 'login',
    'pass', 'changeme', 'letmein123', 'hello', 'hello123',
    'hello1234', 'test123', 'test1234', 'admin123', 'admin1234',
    'root123', 'root1234', 'qwerty123', 'qwerty1234',
    '123456789', '1234567890', '1q2w3e4r', '1qaz2wsx',
    'zaq12wsx', 'qazwsxedc', 'P@ssw0rd', 'P@ssword123',
    'Password123', 'Password123!', 'Welcome123', 'Welcome@123',
    'Admin@123', 'Root@123',

    # Passwords with numbers (the missing ones!)
    'password123', 'password1234', 'password12345',
    'password1', 'password12', 'password123456',
    'pass123', 'pass1234', 'passw0rd123',
    'p@ssword', 'p@ssw0rd', 'p@ssword123', 'p@ssw0rd123',
    'password!', 'password@123', 'password#123',
    'mypassword', 'mypassword123', 'myp@ssword',
    'secret', 'secret123', 'secret1234',
    'passw0rd!', 'passw0rd1',
    'letmein1', 'letmein12', 'letmein1234',
    'welcome1', 'welcome12', 'welcome123', 'welcome1234',
    'admin1', 'admin12', 'adminadmin', 'administrator',
    'root1', 'root12', 'rootpass', 'toor123',
    'guest123', 'guest1234', 'user123', 'user1234',

    # Names + numbers
    'michael1', 'michael123', 'jennifer', 'jennifer1',
    'jessica', 'jessica1', 'daniel', 'daniel1',
    'thomas', 'thomas1', 'robert', 'robert1',
    'william', 'william1', 'matthew', 'matthew1',
    'joshua', 'joshua1', 'andrew', 'andrew1',
    'joseph', 'joseph1', 'charles', 'charles1',

    # Common words + numbers
    'monkey1', 'monkey123', 'dragon1', 'dragon123',
    'master1', 'master123', 'shadow1', 'shadow123',
    'superman1', 'batman', 'batman1', 'ironman',
    'spiderman', 'starwars', 'startrek', 'pokemon',
    'computer', 'computer1', 'internet', 'internet1',
    'samsung', 'samsung1', 'iphone', 'iphone1',
    'google', 'google1', 'facebook', 'facebook1',
    'twitter', 'twitter1', 'instagram', 'linkedin',
    'youtube', 'youtube1', 'whatsapp', 'telegram',
    'android', 'android1', 'windows', 'windows1',
    'linux', 'linux1', 'ubuntu', 'debian',

    # Sports/teams
    'football1', 'baseball1', 'basketball', 'soccer',
    'hockey', 'hockey1', 'tennis', 'tennis1',
    'golf', 'golf1', 'cricket', 'cricket1',
    'arsenal', 'chelsea', 'liverpool', 'barcelona',
    'realmadrid', 'manutd', 'mancity',

    # Common patterns
    'abcd1234', 'abcd123', 'qwertyuiop', 'qwertyui',
    'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
    '1q2w3e', '1q2w3e4r5t', 'qazwsx123', 'qwerty12345',
    'aaaaaa', 'bbbbbb', 'cccccc', '11111111', '22222222',
    '000000', '00000000', '121212', '131313', '999999',
    '123321', '123654', '321321', '456789', '789456',
    'abcdef', 'abcdefg', 'abcdefgh', 'abcdef123',

    # Love/relationship
    'iloveyou1', 'iloveyou2', 'iloveyou123',
    'love', 'love123', 'love1234', 'loveme', 'loveme1',
    'baby', 'baby123', 'babygirl', 'babyboy',
    'sweetheart', 'honey', 'honey123', 'darling',

    # Animals
    'monkey12', 'tiger', 'tiger123', 'lion', 'lion123',
    'eagle', 'eagle123', 'shark', 'shark123', 'wolf',
    'wolf123', 'fox', 'fox123', 'bear', 'bear123',
    'cat', 'cat123', 'dog', 'dog123', 'horse', 'horse123',
    'rabbit', 'rabbit1', 'dolphin', 'dolphin1',
    'elephant', 'elephant1', 'penguin', 'penguin1',

    # Numbers only
    '1234', '12345', '1234567', '123456789',
    '1111', '2222', '3333', '4444', '5555',
    '6666', '7777', '8888', '9999', '0000',
    '111111', '222222', '333333', '444444',

    # Short passwords
    'abc', 'abcd', 'abcde', 'abcdef',
    'aaa', 'aaaa', 'aaaaa',
    'xyz', 'xyz123', 'test12',
    'qwe', 'qwe123', 'qwer', 'qwer1234',

    # Leaked passwords from breaches
    'sunshine1', 'princess', 'princess1', 'football',
    'charlie', 'charlie1', 'aa123456', 'donald',
    'password0', 'qwerty1', 'zxcvbnm1', 'asdfghjkl1',
    '1qaz2wsx3edc', 'monkey12', 'dragon12',
    'michael123', 'shadow123', 'master12',

    # Common phrases
    'letmein1', 'openup', 'opensesame',
    'trustno1', 'noneofyourbusiness',
    'donttellanyone', 'youllneverguess',
    'secretpass', 'topsecret',

    # Numbers with letters
    'a123456', 'b123456', 'c123456',
    'a1b2c3', 'a1b2c3d4', 'x1y2z3',
    'pass1', 'pass12', 'pass123',

    # Simple patterns
    'password!', 'password@', 'password#',
    'pass!', 'pass@', 'pass#',
    'admin!', 'admin@', 'admin#',
    'root!', 'root@', 'root#',
    '123!', '123@', '123#',
]

# ---------------------------------------------------------------------- #
# MAIN CLASS
# ---------------------------------------------------------------------- #
class PasswordAnalyzer:
    def __init__(self, output_file="password_analysis_report.txt", verbose=False):
        self.output_file = output_file
        self.verbose = verbose
        self.results = {
            'hash': None,
            'hash_type': None,
            'cracked': False,
            'password': None,
            'method': None,
            'time_taken': None,
            'attempts': 0,
            'strength': {},
            'recommendations': [],
        }

        # Hash detection patterns
        self.hash_patterns = {
            'bcrypt': r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$',
            'MySQL': r'^\*[A-F0-9]{40}$',
            'MD5': r'^[a-f0-9]{32}$',
            'NTLM': r'^[a-f0-9]{32}$',
            'SHA1': r'^[a-f0-9]{40}$',
            'SHA256': r'^[a-f0-9]{64}$',
            'SHA3-256': r'^[a-f0-9]{64}$',
            'SHA512': r'^[a-f0-9]{128}$',
        }

        self.common_passwords = BUILTIN_WORDLIST

    # ------------------------------------------------------------------ #
    # HASH TYPE IDENTIFICATION
    # ------------------------------------------------------------------ #
    def identify_hash(self, hash_string, forced_algorithm=None):
        """Identify hash type by pattern + length. If forced, return that."""
        h = hash_string.strip()

        if forced_algorithm:
            return f'{forced_algorithm.upper()} (forced)'

        if h.startswith('*'):
            if re.match(self.hash_patterns['MySQL'], h):
                return 'MySQL'
            return 'Unknown (malformed MySQL)'

        if h.startswith('$2'):
            if re.match(self.hash_patterns['bcrypt'], h):
                return 'bcrypt'
            return 'Unknown (malformed bcrypt)'

        if not re.match(r'^[a-fA-F0-9]+$', h):
            return 'Unknown (not hex)'

        length = len(h)
        if length == 32:
            return 'MD5 or NTLM'
        elif length == 40:
            return 'SHA1'
        elif length == 64:
            return 'SHA256 or SHA3-256'
        elif length == 128:
            return 'SHA512'
        else:
            return f'Unknown (length {length})'

    def hash_string(self, text, algorithm='md5'):
        algo = algorithm.lower()
        if algo == 'md5':
            return hashlib.md5(text.encode()).hexdigest()
        elif algo == 'sha1':
            return hashlib.sha1(text.encode()).hexdigest()
        elif algo == 'sha256':
            return hashlib.sha256(text.encode()).hexdigest()
        elif algo == 'sha3-256':
            return hashlib.sha3_256(text.encode()).hexdigest()
        elif algo == 'sha512':
            return hashlib.sha512(text.encode()).hexdigest()
        elif algo == 'ntlm':
            try:
                return hashlib.new('md4', text.encode('utf-16le')).hexdigest()
            except Exception:
                # Fallback: use MD4 if available, else raise
                raise ValueError("MD4 not available in this Python build")
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    # ------------------------------------------------------------------ #
    # DICTIONARY ATTACK
    # ------------------------------------------------------------------ #
    def dictionary_attack(self, target_hash, wordlist_path=None, algorithm='md5'):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[🔍] DICTIONARY ATTACK{Colors.RESET}")

        # --- Load wordlist ---
        if wordlist_path:
            if not os.path.exists(wordlist_path):
                print(f"{Colors.RED}[!] Wordlist not found: {wordlist_path}{Colors.RESET}")
                print(f"{Colors.YELLOW}[!] Aborting dictionary attack.{Colors.RESET}")
                return {
                    'success': False, 'time': 0, 'attempts': 0,
                    'wordlist_size': 0, 'error': 'wordlist_not_found'
                }
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    words = [line.strip() for line in f if line.strip()]
                print(f"    Wordlist: {wordlist_path} ({len(words)} entries)")
            except Exception as e:
                print(f"{Colors.RED}[!] Cannot read wordlist: {e}{Colors.RESET}")
                return {
                    'success': False, 'time': 0, 'attempts': 0,
                    'wordlist_size': 0, 'error': 'wordlist_read_error'
                }
        else:
            words = self.common_passwords
            print(f"    Wordlist: built-in ({len(words)} entries)")

        print(f"    Testing...")

        start = time.time()
        target = target_hash.lower()
        attempts = 0

        for i, word in enumerate(words, 1):
            attempts += 1
            if self.hash_string(word, algorithm) == target:
                elapsed = time.time() - start
                print(f"    {Colors.GREEN}[✓] CRACKED! Password: \"{word}\" "
                      f"(found at line {i}, {elapsed:.2f}s){Colors.RESET}")
                return {
                    'success': True,
                    'password': word,
                    'method': 'dictionary',
                    'time': elapsed,
                    'attempts': attempts,
                    'wordlist_size': len(words),
                }

            if i % 5000 == 0 and self.verbose:
                print(f"    ... tested {i} words")

        elapsed = time.time() - start
        print(f"    {Colors.RED}[✗] Not found in wordlist "
              f"({attempts} attempts, {elapsed:.2f}s){Colors.RESET}")
        return {
            'success': False,
            'time': elapsed,
            'attempts': attempts,
            'wordlist_size': len(words),
        }

    # ------------------------------------------------------------------ #
    # BRUTE-FORCE ATTACK
    # ------------------------------------------------------------------ #
    def brute_force_attack(self, target_hash, algorithm='md5',
                           charset='lower', max_length=4, timeout=60):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[🔍] BRUTE-FORCE ATTACK{Colors.RESET}")

        charsets = {
            'lower': string.ascii_lowercase,
            'upper': string.ascii_uppercase,
            'digits': string.digits,
            'alnum': string.ascii_letters + string.digits,
            'all': string.ascii_letters + string.digits + string.punctuation,
        }
        chars = charsets.get(charset, charset)

        print(f"    Charset: {charset} ({len(chars)} chars)")
        print(f"    Max length: {max_length}")
        print(f"    Timeout: {timeout}s")
        print(f"    Testing...")

        start = time.time()
        target = target_hash.lower()
        attempts = 0
        last_report = 0

        try:
            for length in range(1, max_length + 1):
                for combo in itertools.product(chars, repeat=length):
                    attempts += 1
                    candidate = ''.join(combo)

                    if self.hash_string(candidate, algorithm) == target:
                        elapsed = time.time() - start
                        print(f"    {Colors.GREEN}[✓] CRACKED! Password: \"{candidate}\" "
                              f"({elapsed:.2f}s, {attempts} attempts){Colors.RESET}")
                        return {
                            'success': True,
                            'password': candidate,
                            'method': 'brute-force',
                            'time': elapsed,
                            'attempts': attempts,
                        }

                    # Progress + timeout check every 50k
                    if attempts - last_report >= 50000:
                        elapsed = time.time() - start
                        rate = attempts / elapsed if elapsed > 0 else 0
                        print(f"    ... {attempts:,} tested ({rate:,.0f}/s)")
                        last_report = attempts

                        if elapsed > timeout:
                            raise TimeoutError()

        except TimeoutError:
            elapsed = time.time() - start
            print(f"    {Colors.YELLOW}[!] Timeout after {elapsed:.1f}s "
                  f"({attempts:,} attempts){Colors.RESET}")
            return {
                'success': False,
                'time': elapsed,
                'attempts': attempts,
                'reason': 'timeout',
            }

        elapsed = time.time() - start
        print(f"    {Colors.RED}[✗] Not found ({attempts:,} attempts, {elapsed:.2f}s){Colors.RESET}")
        return {
            'success': False,
            'time': elapsed,
            'attempts': attempts,
        }

    # ------------------------------------------------------------------ #
    # STRENGTH ANALYSIS
    # ------------------------------------------------------------------ #
    def analyze_strength(self, password):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PASSWORD STRENGTH ANALYSIS{Colors.RESET}")

        analysis = {
            'password': password,
            'length': len(password),
            'charsets': [],
            'entropy_bits': 0,
            'crack_time': 'Unknown',
            'is_common': False,
            'rating': 'UNKNOWN',
        }

        if re.search(r'[a-z]', password): analysis['charsets'].append('lowercase')
        if re.search(r'[A-Z]', password): analysis['charsets'].append('uppercase')
        if re.search(r'\d', password): analysis['charsets'].append('digits')
        if re.search(r'[^A-Za-z0-9]', password): analysis['charsets'].append('symbols')

        charset_size = 0
        if 'lowercase' in analysis['charsets']: charset_size += 26
        if 'uppercase' in analysis['charsets']: charset_size += 26
        if 'digits' in analysis['charsets']: charset_size += 10
        if 'symbols' in analysis['charsets']: charset_size += 32
        if charset_size == 0: charset_size = 1

        entropy = len(password) * math.log2(charset_size)
        analysis['entropy_bits'] = round(entropy, 1)

        guesses = charset_size ** len(password)
        seconds = guesses / 1e10
        analysis['crack_time'] = self.format_time(seconds)

        if password.lower() in [p.lower() for p in self.common_passwords]:
            analysis['is_common'] = True

        if entropy < 28:
            rating, color = 'VERY WEAK', Colors.RED
        elif entropy < 36:
            rating, color = 'WEAK', Colors.RED
        elif entropy < 60:
            rating, color = 'REASONABLE', Colors.YELLOW
        elif entropy < 80:
            rating, color = 'STRONG', Colors.GREEN
        else:
            rating, color = 'VERY STRONG', Colors.GREEN

        analysis['rating'] = rating
        analysis['rating_color'] = color

        print(f"    Password:      {'*' * len(password)}")
        print(f"    Length:        {analysis['length']}")
        print(f"    Charsets:      {', '.join(analysis['charsets']) or 'none'}")
        print(f"    Entropy:       {entropy:.1f} bits")
        print(f"    Crack time:    {analysis['crack_time']}")
        print(f"    Common pwd:    {'YES ⚠️' if analysis['is_common'] else 'No'}")
        print(f"    Rating:        {color}{rating}{Colors.RESET}")

        return analysis

    @staticmethod
    def format_time(seconds):
        if seconds < 1: return '< 1 second'
        if seconds < 60: return f'{seconds:.0f} seconds'
        if seconds < 3600: return f'{seconds/60:.1f} minutes'
        if seconds < 86400: return f'{seconds/3600:.1f} hours'
        if seconds < 31536000: return f'{seconds/86400:.1f} days'
        years = seconds / 31536000
        if years < 1e6: return f'{years:.0f} years'
        return f'{years:.2e} years'

    # ------------------------------------------------------------------ #
    # RECOMMENDATIONS
    # ------------------------------------------------------------------ #
    def generate_recommendations(self, analysis):
        recs = []
        if analysis['length'] < 12:
            recs.append('Use at least 12–16 character passwords')
        if 'uppercase' not in analysis['charsets']:
            recs.append('Add uppercase letters (A-Z)')
        if 'lowercase' not in analysis['charsets']:
            recs.append('Add lowercase letters (a-z)')
        if 'digits' not in analysis['charsets']:
            recs.append('Add digits (0-9)')
        if 'symbols' not in analysis['charsets']:
            recs.append('Add symbols (!@#$%^&*)')
        if analysis['is_common']:
            recs.append('Avoid common/dictionary passwords')
        if analysis['rating'] in ('VERY WEAK', 'WEAK'):
            recs.append('Use a password manager to generate strong passwords')
        recs.append('Enable 2FA/MFA on all important accounts')
        recs.append('Never reuse passwords across sites')
        return recs

    # ------------------------------------------------------------------ #
    # REPORT
    # ------------------------------------------------------------------ #
    def save_report(self):
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("PASSWORD SECURITY ANALYSIS REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"Date: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")

            if self.results['hash']:
                f.write("HASH ANALYSIS\n" + "-" * 40 + "\n")
                f.write(f"  Hash:      {self.results['hash']}\n")
                f.write(f"  Type:      {self.results['hash_type']}\n")
                f.write(f"  Length:    {len(self.results['hash'])} chars\n\n")

            f.write("CRACKING RESULT\n" + "-" * 40 + "\n")
            if self.results['cracked']:
                f.write(f"  Password:  {self.results['password']}\n")
                f.write(f"  Method:    {self.results['method']}\n")
                f.write(f"  Time:      {self.results['time_taken']:.2f}s\n")
                f.write(f"  Attempts:  {self.results['attempts']}\n\n")
            else:
                f.write("  Not cracked\n\n")

            if self.results['strength']:
                s = self.results['strength']
                f.write("STRENGTH ANALYSIS\n" + "-" * 40 + "\n")
                f.write(f"  Length:    {s['length']}\n")
                f.write(f"  Charsets:  {', '.join(s['charsets'])}\n")
                f.write(f"  Entropy:   {s['entropy_bits']} bits\n")
                f.write(f"  Crack:     {s['crack_time']}\n")
                f.write(f"  Common:    {s['is_common']}\n")
                f.write(f"  Rating:    {s['rating']}\n\n")

            if self.results['recommendations']:
                f.write("RECOMMENDATIONS\n" + "-" * 40 + "\n")
                for i, r in enumerate(self.results['recommendations'], 1):
                    f.write(f"  {i}. {r}\n")

            f.write("\n" + "=" * 70 + "\n")
            f.write("Generated by Password Security Analyzer — Project #17\n")
            f.write("=" * 70 + "\n")

        print(f"\n{Colors.GREEN}[✓] Report saved: {self.output_file}{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # CRACK WORKFLOW
    # ------------------------------------------------------------------ #
    def crack(self, hash_string, algorithm=None, wordlist=None,
              do_brute=False, brute_charset='lower', brute_max=4,
              brute_timeout=60):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}Password Security Analyzer{Colors.RESET}")
        print("=" * 70)

        # --- Identify hash ---
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] HASH ANALYSIS{Colors.RESET}")
        hash_string = hash_string.strip()
        detected = self.identify_hash(hash_string, forced_algorithm=algorithm)

        print(f"    Hash:   {hash_string}")
        print(f"    Type:   {detected}")
        print(f"    Length: {len(hash_string)} characters")

        self.results['hash'] = hash_string
        self.results['hash_type'] = detected

        # --- Determine algorithm ---
        if algorithm is None:
            if 'MD5' in detected or 'NTLM' in detected:
                algorithm = 'md5'
            elif 'SHA1' in detected:
                algorithm = 'sha1'
            elif 'SHA256' in detected or 'SHA3' in detected:
                algorithm = 'sha256'
            elif 'SHA512' in detected:
                algorithm = 'sha512'
            elif 'bcrypt' in detected:
                print(f"\n{Colors.YELLOW}[!] bcrypt is intentionally slow — "
                      f"skipping cracking{Colors.RESET}")
                algorithm = None
            else:
                print(f"\n{Colors.YELLOW}[!] Unknown hash type — "
                      f"skipping cracking{Colors.RESET}")
                algorithm = None

        # --- Dictionary ---
        if algorithm:
            result = self.dictionary_attack(hash_string, wordlist, algorithm)
            if result['success']:
                self.results['cracked'] = True
                self.results['password'] = result['password']
                self.results['method'] = 'dictionary'
                self.results['time_taken'] = result['time']
                self.results['attempts'] = result['attempts']

                analysis = self.analyze_strength(result['password'])
                self.results['strength'] = analysis
                self.results['recommendations'] = self.generate_recommendations(analysis)

        # --- Brute-force ---
        if algorithm and not self.results['cracked'] and do_brute:
            result = self.brute_force_attack(
                hash_string, algorithm, brute_charset, brute_max, brute_timeout
            )
            if result['success']:
                self.results['cracked'] = True
                self.results['password'] = result['password']
                self.results['method'] = 'brute-force'
                self.results['time_taken'] = result['time']
                self.results['attempts'] = result['attempts']

                analysis = self.analyze_strength(result['password'])
                self.results['strength'] = analysis
                self.results['recommendations'] = self.generate_recommendations(analysis)

        # --- Recommendations ---
        if self.results['recommendations']:
            print(f"\n{Colors.BOLD}{Colors.BLUE}[📋] RECOMMENDATIONS{Colors.RESET}")
            for i, r in enumerate(self.results['recommendations'], 1):
                print(f"    {i}. {r}")

        self.save_report()

    # ------------------------------------------------------------------ #
    # AUTO TEST MODE
    # ------------------------------------------------------------------ #
    def auto_test(self, password, algorithm='md5', do_brute=False,
                  brute_charset='lower', brute_max=4, brute_timeout=30):
        """Generate hash + crack it in one command."""
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}AUTO TEST MODE{Colors.RESET}")
        print("=" * 70)

        # Generate
        h = self.hash_string(password, algorithm)
        print(f"\n{Colors.GREEN}[✓] Generated test hash{Colors.RESET}")
        print(f"    Password:  {password}")
        print(f"    Algorithm: {algorithm}")
        print(f"    Hash:      {h}")

        # Crack
        self.crack(
            hash_string=h,
            algorithm=algorithm,
            wordlist=None,
            do_brute=do_brute,
            brute_charset=brute_charset,
            brute_max=brute_max,
            brute_timeout=brute_timeout,
        )

# ---------------------------------------------------------------------- #
# MAIN
# ---------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="Password Cracking & Hash Analysis Tool (EDUCATIONAL)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto test: generate + crack in ONE command (RECOMMENDED)
  python password_analyzer.py --test password123
  python password_analyzer.py --test abc --brute --brute-max 3

  # Analyze a hash you already have
  python password_analyzer.py --hash 482c811da5d5b4bc6d497ffa98491e38
  python password_analyzer.py --hash <hash> --wordlist common_passwords.txt
  python password_analyzer.py --hash <hash> --brute --brute-max 4

  # Generate a test hash only
  python password_analyzer.py --generate hello --algorithm sha256

  # Analyze a password strength directly
  python password_analyzer.py --strength "MyP@ssw0rd123"

NOTE FOR POWERSHELL USERS:
  Do NOT type <hash> with angle brackets — paste the actual hash!
  Bad:  python password_analyzer.py --hash <hash>
  Good: python password_analyzer.py --hash 482c811da5d5b4bc6d497ffa98491e38
        """
    )

    p.add_argument('--hash', help='Hash string to analyze')
    p.add_argument('--algorithm', choices=['md5', 'sha1', 'sha256', 'sha512',
                                          'sha3-256', 'ntlm'],
                   help='Force hash algorithm')
    p.add_argument('--wordlist', help='Path to wordlist file')
    p.add_argument('--brute', action='store_true',
                   help='Enable brute-force attack')
    p.add_argument('--brute-charset', default='lower',
                   help='Brute-force charset (lower/upper/digits/alnum/all or custom)')
    p.add_argument('--brute-max', type=int, default=4,
                   help='Max brute-force length (default 4)')
    p.add_argument('--brute-timeout', type=int, default=60,
                   help='Brute-force timeout seconds (default 60)')
    p.add_argument('--generate', help='Generate a hash for testing')
    p.add_argument('--strength', help='Analyze a password strength directly')
    p.add_argument('--test', help='AUTO: generate hash + crack it in one command')
    p.add_argument('--output', default='password_analysis_report.txt',
                   help='Output file')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  PASSWORD SECURITY ANALYZER")
    print("  Project #17: Password Cracking & Hash Analysis")
    print("=" * 70)
    print(f"{Colors.RESET}")

    analyzer = PasswordAnalyzer(output_file=args.output, verbose=args.verbose)

    # --- AUTO TEST ---
    if args.test:
        analyzer.auto_test(
            password=args.test,
            algorithm=args.algorithm or 'md5',
            do_brute=args.brute,
            brute_charset=args.brute_charset,
            brute_max=args.brute_max,
            brute_timeout=args.brute_timeout,
        )
        return

    # --- Generate hash ---
    if args.generate:
        algo = args.algorithm or 'md5'
        h = analyzer.hash_string(args.generate, algo)
        print(f"\n{Colors.GREEN}[✓] Generated hash{Colors.RESET}")
        print(f"    Password:  {args.generate}")
        print(f"    Algorithm: {algo}")
        print(f"    Hash:      {h}")
        print(f"\n{Colors.YELLOW}Next step:{Colors.RESET}")
        print(f"    python password_analyzer.py --hash {h}")
        return

    # --- Strength only ---
    if args.strength:
        analysis = analyzer.analyze_strength(args.strength)
        recs = analyzer.generate_recommendations(analysis)
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📋] RECOMMENDATIONS{Colors.RESET}")
        for i, r in enumerate(recs, 1):
            print(f"    {i}. {r}")
        analyzer.results['strength'] = analysis
        analyzer.results['recommendations'] = recs
        analyzer.save_report()
        return

    # --- Crack hash ---
    if args.hash:
        analyzer.crack(
            hash_string=args.hash,
            algorithm=args.algorithm,
            wordlist=args.wordlist,
            do_brute=args.brute,
            brute_charset=args.brute_charset,
            brute_max=args.brute_max,
            brute_timeout=args.brute_timeout,
        )
        return

    print(f"\n{Colors.YELLOW}[!] No action specified. Use --help for options.{Colors.RESET}")
    print(f"{Colors.CYAN}Tip: Try the auto test mode:{Colors.RESET}")
    print(f"    python password_analyzer.py --test password123")

if __name__ == '__main__':
    main()