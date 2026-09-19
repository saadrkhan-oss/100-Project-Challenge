#!/usr/bin/env python3
"""
Binary Reverse Engineering Toolkit
Project #22: Binary Reverse Engineering (ELF + PE + Mach-O)

LEGAL: Only analyze binaries you own or have permission to analyze.
       Never execute untrusted binaries — this tool does static analysis only.
"""

import sys
import os
import re
import json
import struct
import argparse
import datetime
from pathlib import Path
from collections import defaultdict

# ELF
try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.constants import P_FLAGS
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

# PE
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

# Strings
try:
    from pwn import ELF, context, ROP
    HAS_PWNTOOLS = True
except ImportError:
    HAS_PWNTOOLS = False

from dangerous_funcs import DANGEROUS_FUNCTIONS, INTERESTING_KEYWORDS

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
# MAIN TOOLKIT
# ---------------------------------------------------------------------- #
class REtoolkit:
    def __init__(self, target, output_dir="reports", verbose=False):
        self.target = target
        self.verbose = verbose
        self.output_dir = output_dir

        self.results = {
            'target': target,
            'file_size': 0,
            'file_type': None,
            'hashes': {},
            'headers': {},
            'sections': [],
            'symbols': {'functions': [], 'imports': [], 'exports': []},
            'strings': [],
            'interesting_strings': [],
            'dangerous_calls': [],
            'protections': {},
            'vulnerabilities': [],
            'entropy': None,
        }

        os.makedirs(output_dir, exist_ok=True)

    # ------------------------------------------------------------------ #
    # FILE HASHES
    # ------------------------------------------------------------------ #
    def compute_hashes(self):
        import hashlib
        try:
            with open(self.target, 'rb') as f:
                data = f.read()
            self.results['file_size'] = len(data)
            self.results['hashes'] = {
                'md5':    hashlib.md5(data).hexdigest(),
                'sha1':   hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest(),
            }
        except Exception as e:
            print(f"{Colors.RED}[!] Cannot read file: {e}{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # DETECT FILE TYPE
    # ------------------------------------------------------------------ #
    def detect_file_type(self):
        try:
            with open(self.target, 'rb') as f:
                magic = f.read(16)
        except Exception:
            return 'unknown'

        if magic[:4] == b'\x7fELF':
            bits = '64-bit' if magic[4] == 2 else '32-bit'
            endian = 'LSB' if magic[5] == 1 else 'MSB'
            self.results['file_type'] = f'ELF {bits} {endian}'
        elif magic[:2] == b'MZ':
            self.results['file_type'] = 'PE (Windows)'
        elif magic[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                           b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
            self.results['file_type'] = 'Mach-O (macOS)'
        else:
            self.results['file_type'] = 'Unknown'

        return self.results['file_type']

    # ------------------------------------------------------------------ #
    # ELF ANALYSIS
    # ------------------------------------------------------------------ #
    def analyze_elf(self):
        if not HAS_ELFTOOLS:
            print(f"{Colors.RED}[!] pyelftools not installed (pip install pyelftools){Colors.RESET}")
            return

        try:
            with open(self.target, 'rb') as f:
                elf = ELFFile(f)

                # Header info
                self.results['headers'] = {
                    'type':      elf['e_type'],
                    'machine':   elf['e_machine'],
                    'entry':     hex(elf['e_entry']),
                    'endianness': 'Little' if elf.little_endian else 'Big',
                    'class':     '32-bit' if elf.elfclass == 32 else '64-bit',
                }

                # Sections
                for section in elf.iter_sections():
                    self.results['sections'].append({
                        'name':    section.name,
                        'addr':    hex(section['sh_addr']),
                        'offset':  hex(section['sh_offset']),
                        'size':    section['sh_size'],
                        'type':    section['sh_type'],
                    })

                # Symbols
                functions = []
                imports = []

                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            name = sym.name
                            if not name:
                                continue
                            sym_type = sym['st_info']['type']
                            sym_bind = sym['st_info']['bind']

                            if sym_type == 'STT_FUNC':
                                addr = sym['st_value']
                                if addr:
                                    functions.append({'name': name,
                                                      'addr': hex(addr)})
                            elif sym_type == 'STT_NOTYPE' or sym_bind == 'STB_GLOBAL':
                                if name.startswith('_') and not name.startswith('__'):
                                    continue

                        # PLT/GOT imports
                        if section.name == '.dynsym':
                            for sym in section.iter_symbols():
                                if sym.name and sym['st_shndx'] == 'SHN_UNDEF':
                                    imports.append(sym.name)

                self.results['symbols']['functions'] = functions
                self.results['symbols']['imports'] = sorted(set(imports))

        except Exception as e:
            print(f"{Colors.RED}[!] ELF parse error: {e}{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # PE ANALYSIS
    # ------------------------------------------------------------------ #
    def analyze_pe(self):
        if not HAS_PEFILE:
            print(f"{Colors.YELLOW}[!] pefile not installed (pip install pefile){Colors.RESET}")
            return

        try:
            pe = pefile.PE(self.target)

            self.results['headers'] = {
                'machine':    hex(pe.FILE_HEADER.Machine),
                'timestamp':  datetime.datetime.utcfromtimestamp(
                                pe.FILE_HEADER.TimeDateStamp).isoformat(),
                'entry':      hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'imagebase':  hex(pe.OPTIONAL_HEADER.ImageBase),
                'subsystem':  pe.OPTIONAL_HEADER.Subsystem,
            }

            for sec in pe.sections:
                self.results['sections'].append({
                    'name':   sec.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'addr':   hex(sec.VirtualAddress),
                    'size':   sec.SizeOfRawData,
                    'type':   'PE_SECTION',
                })

            # Imports
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(f"{dll}!{imp.name.decode('utf-8', errors='ignore')}")
            self.results['symbols']['imports'] = imports

            # Exports
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', errors='ignore'))
            self.results['symbols']['exports'] = exports

        except Exception as e:
            print(f"{Colors.RED}[!] PE parse error: {e}{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # STRING EXTRACTION
    # ------------------------------------------------------------------ #
    def extract_strings(self, min_len=4):
        try:
            with open(self.target, 'rb') as f:
                data = f.read()
        except Exception:
            return

        # Extract ASCII + Unicode printable sequences
        pattern = rb'[\x20-\x7e]{%d,}' % min_len
        strings = []
        for m in re.finditer(pattern, data):
            s = m.group().decode('ascii', errors='ignore')
            strings.append(s)

        # Deduplicate but keep count
        seen = {}
        for s in strings:
            seen[s] = seen.get(s, 0) + 1

        self.results['strings'] = [
            {'value': s, 'count': c} for s, c in seen.items()
        ]

        # Interesting strings
        interesting = []
        for s in seen:
            low = s.lower()
            for kw in INTERESTING_KEYWORDS:
                if kw.lower() in low:
                    interesting.append({
                        'value': s,
                        'matched': kw,
                    })
                    break

        self.results['interesting_strings'] = interesting[:100]

    # ------------------------------------------------------------------ #
    # DANGEROUS FUNCTIONS
    # ------------------------------------------------------------------ #
    def find_dangerous_calls(self):
        # Combine imports + any string that matches a function name
        all_names = set()
        for imp in self.results['symbols']['imports']:
            # Strip DLL prefix for PE
            name = imp.split('!')[-1] if '!' in imp else imp
            # Strip version suffix (e.g. strcpy@plt)
            name = name.split('@')[0]
            all_names.add(name)

        # Also scan strings
        for s in self.results['strings']:
            v = s['value'].strip()
            if v in DANGEROUS_FUNCTIONS:
                all_names.add(v)
            # Check for name inside strings like "strcpy@plt"
            for df in DANGEROUS_FUNCTIONS:
                if df in v and v == df:
                    all_names.add(df)

        # Match against dangerous database
        for name in sorted(all_names):
            base = name.split('@')[0]
            if base in DANGEROUS_FUNCTIONS:
                info = DANGEROUS_FUNCTIONS[base]
                self.results['dangerous_calls'].append({
                    'name': base,
                    'risk': info['risk'],
                    'category': info['category'],
                    'desc': info['desc'],
                })

    # ------------------------------------------------------------------ #
    # PROTECTIONS (checksec-style)
    # ------------------------------------------------------------------ #
    def check_protections(self):
        """Use pwntools checksec if available, else fallback to manual."""
        if HAS_PWNTOOLS:
            try:
                elf = ELF(self.target, checksec=False)
                self.results['protections'] = {
                    'NX':       'Enabled' if elf.nx else 'Disabled',
                    'PIE':      'Enabled' if elf.pie else 'Disabled',
                    'Canary':   'Enabled' if elf.canary else 'Disabled',
                    'RELRO':    'Full' if elf.relro == 'Full' else
                                'Partial' if elf.relro == 'Partial' else 'Disabled',
                    'Fortify':  'Enabled' if elf.fortify else 'Disabled',
                }
                return
            except Exception:
                pass

        # Manual fallback for ELF
        if self.results['file_type'].startswith('ELF'):
            try:
                with open(self.target, 'rb') as f:
                    elf = ELFFile(f)

                    # PIE: e_type == ET_DYN
                    pie = (elf['e_type'] == 'ET_DYN')
                    # NX: any PT_GNU_STACK without X
                    nx = False
                    for seg in elf.iter_segments():
                        if seg['p_type'] == 'PT_GNU_STACK':
                            nx = not bool(seg['p_flags'] & P_FLAGS.PF_X)
                            break
                    # Canary: look for __stack_chk_fail
                    has_canary = False
                    for section in elf.iter_sections():
                        if isinstance(section, SymbolTableSection):
                            for sym in section.iter_symbols():
                                if sym.name == '__stack_chk_fail':
                                    has_canary = True
                                    break

                    # RELRO: PT_GNU_RELRO
                    has_relro = any(seg['p_type'] == 'PT_GNU_RELRO'
                                    for seg in elf.iter_segments())

                    self.results['protections'] = {
                        'NX':     'Enabled' if nx else 'Disabled',
                        'PIE':    'Enabled' if pie else 'Disabled',
                        'Canary': 'Enabled' if has_canary else 'Disabled',
                        'RELRO':  'Partial' if has_relro else 'Disabled',
                    }
            except Exception as e:
                if self.verbose:
                    print(f"[!] Protection check error: {e}")

    # ------------------------------------------------------------------ #
    # VULNERABILITY SUMMARY
    # ------------------------------------------------------------------ #
    def summarize_vulnerabilities(self):
        vulns = []
        prot = self.results['protections']

        # Dangerous function findings
        for df in self.results['dangerous_calls']:
            if df['risk'] in ('CRITICAL', 'HIGH'):
                vulns.append({
                    'severity': df['risk'],
                    'title':    f"{df['name']}() — {df['category']}",
                    'detail':   df['desc'],
                })

        # Protection findings
        if prot.get('NX') == 'Disabled':
            vulns.append({
                'severity': 'HIGH',
                'title':    'NX disabled',
                'detail':   'Stack is executable — shellcode injection possible',
            })
        if prot.get('PIE') == 'Disabled':
            vulns.append({
                'severity': 'MEDIUM',
                'title':    'PIE disabled',
                'detail':   'Fixed addresses — ROP/overflow easier to exploit',
            })
        if prot.get('Canary') == 'Disabled':
            vulns.append({
                'severity': 'HIGH',
                'title':    'Stack canary disabled',
                'detail':   'Buffer overflows not detected at runtime',
            })
        if prot.get('RELRO') in ('Disabled', 'Partial'):
            vulns.append({
                'severity': 'MEDIUM',
                'title':    f'RELRO {prot.get("RELRO")}',
                'detail':   'GOT overwrite possible',
            })

        self.results['vulnerabilities'] = vulns

    # ------------------------------------------------------------------ #
    # DISPLAY
    # ------------------------------------------------------------------ #
    def print_headers(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] BINARY HEADERS{Colors.RESET}")
        print(f"    File Type:   {self.results['file_type']}")
        print(f"    File Size:   {self.results['file_size']} bytes")
        print(f"    MD5:         {self.results['hashes'].get('md5', '?')}")
        print(f"    SHA256:      {self.results['hashes'].get('sha256', '?')}")
        for k, v in self.results['headers'].items():
            print(f"    {k.capitalize():12} {v}")

    def print_sections(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] SECTIONS{Colors.RESET}")
        for sec in self.results['sections'][:20]:
            print(f"    {sec['name']:12} {sec['addr']:>12}  {sec['size']:>8} bytes")

    def print_symbols(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] SYMBOLS{Colors.RESET}")
        funcs = self.results['symbols']['functions']
        imports = self.results['symbols']['imports']
        if funcs:
            print(f"    {Colors.CYAN}Functions ({len(funcs)}):{Colors.RESET}")
            for f in funcs[:15]:
                print(f"        {f['name']}  ({f['addr']})")
        if imports:
            print(f"    {Colors.CYAN}Imports ({len(imports)}):{Colors.RESET}")
            for imp in imports[:15]:
                print(f"        {imp}")

    def print_dangerous(self):
        if not self.results['dangerous_calls']:
            print(f"\n{Colors.BOLD}{Colors.BLUE}[⚠️] DANGEROUS FUNCTIONS{Colors.RESET}")
            print(f"    {Colors.GREEN}None detected{Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}{Colors.BLUE}[⚠️] DANGEROUS FUNCTIONS{Colors.RESET}")
        for d in self.results['dangerous_calls']:
            color = (Colors.RED if d['risk'] == 'CRITICAL'
                     else Colors.YELLOW if d['risk'] == 'HIGH'
                     else Colors.CYAN)
            print(f"    {color}[{d['risk']}]{Colors.RESET} {d['name']}() — "
                  f"{d['desc']}")

    def print_strings(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] STRING ANALYSIS{Colors.RESET}")
        print(f"    Total unique strings: {len(self.results['strings'])}")
        if self.results['interesting_strings']:
            print(f"    {Colors.YELLOW}Interesting ({len(self.results['interesting_strings'])}):{Colors.RESET}")
            for s in self.results['interesting_strings'][:20]:
                print(f"        [{s['matched']}] {s['value'][:80]}")

    def print_protections(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] PROTECTION ANALYSIS{Colors.RESET}")
        for k, v in self.results['protections'].items():
            color = (Colors.GREEN if v == 'Enabled'
                     else Colors.YELLOW if v == 'Partial'
                     else Colors.RED)
            print(f"    {k:10} {color}{v}{Colors.RESET}")

    def print_vulnerabilities(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[📊] VULNERABILITY SUMMARY{Colors.RESET}")
        if not self.results['vulnerabilities']:
            print(f"    {Colors.GREEN}No issues found{Colors.RESET}")
            return
        for v in self.results['vulnerabilities']:
            color = (Colors.RED if v['severity'] == 'CRITICAL'
                     else Colors.YELLOW if v['severity'] == 'HIGH'
                     else Colors.CYAN)
            print(f"    {color}[{v['severity']}]{Colors.RESET} {v['title']}")
            print(f"        → {v['detail']}")

    # ------------------------------------------------------------------ #
    # SAVE REPORT
    # ------------------------------------------------------------------ #
    def save_report(self):
        base = os.path.basename(self.target).replace('/', '_').replace('\\', '_')
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

        # JSON
        json_path = f"{self.output_dir}/{base}_{ts}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)

        # Text
        txt_path = f"{self.output_dir}/{base}_{ts}.txt"
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("BINARY REVERSE ENGINEERING REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Target:    {self.target}\n")
            f.write(f"File Type: {self.results['file_type']}\n")
            f.write(f"Size:      {self.results['file_size']} bytes\n")
            f.write(f"MD5:       {self.results['hashes'].get('md5', '?')}\n")
            f.write(f"SHA256:    {self.results['hashes'].get('sha256', '?')}\n")
            f.write(f"Date:      {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n")
            f.write("=" * 80 + "\n\n")

            f.write("HEADERS\n" + "-" * 40 + "\n")
            for k, v in self.results['headers'].items():
                f.write(f"  {k}: {v}\n")
            f.write("\n")

            f.write("SECTIONS\n" + "-" * 40 + "\n")
            for sec in self.results['sections']:
                f.write(f"  {sec['name']:15} {sec['addr']:>12}  {sec['size']:>8}\n")
            f.write("\n")

            f.write("DANGEROUS FUNCTIONS\n" + "-" * 40 + "\n")
            for d in self.results['dangerous_calls']:
                f.write(f"  [{d['risk']}] {d['name']}() — {d['desc']}\n")
            f.write("\n")

            f.write("INTERESTING STRINGS\n" + "-" * 40 + "\n")
            for s in self.results['interesting_strings']:
                f.write(f"  [{s['matched']}] {s['value']}\n")
            f.write("\n")

            f.write("PROTECTIONS\n" + "-" * 40 + "\n")
            for k, v in self.results['protections'].items():
                f.write(f"  {k}: {v}\n")
            f.write("\n")

            f.write("VULNERABILITIES\n" + "-" * 40 + "\n")
            for v in self.results['vulnerabilities']:
                f.write(f"  [{v['severity']}] {v['title']}\n")
                f.write(f"      → {v['detail']}\n")
            f.write("\n")

            f.write("=" * 80 + "\n")
            f.write("Generated by RE Toolkit — Project #22\n")
            f.write("=" * 80 + "\n")

        print(f"\n{Colors.GREEN}[✓] JSON report: {json_path}{Colors.RESET}")
        print(f"{Colors.GREEN}[✓] Text report: {txt_path}{Colors.RESET}")

    # ------------------------------------------------------------------ #
    # MAIN
    # ------------------------------------------------------------------ #
    def analyze(self):
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}{Colors.MAGENTA}Binary Reverse Engineering Toolkit{Colors.RESET}")
        print("=" * 70)
        print(f"{Colors.BOLD}Target: {self.target}{Colors.RESET}")

        if not os.path.exists(self.target):
            print(f"{Colors.RED}[!] File not found: {self.target}{Colors.RESET}")
            return

        self.compute_hashes()
        ftype = self.detect_file_type()
        print(f"{Colors.BOLD}Type:   {ftype}{Colors.RESET}")

        # Run appropriate analyzer
        if ftype.startswith('ELF'):
            self.analyze_elf()
        elif ftype.startswith('PE'):
            self.analyze_pe()
        else:
            print(f"{Colors.YELLOW}[!] Unsupported format — running strings only{Colors.RESET}")

        self.extract_strings()
        self.find_dangerous_calls()
        self.check_protections()
        self.summarize_vulnerabilities()

        # Display
        self.print_headers()
        self.print_sections()
        self.print_symbols()
        self.print_dangerous()
        self.print_strings()
        self.print_protections()
        self.print_vulnerabilities()

        # Save
        self.save_report()

# ---------------------------------------------------------------------- #
# MAIN
# ---------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(
        description="Binary Reverse Engineering Toolkit (Project #22)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 re_toolkit.py ./vulnerable
  python3 re_toolkit.py /bin/ls
  python3 re_toolkit.py /bin/cat --output reports
  python3 re_toolkit.py suspicious.exe

LEGAL: Static analysis only. Only analyze binaries you own or have permission.
        """
    )
    p.add_argument('binary', help='Path to binary file')
    p.add_argument('-o', '--output', default='reports', help='Output directory')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  BINARY REVERSE ENGINEERING TOOLKIT")
    print("  Project #22: Binary Analysis (ELF / PE / Mach-O)")
    print("=" * 70)
    print(f"{Colors.RESET}")

    toolkit = REtoolkit(args.binary, output_dir=args.output, verbose=args.verbose)
    toolkit.analyze()

if __name__ == "__main__":
    main()