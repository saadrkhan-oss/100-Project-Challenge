#!/usr/bin/env python3
"""
crypto_breaker.py — Custom Cryptography Breaking (Project #59) — FINAL
Recovers XOR key via known-plaintext (FLAG{) + intelligent brute-force.
"""
import os, sys, json, re
from datetime import datetime
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pwn import ELF

BINARY = "./custom_crypto"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

CIPHERTEXT_HEX = "150902153e17650a15171d1a1d640c03161c38"

class CryptoBreaker:
    def __init__(self, ciphertext_hex=CIPHERTEXT_HEX):
        self.ciphertext = bytes.fromhex(ciphertext_hex)
        self.report = {
            "ciphertext_hex": ciphertext_hex,
            "ciphertext_len": len(self.ciphertext),
            "timestamp": datetime.now().isoformat(),
            "phases": {},
        }

    def phase1_analyze_binary(self):
        print("\n[PHASE 1] BINARY ANALYSIS")
        if not os.path.exists(BINARY):
            print(f"    [!] {BINARY} not found")
            return
        b = ELF(BINARY, checksec=False)
        encrypt_addr = b.symbols.get('encrypt')
        print(f"    Binary: {BINARY}")
        print(f"    Arch:   {b.arch}")
        print(f"    encrypt: {hex(encrypt_addr) if encrypt_addr else 'NOT FOUND'}")
        self.binary = b
        self.encrypt_addr = encrypt_addr
        self.report["phases"]["binary"] = {
            "arch": b.arch,
            "encrypt": hex(encrypt_addr) if encrypt_addr else None,
        }

    def phase2_identify_algorithm(self):
        print("\n[PHASE 2] ALGORITHM IDENTIFICATION")
        if not hasattr(self, 'binary'):
            return
        encrypt_bytes = self.binary.read(self.encrypt_addr, 128)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        xors_found = 0
        for insn in md.disasm(encrypt_bytes, self.encrypt_addr):
            if 'xor' in insn.mnemonic:
                print(f"    {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                xors_found += 1
        print(f"\n    XORS: {xors_found}")
        print(f"    Algorithm: XOR with repeating key")
        print(f"    [+] WEAK ENCRYPTION IDENTIFIED")
        self.report["phases"]["algorithm"] = {
            "type": "XOR_with_repeating_key",
            "xor_instructions": xors_found,
        }

    def phase3_known_prefix(self):
        print("\n[PHASE 3] KNOWN-PLAINTEXT ATTACK (FLAG{)")
        known = b"FLAG{"
        if self.ciphertext[:5] == known:
            print(f"    [!] Ciphertext starts with FLAG{{ — not encrypted?")
        key_partial = bytes(c ^ known[i] for i, c in enumerate(self.ciphertext[:5]))
        key_ascii = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in key_partial)
        print(f"    Known plaintext: FLAG{{ (5 bytes)")
        print(f"    Recovered key[0:5]: {key_partial} ({key_ascii})")

        self.key_partial = key_partial
        self.report["phases"]["known_prefix"] = {
            "known_plaintext": "FLAG{",
            "recovered_key_partial": key_partial.hex(),
            "recovered_key_partial_ascii": key_ascii,
        }

    def phase4_complete_key(self):
        print("\n[PHASE 4] KEY COMPLETION (brute-force remaining bytes)")
        # Try all possible values for remaining key bytes (7 - 5 = 2 bytes)
        # Score based on English-like plaintext in the middle section
        key_len = 7
        best_key = None
        best_score = -1

        for c5 in range(256):
            for c6 in range(256):
                key = self.key_partial + bytes([c5, c6])
                try:
                    plaintext = bytes(c ^ key[i % key_len]
                                      for i, c in enumerate(self.ciphertext))
                    text = plaintext.decode('ascii')
                except (UnicodeDecodeError, Exception):
                    continue

                # Score: how English-like is the middle?
                # Look for common patterns: CRYPTO, IS, FUN, or any all-alpha middle
                score = 0
                if 'CRYPTO' in text: score += 100
                if 'IS' in text: score += 20
                if 'FUN' in text: score += 50
                if text.startswith('FLAG{') and text.endswith('}'): score += 10
                # All printable
                if all(32 <= b <= 126 for b in plaintext): score += 5
                # Only alnum and _ in the middle
                middle = text[5:-1]
                if all(c.isalnum() or c == '_' for c in middle): score += 10

                if score > best_score:
                    best_score = score
                    best_key = (key, text, score)

        if best_key:
            key, text, score = best_key
            key_ascii = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in key)
            print(f"    Best key: {key} ({key_ascii})")
            print(f"    Plaintext: {text}")
            print(f"    Score: {score}")
            self.key = key
            self.plaintext = text
            self.report["phases"]["key_completion"] = {
                "key_hex": key.hex(),
                "key_ascii": key_ascii,
                "plaintext": text,
                "score": score,
            }
        else:
            print(f"    [!] No valid key found")

    def phase5_extract_flag(self):
        print("\n[PHASE 5] EXTRACTING FLAG")
        if hasattr(self, 'plaintext'):
            m = re.search(r'FLAG\{[^}]+\}', self.plaintext)
            flag = m.group(0) if m else "(not found)"
            if flag != "(not found)":
                print(f"    [+] FLAG FOUND: {flag}")
            self.flag = flag
            self.report["phases"]["flag"] = {"flag": flag}

    def phase6_solve_script(self):
        print("\n[PHASE 6] GENERATING SOLVE SCRIPT")
        if not hasattr(self, 'key'):
            return
        solve = f'''#!/usr/bin/env python3
"""solve_crypto.py — Auto-generated (Project #59)"""

CIPHERTEXT = bytes.fromhex("{self.ciphertext.hex()}")
KEY = bytes.fromhex("{self.key.hex()}")

def xor_decrypt(ciphertext, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))

if __name__ == "__main__":
    plaintext = xor_decrypt(CIPHERTEXT, KEY)
    print(f"Plaintext: {{plaintext.decode()}}")
    import re
    m = re.search(rb"FLAG\\{{[^}}]+\\}}", plaintext)
    if m:
        print(f"Flag: {{m.group(0).decode()}}")
'''
        with open("solve_crypto.py", "w") as f:
            f.write(solve)
        print(f"    [+] Generated: solve_crypto.py")
        self.report["phases"]["solve_script"] = {"file": "solve_crypto.py"}

    def phase7_report(self):
        print("\n[PHASE 7] REPORT")
        confirmed = []
        if self.report["phases"].get("algorithm"):
            confirmed.append("xor_encryption_found")
        if self.report["phases"].get("key_completion"):
            confirmed.append("key_recovered")
        if self.report["phases"].get("flag", {}).get("flag", "").startswith("FLAG"):
            confirmed.append("flag_found")

        print(f"\n    Total findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/crypto_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/crypto_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Crypto Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>Custom Cryptography Breaking Report</h1>
<p><b>Ciphertext:</b> {self.report['ciphertext_hex']}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Custom Cryptography Breaking - Project #59")
        print("=" * 64)
        self.phase1_analyze_binary()
        self.phase2_identify_algorithm()
        self.phase3_known_prefix()
        self.phase4_complete_key()
        self.phase5_extract_flag()
        self.phase6_solve_script()
        self.phase7_report()

if __name__ == "__main__":
    CryptoBreaker().run_all()
