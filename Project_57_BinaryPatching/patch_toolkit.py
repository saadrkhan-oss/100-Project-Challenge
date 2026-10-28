#!/usr/bin/env python3
"""patch_toolkit.py — Binary Patching & License Bypass (Project #57) — FINAL"""
import os, sys, json, shutil, subprocess
from datetime import datetime
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from pwn import ELF

BINARY = "./licensed"
BACKUP = "./licensed.orig"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

class PatchToolkit:
    def __init__(self):
        self.binary = ELF(BINARY, checksec=False)
        self.report = {
            "binary": BINARY,
            "timestamp": datetime.now().isoformat(),
            "arch": self.binary.arch,
            "phases": {},
        }

    def phase1_analyze(self):
        print("\n[PHASE 1] ANALYZING BINARY")
        size = os.path.getsize(BINARY)
        check_addr = self.binary.symbols['check_license']
        print(f"    Binary size: {size:,} bytes")
        print(f"    Architecture: {self.binary.arch}")
        print(f"    check_license: {hex(check_addr)}")

        self.check_addr = check_addr
        self.check_bytes = self.binary.read(check_addr, 128)
        print(f"    Bytes: {self.check_bytes[:16].hex()}...")

        self.report["phases"]["analyze"] = {
            "size": size,
            "arch": self.binary.arch,
            "check_license": hex(check_addr),
        }

    def phase2_disassemble(self):
        print("\n[PHASE 2] DISASSEMBLING check_license")
        md = Cs(CS_ARCH_X86, CS_MODE_32)

        self.instructions = list(md.disasm(self.check_bytes, self.check_addr))
        prev = None
        self.jump_insn = None

        for insn in self.instructions:
            marker = ""
            if insn.mnemonic == 'test':
                marker = " ← TEST"
            elif (prev == 'test' and
                  insn.mnemonic in ('jne', 'je', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle')):
                marker = " ← CONDITIONAL JUMP"
                if self.jump_insn is None:
                    self.jump_insn = insn
            print(f"    {hex(insn.address)}: {insn.mnemonic:<8} {insn.op_str}{marker}")
            prev = insn.mnemonic

        if self.jump_insn is None:
            print("    [!] No conditional jump found")
            self.report["phases"]["disassemble"] = {"error": "no_jump"}
            return False

        print(f"\n    TARGET: {self.jump_insn.mnemonic} at {hex(self.jump_insn.address)}")
        print(f"    Bytes:  {self.jump_insn.bytes.hex()}")
        print(f"    Size:   {self.jump_insn.size}")

        self.report["phases"]["disassemble"] = {
            "jump_address": hex(self.jump_insn.address),
            "jump_mnemonic": self.jump_insn.mnemonic,
            "jump_bytes": self.jump_insn.bytes.hex(),
            "jump_size": self.jump_insn.size,
        }
        return True

    def phase3_patch(self):
        print("\n[PHASE 3] PATCHING BINARY")

        # Backup
        if not os.path.exists(BACKUP):
            shutil.copy(BINARY, BACKUP)
            print(f"    [+] Backup: {BACKUP}")

        # Compute file offset
        text = self.binary.get_section_by_name('.text')
        text_vaddr = text.header.sh_addr
        text_offset = text.header.sh_offset
        file_offset = self.jump_insn.address - text_vaddr + text_offset

        print(f"    Vaddr:       {hex(self.jump_insn.address)}")
        print(f"    .text start: vaddr={hex(text_vaddr)} offset={hex(text_offset)}")
        print(f"    File offset: {hex(file_offset)}")

        with open(BINARY, "r+b") as f:
            f.seek(file_offset)
            original = f.read(self.jump_insn.size)
            f.seek(file_offset)
            nop_patch = b'\x90' * self.jump_insn.size
            f.write(nop_patch)

        print(f"    Original:    {original.hex()}")
        print(f"    Patched:     {nop_patch.hex()}")
        print(f"    [+] Binary patched!")

        self.report["phases"]["patch"] = {
            "file_offset": hex(file_offset),
            "original_bytes": original.hex(),
            "patched_bytes": nop_patch.hex(),
        }
        return True

    def phase4_test(self):
        print("\n[PHASE 4] TESTING PATCHED BINARY")
        print(f"    Running: {BINARY} wrong_key")

        try:
            result = subprocess.run([BINARY, "wrong_key"],
                                     capture_output=True, text=True, timeout=5)
            out = result.stdout.strip()
            print(f"    Output: {out}")

            bypassed = "License valid" in out
            print(f"    [+] LICENSE BYPASSED! ✅" if bypassed else f"    [-] Still locked")

            self.report["phases"]["test"] = {
                "output": out,
                "bypassed": bypassed,
            }
            return bypassed
        except Exception as e:
            print(f"    [!] {e}")
            return False

    def phase5_restore(self):
        print("\n[PHASE 5] RESTORING ORIGINAL")
        if os.path.exists(BACKUP):
            shutil.copy(BACKUP, BINARY)
            print(f"    [+] Restored from {BACKUP}")

            result = subprocess.run([BINARY, "wrong_key"],
                                     capture_output=True, text=True, timeout=5)
            print(f"    Verify: {result.stdout.strip()}")
            self.report["phases"]["restore"] = {"restored": True}
        else:
            self.report["phases"]["restore"] = {"restored": False}

    def phase6_report(self):
        print("\n[PHASE 6] REPORT")
        confirmed = []
        if self.report["phases"].get("disassemble", {}).get("jump_address"):
            confirmed.append("jump_found")
        if self.report["phases"].get("patch"):
            confirmed.append("binary_patched")
        if self.report["phases"].get("test", {}).get("bypassed"):
            confirmed.append("license_bypassed")
        if self.report["phases"].get("restore", {}).get("restored"):
            confirmed.append("restored")

        print(f"\n    Total findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/patch_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/patch_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Patch Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>Binary Patching Report</h1>
<p><b>Binary:</b> {self.report['binary']}</p>
<p><b>Arch:</b> {self.report['arch']}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Binary Patching Toolkit - Project #57")
        print("=" * 64)
        self.phase1_analyze()
        if not self.phase2_disassemble():
            print("  [!] Cannot continue")
            return
        if self.phase3_patch():
            self.phase4_test()
            self.phase5_restore()
        self.phase6_report()

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("ERROR: Linux only")
        sys.exit(1)
    PatchToolkit().run_all()
