#!/usr/bin/env python3
"""
vm_reverse_toolkit.py — Custom VM Reverse Engineering (Project #58) — FINAL
"""
import os, sys, json
from datetime import datetime
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pwn import ELF

BINARY = "./vm"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

OPCODES = {
    0x01: "PUSH", 0x02: "ADD", 0x03: "CMP",
    0x04: "JMP",  0x05: "JZ", 0x06: "PRINT", 0xFF: "HALT",
}

class VMReverseToolkit:
    def __init__(self):
        self.binary = ELF(BINARY, checksec=False)
        self.report = {
            "binary": BINARY,
            "timestamp": datetime.now().isoformat(),
            "arch": self.binary.arch,
            "phases": {},
        }

    def phase1_analyze(self):
        print("\n[PHASE 1] BINARY ANALYSIS")
        size = os.path.getsize(BINARY)
        vm_addr = self.binary.symbols.get('run_vm')
        main_addr = self.binary.symbols.get('main')
        print(f"    Binary size: {size:,} bytes")
        print(f"    Architecture: {self.binary.arch}")
        print(f"    run_vm:  {hex(vm_addr)}")
        print(f"    main:    {hex(main_addr)}")

        self.vm_addr = vm_addr
        self.main_addr = main_addr
        self.report["phases"]["analyze"] = {
            "size": size, "arch": self.binary.arch,
            "run_vm": hex(vm_addr), "main": hex(main_addr),
        }

    def phase2_opcode_mapping(self):
        print("\n[PHASE 2] OPCODE MAPPING")
        for op, name in OPCODES.items():
            print(f"    {name:<8} = 0x{op:02x}")
        self.report["phases"]["opcode_mapping"] = {name: f"0x{op:02x}" for op, name in OPCODES.items()}

    def phase3_extract_bytecode(self):
        print("\n[PHASE 3] BYTECODE EXTRACTION (from movabs/mov immediates)")
        main_bytes = self.binary.read(self.main_addr, 128)
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        bytecode = bytearray()
        for insn in md.disasm(main_bytes, self.main_addr):
            raw = insn.bytes
            mn = insn.mnemonic

            # movabs rax/rdx, imm64: 48 b8/ba + 8 bytes
            if mn == 'movabs' and len(raw) == 10 and raw[0] == 0x48 and raw[1] in (0xb8, 0xba):
                bytecode.extend(raw[2:10])
                print(f"    {hex(insn.address)}: movabs imm64 = {raw[2:10].hex()}")
            # mov word [rbp-X], imm16: 66 c7 45 XX + 2
            elif mn == 'mov' and 'word' in insn.op_str and len(raw) == 6 and raw[0] == 0x66:
                bytecode.extend(raw[-2:])
                print(f"    {hex(insn.address)}: mov word    = {raw[-2:].hex()}")
            # mov byte [rbp-X], imm8: c6 45 XX + 1
            elif mn == 'mov' and 'byte' in insn.op_str and len(raw) == 4 and raw[0] == 0xc6:
                bytecode.extend(raw[-1:])
                print(f"    {hex(insn.address)}: mov byte    = {raw[-1:].hex()}")

        print(f"\n    Extracted: {len(bytecode)} bytes")
        print(f"    Hex: {bytecode.hex()}")
        self.bytecode = bytes(bytecode)
        self.report["phases"]["extract"] = {
            "length": len(bytecode),
            "hex": bytecode.hex(),
        }

    def phase4_disassemble_bytecode(self):
        print("\n[PHASE 4] BYTECODE DISASSEMBLY")
        pc = 0
        instructions = []
        while pc < len(self.bytecode):
            op = self.bytecode[pc]
            name = OPCODES.get(op, f"UNKNOWN_0x{op:02x}")
            if name == "PUSH":
                arg = self.bytecode[pc+1]
                ch = chr(arg) if 32 <= arg <= 126 else '?'
                print(f"    {pc:2d}: PUSH '{ch}'")
                instructions.append({"pc": pc, "op": name, "arg": arg, "char": ch})
                pc += 2
            else:
                print(f"    {pc:2d}: {name}")
                instructions.append({"pc": pc, "op": name})
                pc += 1
        self.instructions = instructions
        self.report["phases"]["disassembly"] = instructions

    def phase5_simulate(self):
        print("\n[PHASE 5] SIMULATING VM")
        stack = []
        flag = ""
        pc = 0
        steps = []
        while pc < len(self.bytecode):
            op = self.bytecode[pc]
            name = OPCODES.get(op)
            if name == "PUSH":
                stack.append(self.bytecode[pc+1])
                steps.append(f"PUSH {chr(self.bytecode[pc+1])} → stack={len(stack)}")
                pc += 2
            elif name == "PRINT":
                if stack:
                    flag += chr(stack.pop())
                steps.append(f"PRINT → '{flag}'")
                pc += 1
            elif name == "HALT":
                steps.append("HALT")
                break
            else:
                pc += 1

        print(f"    Output: {flag}")
        print(f"    [+] FLAG FOUND: {flag}")
        self.flag = flag
        self.report["phases"]["simulate"] = {"flag": flag, "steps": steps}

    def phase6_solve_script(self):
        print("\n[PHASE 6] GENERATING SOLVE SCRIPT")
        solve = f'''#!/usr/bin/env python3
"""solve_vm.py — Auto-generated VM solver (from RE analysis)"""

OPCODES = {{
    0x01: "PUSH", 0x02: "ADD", 0x03: "CMP",
    0x04: "JMP",  0x05: "JZ", 0x06: "PRINT", 0xFF: "HALT",
}}

BYTECODE = bytes.fromhex("{self.bytecode.hex()}")

def run_vm(code):
    stack, out, pc = [], "", 0
    while pc < len(code):
        op = code[pc]
        if op == 0x01:
            stack.append(code[pc+1])
            pc += 2
        elif op == 0x06:
            if stack: out += chr(stack.pop())
            pc += 1
        elif op == 0xFF:
            break
        else:
            pc += 1
    return out

if __name__ == "__main__":
    print(f"Flag: {{run_vm(BYTECODE)}}")
'''
        with open("solve_vm.py", "w") as f:
            f.write(solve)
        print(f"    [+] Generated: solve_vm.py")
        print(f"    Run: python3 solve_vm.py")
        self.report["phases"]["solve_script"] = {"file": "solve_vm.py"}

    def phase7_report(self):
        print("\n[PHASE 7] REPORT")
        confirmed = []
        if self.report["phases"].get("analyze", {}).get("run_vm"):
            confirmed.append("vm_interpreter_found")
        if self.report["phases"].get("extract"):
            confirmed.append("bytecode_extracted")
        if self.report["phases"].get("simulate", {}).get("flag"):
            confirmed.append("flag_found")

        print(f"\n    Total findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/vm_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/vm_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>VM RE Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>Custom VM Reverse Engineering Report</h1>
<p><b>Binary:</b> {self.report['binary']}</p>
<p><b>Arch:</b> {self.report['arch']}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Custom VM Reverse Engineering - Project #58")
        print("=" * 64)
        self.phase1_analyze()
        self.phase2_opcode_mapping()
        self.phase3_extract_bytecode()
        self.phase4_disassemble_bytecode()
        self.phase5_simulate()
        self.phase6_solve_script()
        self.phase7_report()

if __name__ == "__main__":
    VMReverseToolkit().run_all()
