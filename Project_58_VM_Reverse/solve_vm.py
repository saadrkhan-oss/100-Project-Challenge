#!/usr/bin/env python3
"""solve_vm.py — Auto-generated VM solver (from RE analysis)"""

OPCODES = {
    0x01: "PUSH", 0x02: "ADD", 0x03: "CMP",
    0x04: "JMP",  0x05: "JZ", 0x06: "PRINT", 0xFF: "HALT",
}

BYTECODE = bytes.fromhex("015306014506014306015206014506015406ff")

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
    print(f"Flag: {run_vm(BYTECODE)}")
