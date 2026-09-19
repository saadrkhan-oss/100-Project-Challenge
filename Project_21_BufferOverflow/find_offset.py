#!/usr/bin/env python3
"""
Find EIP offset — helper script (Project #21)
Run this to generate a cyclic pattern and send it to the binary.
Then use the crash EIP with `cyclic -l <eip>` (pwntools CLI) or
`pattern_offset` inside gdb to find the offset.
"""

from pwn import *
import sys

context.log_level = 'info'

BINARY = "./vulnerable"
PATTERN_SIZE = 500

def main():
    print("=" * 70)
    print("  EIP OFFSET FINDER")
    print("=" * 70)

    # Create cyclic pattern
    pattern = cyclic(PATTERN_SIZE)
    with open("pattern.txt", "wb") as f:
        f.write(pattern)
    print(f"[+] Saved {PATTERN_SIZE}-byte pattern to pattern.txt")

    # Send it
    print(f"[*] Sending pattern to {BINARY}...")
    p = process([BINARY, pattern])
    try:
        p.wait(timeout=2)
    except EOFError:
        pass

    # Try to read EIP
    try:
        core = p.corefile
        eip = core.eip
        offset = cyclic_find(eip)
        print(f"[+] EIP = {hex(eip)}")
        print(f"[+] Offset to EIP = {offset}")
    except Exception as e:
        print(f"[!] Could not auto-read EIP: {e}")
        print(f"[*] Manual: run `gdb {BINARY}`, send pattern.txt, then use")
        print(f"    (gdb) info registers eip")
        print(f"    (gdb) p $eip")
        print(f"    Then: python3 -c \"from pwn import *; print(cyclic_find(0x<eip>))\"")

if __name__ == "__main__":
    main()