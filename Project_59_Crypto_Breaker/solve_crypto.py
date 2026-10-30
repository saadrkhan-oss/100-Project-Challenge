#!/usr/bin/env python3
"""solve_crypto.py — Auto-generated (Project #59)"""

CIPHERTEXT = bytes.fromhex("150902153e17650a15171d1a1d640c03161c38")
KEY = bytes.fromhex("53454352455437")

def xor_decrypt(ciphertext, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))

if __name__ == "__main__":
    plaintext = xor_decrypt(CIPHERTEXT, KEY)
    print(f"Plaintext: {plaintext.decode()}")
    import re
    m = re.search(rb"FLAG\{[^}]+\}", plaintext)
    if m:
        print(f"Flag: {m.group(0).decode()}")
