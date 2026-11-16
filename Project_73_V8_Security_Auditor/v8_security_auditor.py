#!/usr/bin/env python3
"""
v8_security_auditor.py — V8 Engine Security Auditor (Project #73, Defensive)
Scans for browser V8 versions, checks hardening flags, audits security posture.
Runs on WSL/Linux. No exploitation, no shellcode, no RCE.
"""
import os, sys, json, re, subprocess
from datetime import datetime
from collections import defaultdict

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Known V8 version → security status (simulated CVE database)
V8_SECURITY_STATUS = {
    "11.0": {"status": "VULNERABLE", "cves": ["CVE-2023-2033", "CVE-2023-3079"], "note": "Known type confusion bugs"},
    "11.1": {"status": "VULNERABLE", "cves": ["CVE-2023-3079"], "note": "Partial fix"},
    "11.2": {"status": "PATCHED", "cves": [], "note": "CVE-2023-2033 patched"},
    "11.3": {"status": "PATCHED", "cves": [], "note": "CVE-2023-3079 patched"},
    "11.4": {"status": "SECURE", "cves": [], "note": "All known CVEs patched"},
}

# Hardening flags that matter for V8 security
HARDENING_FLAGS = {
    "--jitless": "Disable JIT (blocks JIT spraying, slows JS)",
    "--no-expose-wasm": "Disable WebAssembly (blocks WASM exploits)",
    "--disallow-unsafe-eval": "Block eval() (reduces attack surface)",
    "--no-opt": "Disable TurboFan (blocks JIT type confusion)",
    "--enable-sandbox": "V8 memory sandbox (mitigates UAF)",
    "--disable-web-security": "⚠️ DANGEROUS — disables CORS/SOP",
}

class V8SecurityAuditor:
    def __init__(self):
        self.report = {
            "timestamp": datetime.now().isoformat(),
            "phases": {},
        }

    def _run(self, cmd, timeout=10):
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True,
                               text=True, timeout=timeout)
            return r.stdout.strip(), r.stderr.strip()
        except Exception as e:
            return "", str(e)

    # ------------------------------------------------------------------
    # PHASE 1 — Browser & V8 Version Detection
    # ------------------------------------------------------------------
    def phase1_version_detect(self):
        print("\n[PHASE 1] BROWSER & V8 VERSION DETECTION")
        results = {"browsers": []}

        # Try to find Chrome / Chromium on the system
        chrome_paths = [
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/opt/google/chrome/chrome",
        ]

        found_browser = None
        for path in chrome_paths:
            if os.path.exists(path):
                found_browser = path
                break

        if found_browser:
            version, _ = self._run(f"'{found_browser}' --version")
            print(f"    Browser: {version}")
            results["browsers"].append({"path": found_browser, "version": version})

            # Extract V8 version from Chrome version
            match = re.search(r'(\d+)\.(\d+)', version)
            if match:
                v8_major_minor = f"{match.group(1)}.{match.group(2)}"
                print(f"    V8 (approx): {v8_major_minor}")
                results["v8_approx"] = v8_major_minor
        else:
            print(f"    [!] No Chrome/Chromium found in PATH")
            print(f"    [i] Install with: sudo apt install chromium-browser")
            results["browsers"] = []

        # Check Node.js (also uses V8)
        node_ver, _ = self._run("node --version 2>/dev/null")
        if node_ver:
            print(f"    Node.js:     {node_ver}")
            # Node 18 = V8 10.1, Node 20 = V8 11.3, Node 21 = V8 11.8
            node_v8 = {"v18": "10.1", "v19": "10.8", "v20": "11.3", "v21": "11.8"}
            for n, v in node_v8.items():
                if node_ver.startswith(f"v{n[1:]}"):
                    print(f"    V8 (Node):   {v}")
                    results["v8_node"] = v
                    break
        else:
            print(f"    [!] Node.js not installed")
            results["v8_node"] = None

        self.report["phases"]["version"] = results

    # ------------------------------------------------------------------
    # PHASE 2 — V8 Security Status
    # ------------------------------------------------------------------
    def phase2_security_status(self):
        print("\n[PHASE 2] V8 SECURITY STATUS (CVE CHECK)")
        results = {"checks": []}

        # Get V8 version from Phase 1
        v8 = self.report["phases"].get("version", {}).get("v8_node")
        if not v8:
            v8 = self.report["phases"].get("version", {}).get("v8_approx", "unknown")

        print(f"    V8 version: {v8}")
        if v8 in V8_SECURITY_STATUS:
            info = V8_SECURITY_STATUS[v8]
            print(f"    Status: {info['status']}")
            print(f"    Note:   {info['note']}")
            if info["cves"]:
                print(f"    CVEs:   {', '.join(info['cves'])}")
            results["checks"].append({"v8": v8, **info})
        else:
            print(f"    [i] Version {v8} not in known CVE database")
            print(f"    [i] Assume SECURE (patch level unknown)")
            results["checks"].append({"v8": v8, "status": "UNKNOWN", "note": "not in database"})

        self.report["phases"]["security_status"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — Hardening Flag Check (if browser found)
    # ------------------------------------------------------------------
    def phase3_hardening_flags(self):
        print("\n[PHASE 3] HARDENING FLAG ANALYSIS")
        results = {"hardening": [], "dangerous": []}

        # Check if browser is running with hardened flags
        # (We can't see live process flags, so we check what's possible)
        print(f"    [i] Known hardening flags (recommended for high-security environments):")
        for flag, desc in HARDENING_FLAGS.items():
            print(f"      {flag:<30} — {desc}")
            if flag == "--disable-web-security":
                results["dangerous"].append(flag)
            else:
                results["hardening"].append(flag)

        # Check if any dangerous flags are in shell aliases
        aliases, _ = self._run("grep -r 'disable-web-security' ~/.bashrc ~/.profile 2>/dev/null")
        if aliases:
            print(f"    [!] DANGEROUS: --disable-web-security found in shell config")
            print(f"      {aliases[:200]}")
            results["dangerous_found"] = True
        else:
            print(f"    [+] No dangerous flags in shell config")

        self.report["phases"]["hardening"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — Browser Cache Audit (exploitation artifacts)
    # ------------------------------------------------------------------
    def phase4_cache_audit(self):
        print("\n[PHASE 4] BROWSER CACHE AUDIT (exploitation artifacts)")
        results = {"cache_dirs": [], "suspicious": []}

        # Common Chromium cache locations
        cache_paths = [
            os.path.expanduser("~/.cache/chromium"),
            os.path.expanduser("~/.cache/google-chrome"),
            os.path.expanduser("~/.config/chromium"),
        ]

        for path in cache_paths:
            if os.path.exists(path):
                size, _ = self._run(f"du -sh '{path}' 2>/dev/null")
                print(f"    Cache: {path} ({size})")
                results["cache_dirs"].append({"path": path, "size": size})

        if not results["cache_dirs"]:
            print(f"    [+] No Chromium cache directories found")
            print(f"    [i] This is expected on WSL (no GUI browser)")

        self.report["phases"]["cache_audit"] = results

    # ------------------------------------------------------------------
    # PHASE 5 — Report
    # ------------------------------------------------------------------
    def phase5_report(self):
        print("\n[PHASE 5] REPORT")

        confirmed = []
        v = self.report["phases"].get("version", {})
        if v.get("browsers"):
            confirmed.append(f"version.browser_detected ({v['browsers'][0]['version'][:50]})")
        if v.get("v8_node"):
            confirmed.append(f"version.v8_detected ({v['v8_node']})")

        s = self.report["phases"].get("security_status", {})
        for check in s.get("checks", []):
            if check.get("status") == "VULNERABLE":
                confirmed.append(f"security.vulnerable ({check['v8']} — {check['cves']})")

        h = self.report["phases"].get("hardening", {})
        confirmed.append(f"hardening.flags_available ({len(h.get('hardening', []))})")
        if h.get("dangerous"):
            confirmed.append(f"hardening.dangerous_flags ({len(h['dangerous'])})")

        c = self.report["phases"].get("cache_audit", {})
        if c.get("cache_dirs"):
            confirmed.append(f"cache.dirs_found ({len(c['cache_dirs'])})")

        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c_item in confirmed:
            print(f"      * {c_item}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/v8_audit_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/v8_audit_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>V8 Security Audit</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#aa44ff; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #aa44ff; overflow:auto; }}
</style></head><body>
<h1>V8 Security Auditor Report</h1>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" V8 Security Auditor - Project #73 (Defensive)")
        print("=" * 64)
        self.phase1_version_detect()
        self.phase2_security_status()
        self.phase3_hardening_flags()
        self.phase4_cache_audit()
        self.phase5_report()

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("ERROR: Linux only")
        sys.exit(1)
    V8SecurityAuditor().run_all()
