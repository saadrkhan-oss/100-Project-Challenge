#!/usr/bin/env python3
"""
kernel_defense.py — Linux Kernel Security Defensive Toolkit (Project #71)
Checks mitigations, detects exploitation signs, audits modules.
"""
import os, sys, json, re, subprocess
from datetime import datetime

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

class KernelDefenseToolkit:
    def __init__(self):
        self.report = {
            "timestamp": datetime.now().isoformat(),
            "hostname": os.uname().nodename,
            "kernel": os.uname().release,
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
    # PHASE 1 — Mitigation Verification
    # ------------------------------------------------------------------
    def phase1_mitigations(self):
        print("\n[PHASE 1] KERNEL MITIGATION VERIFICATION")
        results = {}

        # 1. KASLR
        cmdline, _ = self._run("cat /proc/cmdline")
        kaslr_disabled = "nokaslr" in cmdline
        kaslr_enabled = not kaslr_disabled
        print(f"    [KASLR] {'ENABLED' if kaslr_enabled else 'DISABLED (nokaslr)'}")
        print(f"      cmdline: {cmdline[:100]}")
        results["kaslr"] = {"enabled": kaslr_enabled, "cmdline": cmdline}

        # 2. KPTI
        kpti_disabled = "nopti" in cmdline
        kpti_enabled = not kpti_disabled
        print(f"    [KPTI]  {'ENABLED' if kpti_enabled else 'DISABLED (nopti)'}")
        results["kpti"] = {"enabled": kpti_enabled}

        # 3. SMEP / SMAP — check via /proc/cpuinfo flags
        cpuinfo, _ = self._run("grep -m1 flags /proc/cpuinfo")
        has_smep = "smep" in cpuinfo
        has_smap = "smap" in cpuinfo
        print(f"    [SMEP]  {'CPU supports' if has_smep else 'NOT supported'}")
        print(f"    [SMAP]  {'CPU supports' if has_smap else 'NOT supported'}")
        results["smep"] = {"supported": has_smep}
        results["smap"] = {"supported": has_smap}

        # 4. Stack canary
        canary = "unknown"
        try:
            with open("/proc/sys/kernel/randomize_va_space") as f:
                aslr = f.read().strip()
            canary = f"ASLR={aslr}"
        except Exception:
            pass
        print(f"    [ASLR]  randomize_va_space={aslr if 'aslr' in dir() else '?'}")
        results["aslr"] = {"randomize_va_space": aslr if 'aslr' in dir() else "?"}

        # 5. dmesg_restrict
        restrict, _ = self._run("cat /proc/sys/kernel/dmesg_restrict 2>/dev/null")
        print(f"    [DMESG] dmesg_restrict={restrict or '?'}")
        results["dmesg_restrict"] = {"value": restrict or "unknown"}

        # 6. kptr_restrict
        kptr, _ = self._run("cat /proc/sys/kernel/kptr_restrict 2>/dev/null")
        print(f"    [KPTR]  kptr_restrict={kptr or '?'}")
        results["kptr_restrict"] = {"value": kptr or "unknown"}

        self.report["phases"]["mitigations"] = results

    # ------------------------------------------------------------------
    # PHASE 2 — Exploitation Sign Detection (dmesg)
    # ------------------------------------------------------------------
    def phase2_exploitation_signs(self):
        print("\n[PHASE 2] EXPLOITATION SIGN DETECTION (dmesg)")
        dmesg, err = self._run("dmesg 2>/dev/null | tail -100")

        if not dmesg:
            print(f"    [!] dmesg not accessible: {err[:100]}")
            print(f"    [i] This is expected on WSL — dmesg_restrict=1")
            self.report["phases"]["exploitation_signs"] = {"accessible": False}
            return

        # Exploitation indicators
        patterns = {
            "stack_smashing": r"stack smashing detected|Kernel panic.*stack",
            "kernel_oops": r"Oops:|BUG:|kernel NULL pointer|general protection fault",
            "kaslr_leak": r"kernel.*0xffffffff8[0-9a-f]{7}",
            "oob_access": r"out-of-bounds|slab-out-of-bounds|use-after-free",
            "privesc": r"uid=0.*root|commit_creds|prepare_kernel_cred",
        }

        hits = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, dmesg, re.IGNORECASE)
            if matches:
                hits[name] = matches[:5]
                print(f"    [!] {name}: {len(matches)} occurrences")
                for m in matches[:3]:
                    print(f"        {m[:100]}")

        if not hits:
            print(f"    [+] No exploitation signs in last 100 dmesg lines")

        self.report["phases"]["exploitation_signs"] = {
            "accessible": True,
            "hits": hits,
        }

    # ------------------------------------------------------------------
    # PHASE 3 — Kernel Module Audit
    # ------------------------------------------------------------------
    def phase3_module_audit(self):
        print("\n[PHASE 3] KERNEL MODULE AUDIT")
        modules, _ = self._run("lsmod")
        if not modules:
            print(f"    [!] lsmod not available")
            self.report["phases"]["module_audit"] = {"count": 0}
            return

        lines = modules.split("\n")[1:]  # skip header
        mod_names = [l.split()[0] for l in lines if l.strip()]
        print(f"    Loaded modules: {len(mod_names)}")

        # Check for suspicious module names
        suspicious = ["vuln", "exploit", "rootkit", "backdoor", "hack"]
        flagged = [m for m in mod_names if any(s in m.lower() for s in suspicious)]
        if flagged:
            print(f"    [!] Suspicious modules: {flagged}")
        else:
            print(f"    [+] No suspicious module names")

        # Check signature enforcement
        sig, _ = self._run("cat /proc/sys/kernel/module_sig_enforce 2>/dev/null")
        print(f"    [SIG] module_sig_enforce={sig or 'unknown'}")

        self.report["phases"]["module_audit"] = {
            "count": len(mod_names),
            "suspicious": flagged,
            "signature_enforce": sig or "unknown",
        }

    # ------------------------------------------------------------------
    # PHASE 4 — /dev Entry Audit
    # ------------------------------------------------------------------
    def phase4_dev_audit(self):
        print("\n[PHASE 4] /dev ENTRY AUDIT")
        dev_entries, _ = self._run("ls /dev/ 2>/dev/null | head -50")
        if not dev_entries:
            print(f"    [!] /dev not accessible")
            self.report["phases"]["dev_audit"] = {"count": 0}
            return

        entries = dev_entries.split("\n")
        print(f"    /dev entries: {len(entries)}")

        # Look for suspicious device names (ioctl targets)
        suspicious = ["vuln", "exploit", "pwn", "test_dev"]
        flagged = [e for e in entries if any(s in e.lower() for s in suspicious)]
        if flagged:
            print(f"    [!] Suspicious /dev entries: {flagged}")
        else:
            print(f"    [+] No suspicious /dev entries")

        self.report["phases"]["dev_audit"] = {
            "count": len(entries),
            "suspicious": flagged,
        }

    # ------------------------------------------------------------------
    # PHASE 5 — Report
    # ------------------------------------------------------------------
    def phase5_report(self):
        print("\n[PHASE 5] REPORT")

        # Build findings
        confirmed = []
        m = self.report["phases"].get("mitigations", {})
        if not m.get("kaslr", {}).get("enabled", True):
            confirmed.append("mitigation.kaslr_disabled")
        if not m.get("kpti", {}).get("enabled", True):
            confirmed.append("mitigation.kpti_disabled")
        if not m.get("smep", {}).get("supported", True):
            confirmed.append("mitigation.smep_missing")
        if not m.get("smap", {}).get("supported", True):
            confirmed.append("mitigation.smap_missing")

        e = self.report["phases"].get("exploitation_signs", {})
        for k in e.get("hits", {}):
            confirmed.append(f"exploitation.{k}")

        mod = self.report["phases"].get("module_audit", {})
        for s in mod.get("suspicious", []):
            confirmed.append(f"module.suspicious ({s})")

        dev = self.report["phases"].get("dev_audit", {})
        for s in dev.get("suspicious", []):
            confirmed.append(f"dev.suspicious ({s})")

        # Positive findings (mitigations enabled)
        positive = []
        if m.get("kaslr", {}).get("enabled"):
            positive.append("KASLR enabled")
        if m.get("kpti", {}).get("enabled"):
            positive.append("KPTI enabled")
        if m.get("smep", {}).get("supported"):
            positive.append("SMEP supported")
        if m.get("smap", {}).get("supported"):
            positive.append("SMAP supported")

        print(f"\n    Positive (mitigations): {len(positive)}")
        for p in positive:
            print(f"      [+] {p}")

        print(f"\n    Negative (findings): {len(confirmed)}")
        for c in confirmed:
            print(f"      [!] {c}")

        if not confirmed:
            print(f"    [+] No kernel security issues detected")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/kernel_defense_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/kernel_defense_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(positive, confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, positive, confirmed):
        pos_li = "".join(f"<li class='ok'>✓ {p}</li>" for p in positive)
        neg_li = "".join(f"<li class='bad'>✗ {c}</li>" for c in confirmed) or "<li class='ok'>✓ No findings</li>"
        return f"""<!DOCTYPE html>
<html><head><title>Kernel Defense Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#4488ff; }} h2 {{ color:#55ff55; border-bottom:1px solid #333; }}
ul {{ list-style:none; padding:0; }}
li {{ padding:5px; margin:3px 0; }}
.ok {{ color:#55ff55; }}
.bad {{ color:#ff4444; }}
</style></head><body>
<h1>Linux Kernel Defense Report</h1>
<p><b>Hostname:</b> {self.report['hostname']}</p>
<p><b>Kernel:</b> {self.report['kernel']}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<h2>Mitigations ({len(positive)})</h2>
<ul>{pos_li}</ul>
<h2>Findings ({len(confirmed)})</h2>
<ul>{neg_li}</ul>
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Linux Kernel Defense Toolkit - Project #71")
        print("=" * 64)
        print(f"[+] Hostname: {self.report['hostname']}")
        print(f"[+] Kernel:   {self.report['kernel']}")
        self.phase1_mitigations()
        self.phase2_exploitation_signs()
        self.phase3_module_audit()
        self.phase4_dev_audit()
        self.phase5_report()

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("ERROR: Linux only")
        sys.exit(1)
    KernelDefenseToolkit().run_all()
