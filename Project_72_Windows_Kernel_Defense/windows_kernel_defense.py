#!/usr/bin/env python3
"""
windows_kernel_defense.py — Windows Kernel Defense Toolkit (Project #72)
Verifies mitigations, audits drivers, detects exploitation signs.
Runs on Windows (not WSL).
"""
import os, sys, json, subprocess, re
from datetime import datetime

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

def run_ps(cmd, timeout=15):
    """Run PowerShell command, return stdout."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return "", str(e)

class WindowsKernelDefense:
    def __init__(self):
        self.report = {
            "timestamp": datetime.now().isoformat(),
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "phases": {},
        }

    # ------------------------------------------------------------------
    # PHASE 1 — Mitigation Verification
    # ------------------------------------------------------------------
    def phase1_mitigations(self):
        print("\n[PHASE 1] MITIGATION VERIFICATION")
        results = {}

        # 1. DEP (Data Execution Prevention)
        dep, _ = run_ps("bcdedit /enum {current} | findstr nx")
        dep_enabled = "OptIn" in dep or "AlwaysOn" in dep or "OptOut" in dep
        print(f"    [DEP]   {'ENABLED' if dep_enabled else 'DISABLED'}")
        results["dep"] = {"enabled": dep_enabled, "raw": dep[:100]}

        # 2. KASLR — check if kernel randomization is on
        # Windows uses "Kernel ASLR" which is on by default; check via registry
        kaslr, _ = run_ps("Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management' -Name 'MoveImages' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MoveImages")
        kaslr_enabled = kaslr != "0"
        print(f"    [KASLR] {'ENABLED' if kaslr_enabled else 'DISABLED'}")
        results["kaslr"] = {"enabled": kaslr_enabled, "raw": kaslr[:50]}

        # 3. SMEP — CPU feature
        smep, _ = run_ps("(Get-CimInstance Win32_Processor).VirtualizationFirmwareEnabled")
        smep_supported = "True" in smep
        print(f"    [SMEP]  {'CPU supports' if smep_supported else 'NOT supported'}")
        results["smep"] = {"supported": smep_supported, "raw": smep[:50]}

        # 4. CFG (Control Flow Guard)
        cfg, _ = run_ps("(Get-ProcessMitigation -System).Cfg | Select-String -Pattern 'Enable' -SimpleMatch | Select-Object -First 1")
        cfg_enabled = "Enable" in cfg
        print(f"    [CFG]   {'ENABLED' if cfg_enabled else 'DISABLED'}")
        results["cfg"] = {"enabled": cfg_enabled, "raw": cfg[:50]}

        # 5. CET (Control-flow Enforcement Technology)
        cet, _ = run_ps("(Get-ProcessMitigation -System).Cet | Select-String -Pattern 'Enable' -SimpleMatch | Select-Object -First 1")
        cet_enabled = "Enable" in cet
        print(f"    [CET]   {'ENABLED' if cet_enabled else 'DISABLED'}")
        results["cet"] = {"enabled": cet_enabled, "raw": cet[:50]}

        # 6. HVCI (Hypervisor-protected Code Integrity / Memory Integrity)
        hvci, _ = run_ps("(Get-CimInstance -ClassName Win32_DeviceGuard).SecurityServicesRunning")
        hvci_enabled = "2" in hvci or "1" in hvci
        print(f"    [HVCI]  {'ENABLED (Memory Integrity)' if hvci_enabled else 'DISABLED'}")
        results["hvci"] = {"enabled": hvci_enabled, "raw": hvci[:50]}

        self.report["phases"]["mitigations"] = results

    # ------------------------------------------------------------------
    # PHASE 2 — Driver Audit
    # ------------------------------------------------------------------
    def phase2_driver_audit(self):
        print("\n[PHASE 2] DRIVER AUDIT")
        results = {"loaded": 0, "unsigned": [], "suspicious": []}

        # Loaded drivers count
        drivers, _ = run_ps("driverquery /v")
        driver_lines = [l for l in drivers.split("\n") if l.strip() and not l.startswith("Module Name")]
        results["loaded"] = len(driver_lines)
        print(f"    Loaded drivers: {results['loaded']}")

        # Suspicious names
        suspicious_patterns = ["vuln", "exploit", "rootkit", "backdoor", "hack", "test"]
        driver_names = [l.split()[0].lower() for l in driver_lines if l.strip()]
        suspicious = [d for d in driver_names if any(p in d for p in suspicious_patterns)]
        results["suspicious"] = suspicious
        if suspicious:
            print(f"    [!] Suspicious names: {suspicious[:5]}")
        else:
            print(f"    [+] No suspicious driver names")

        # Unsigned drivers (check a sample — full scan is slow)
        unsigned, _ = run_ps("Get-AuthenticodeSignature 'C:\\Windows\\System32\\drivers\\*.sys' | Where-Object { $_.Status -ne 'Valid' } | Select-Object -First 5 -ExpandProperty Path")
        unsigned_list = [u.strip() for u in unsigned.split("\n") if u.strip()]
        results["unsigned"] = unsigned_list
        if unsigned_list:
            print(f"    [!] Unsigned drivers: {len(unsigned_list)} found")
        else:
            print(f"    [+] All sampled drivers are signed")

        self.report["phases"]["driver_audit"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — Exploitation Detection
    # ------------------------------------------------------------------
    def phase3_exploitation(self):
        print("\n[PHASE 3] EXPLOITATION DETECTION")
        results = {"crash_dumps": [], "bsod_count": 0}

        # Crash dumps
        dumps, _ = run_ps("Get-ChildItem 'C:\\Windows\\Minidump\\*.dmp' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name")
        dump_list = [d.strip() for d in dumps.split("\n") if d.strip()]
        results["crash_dumps"] = dump_list
        print(f"    Crash dumps: {len(dump_list)} found")
        for d in dump_list[:3]:
            print(f"      - {d}")

        # BSOD events (Event ID 1001 = BugCheck)
        bsod, _ = run_ps("Get-WinEvent -FilterHashtable @{LogName='System'; ID=1001} -MaxEvents 10 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count")
        bsod_count = int(bsod) if bsod.strip().isdigit() else 0
        results["bsod_count"] = bsod_count
        print(f"    BSOD events (ID 1001): {bsod_count}")

        # Kernel panic (Event ID 41 = unexpected shutdown)
        panic, _ = run_ps("Get-WinEvent -FilterHashtable @{LogName='System'; ID=41} -MaxEvents 10 -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count")
        panic_count = int(panic) if panic.strip().isdigit() else 0
        results["panic_count"] = panic_count
        print(f"    Kernel panics (ID 41): {panic_count}")

        self.report["phases"]["exploitation"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — Hardening Check
    # ------------------------------------------------------------------
    def phase4_hardening(self):
        print("\n[PHASE 4] HARDENING CHECK")
        results = {}

        # Secure Boot
        sb, _ = run_ps("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue")
        sb_enabled = "True" in sb
        print(f"    [SECURE_BOOT] {'ENABLED' if sb_enabled else 'DISABLED'}")
        results["secure_boot"] = {"enabled": sb_enabled}

        # Test signing
        ts, _ = run_ps("bcdedit /enum {current} | findstr testsigning")
        ts_disabled = "testsigning" not in ts.lower() or "Yes" not in ts
        print(f"    [DRIVER_SIGNING] {'ENFORCED' if ts_disabled else 'TEST SIGNING ENABLED'}")
        results["driver_signing"] = {"enforced": ts_disabled}

        # ASLR
        aslr, _ = run_ps("(Get-ProcessMitigation -System).Aslr | Select-String -Pattern 'Enable' -SimpleMatch | Select-Object -First 1")
        aslr_enabled = "Enable" in aslr
        print(f"    [ASLR] {'ENABLED' if aslr_enabled else 'DISABLED'}")
        results["aslr"] = {"enabled": aslr_enabled}

        # CFI (Control Flow Integrity)
        cfi, _ = run_ps("(Get-ProcessMitigation -System).Cfg | Select-String -Pattern 'Enable' -SimpleMatch | Select-Object -First 1")
        cfi_enabled = "Enable" in cfi
        print(f"    [CFI] {'ENABLED' if cfi_enabled else 'DISABLED'}")
        results["cfi"] = {"enabled": cfi_enabled}

        enabled_count = sum(1 for v in results.values() if v.get("enabled") or v.get("enforced"))
        print(f"    [+] {enabled_count}/{len(results)} hardening features enabled")
        self.report["phases"]["hardening"] = results

    # ------------------------------------------------------------------
    # PHASE 5 — Report
    # ------------------------------------------------------------------
    def phase5_report(self):
        print("\n[PHASE 5] REPORT")

        confirmed = []
        m = self.report["phases"].get("mitigations", {})
        for k in ["dep", "kaslr", "smep", "cfg", "cet", "hvci"]:
            v = m.get(k, {})
            if v.get("enabled") or v.get("supported"):
                confirmed.append(f"mitigation.{k}_enabled")
            else:
                confirmed.append(f"mitigation.{k}_disabled")

        d = self.report["phases"].get("driver_audit", {})
        if d.get("unsigned"):
            confirmed.append(f"driver.unsigned ({len(d['unsigned'])})")
        if d.get("suspicious"):
            confirmed.append(f"driver.suspicious ({len(d['suspicious'])})")

        e = self.report["phases"].get("exploitation", {})
        if e.get("crash_dumps"):
            confirmed.append(f"exploitation.crash_dumps ({len(e['crash_dumps'])})")
        if e.get("bsod_count", 0) > 0:
            confirmed.append(f"exploitation.bsod ({e['bsod_count']})")
        if e.get("panic_count", 0) > 0:
            confirmed.append(f"exploitation.panic ({e['panic_count']})")

        h = self.report["phases"].get("hardening", {})
        for k, v in h.items():
            if v.get("enabled") or v.get("enforced"):
                confirmed.append(f"hardening.{k}_enabled")

        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/windows_kernel_defense_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/windows_kernel_defense_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Windows Kernel Defense</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#4488ff; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #4488ff; overflow:auto; }}
</style></head><body>
<h1>Windows Kernel Defense Report</h1>
<p><b>Hostname:</b> {self.report['hostname']}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Windows Kernel Defense Toolkit - Project #72")
        print("=" * 64)
        print(f"[+] Hostname: {self.report['hostname']}")
        self.phase1_mitigations()
        self.phase2_driver_audit()
        self.phase3_exploitation()
        self.phase4_hardening()
        self.phase5_report()

if __name__ == "__main__":
    if sys.platform != "win32":
        print("ERROR: This toolkit must run on Windows.")
        sys.exit(1)
    WindowsKernelDefense().run_all()
