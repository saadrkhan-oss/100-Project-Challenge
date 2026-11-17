#!/usr/bin/env python3
"""
android_kernel_auditor.py — Android Kernel Security Auditor (Project #74)
Defensive audit of Android kernel mitigations, SELinux, CVEs, bootloader.
"""
import os, sys, json, re, subprocess
from datetime import datetime

MOCK_DIR = "mock"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# CVE kernel version ranges
CVE_RANGES = {
    "dirty_pipe":  {"min": (5, 8),  "max": (5, 16, 11), "name": "CVE-2022-0847 (Dirty Pipe)"},
    "dirty_cow":   {"min": (2, 6, 22), "max": (3, 9), "name": "CVE-2016-5195 (Dirty COW)"},
}

def parse_kernel_version(ver_str):
    """Parse '5.10.101-android13-...' → (5, 10, 101)"""
    m = re.match(r'(\d+)\.(\d+)(?:\.(\d+))?', ver_str)
    if not m:
        return None
    return tuple(int(x) if x else 0 for x in m.groups())

def version_in_range(version, min_v, max_v):
    """Check if version tuple is >= min_v and < max_v"""
    # Pad to same length
    max_len = max(len(version), len(min_v), len(max_v))
    v = version + (0,) * (max_len - len(version))
    mn = min_v + (0,) * (max_len - len(min_v))
    mx = max_v + (0,) * (max_len - len(max_v))
    return mn <= v < mx

class AndroidKernelAuditor:
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

    def _load_device(self):
        """Load mock device profile (or real ADB if available)."""
        adb, _ = self._run("adb devices 2>/dev/null | grep -v 'List of devices' | grep device")
        if adb:
            print(f"    [+] ADB device detected: {adb[:50]}")
            # In real deployment, we'd call adb shell getprop here
            # For this lab, fall back to mock
        print(f"    [i] Using mock device profile (simulated)")
        with open(os.path.join(MOCK_DIR, "device.json")) as f:
            return json.load(f)

    # ------------------------------------------------------------------
    # PHASE 1 — Version Detection
    # ------------------------------------------------------------------
    def phase1_version(self):
        print("\n[PHASE 1] KERNEL VERSION DETECTION")
        d = self._load_device()

        print(f"    Android:        {d['build']['android_version']}")
        print(f"    SDK:            {d['build']['sdk']}")
        print(f"    Kernel:         {d['kernel']['version']}")
        print(f"    Security patch: {d['build']['security_patch']}")
        print(f"    Build ID:       {d['build']['build_id']}")

        self.device = d
        self.report["phases"]["version"] = d["build"]

    # ------------------------------------------------------------------
    # PHASE 2 — Mitigation Verification
    # ------------------------------------------------------------------
    def phase2_mitigations(self):
        print("\n[PHASE 2] MITIGATION VERIFICATION")
        d = self.device
        results = {}

        # KASLR — check cmdline for "nokaslr"
        kaslr_disabled = "nokaslr" in d["cmdline"]
        kaslr = not kaslr_disabled
        print(f"    [KASLR]          {'ENABLED' if kaslr else 'DISABLED'}")
        results["kaslr"] = {"enabled": kaslr}

        # PXN — CPU flag
        pxn = "pxn" in d["cpu_flags"]
        print(f"    [PXN]            {'ENABLED' if pxn else 'DISABLED'}")
        results["pxn"] = {"enabled": pxn}

        # PAN — CPU flag
        pan = "pan" in d["cpu_flags"]
        print(f"    [PAN]            {'ENABLED' if pan else 'DISABLED'}")
        results["pan"] = {"enabled": pan}

        # SELinux
        selinux = d["selinux"]["getenforce"]
        selinux_ok = selinux.lower() == "enforcing"
        print(f"    [SELINUX]        {selinux} {'(GOOD)' if selinux_ok else '(WEAK)'}")
        results["selinux"] = {"state": selinux, "enforcing": selinux_ok}

        # Verified Boot
        vb = d["bootloader"]["verified_boot_state"]
        vb_ok = vb.lower() == "green"
        print(f"    [VERIFIED_BOOT]  {vb.upper()} {'(GOOD)' if vb_ok else '(WEAK)'}")
        results["verified_boot"] = {"state": vb, "green": vb_ok}

        self.report["phases"]["mitigations"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — SELinux Policy Audit
    # ------------------------------------------------------------------
    def phase3_selinux(self):
        print("\n[PHASE 3] SELINUX POLICY AUDIT")
        d = self.device
        results = {}

        getenforce = d["selinux"]["getenforce"]
        boot_selinux = d["selinux"]["boot_selinux"]

        print(f"    [ENFORCING]  {getenforce}")
        print(f"    [POLICY]     Loaded")
        print(f"    [PERMISSIVE] {'YES (WEAK)' if getenforce.lower() != 'enforcing' else 'NO (GOOD)'}")

        if getenforce.lower() == "enforcing":
            print(f"    [+] SELinux is enforcing (good)")
        else:
            print(f"    [!] SELinux is NOT enforcing (CRITICAL)")

        results["getenforce"] = getenforce
        results["enforcing"] = getenforce.lower() == "enforcing"

        self.report["phases"]["selinux"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — CVE Check
    # ------------------------------------------------------------------
    def phase4_cve_check(self):
        print("\n[PHASE 4] CVE CHECK")
        d = self.device
        kv = parse_kernel_version(d["kernel"]["version"])
        print(f"    Kernel version: {kv}")

        results = {}
        for cve_id, info in CVE_RANGES.items():
            min_v, max_v = info["min"], info["max"]
            vulnerable = version_in_range(kv, min_v, max_v)
            status = "VULNERABLE" if vulnerable else "NOT VULNERABLE"
            print(f"    [{cve_id.upper():<12}] {status:<15} ({info['name']})")
            results[cve_id] = {
                "name": info["name"],
                "vulnerable": vulnerable,
                "kernel_range": f">={'.'.join(map(str,min_v))} <{'.'.join(map(str,max_v))}",
            }

        # PwnKit — based on security patch date
        patch = d["build"]["security_patch"]
        pwnkit_patched = patch >= "2021-11-01"
        print(f"    [PWNKIT]      {'PATCHED' if pwnkit_patched else 'VULNERABLE'} (security patch {patch})")
        results["pwnkit"] = {"patched": pwnkit_patched, "patch_date": patch}

        self.report["phases"]["cve"] = results

    # ------------------------------------------------------------------
    # PHASE 5 — Bootloader Audit
    # ------------------------------------------------------------------
    def phase5_bootloader(self):
        print("\n[PHASE 5] BOOTLOADER AUDIT")
        d = self.device
        results = {}

        locked = d["bootloader"]["flash_locked"] == "1"
        vb_state = d["bootloader"]["verified_boot_state"]
        verity = d["bootloader"]["verity_mode"]

        print(f"    [LOCKED]        {'YES (GOOD)' if locked else 'NO (WEAK)'}")
        print(f"    [VERIFIED_BOOT] {vb_state.upper()} {'(GOOD)' if vb_state == 'green' else '(WEAK)'}")
        print(f"    [UNLOCKED]      {'NO' if locked else 'YES'}")
        print(f"    [VERITY]        {verity}")

        if locked and vb_state == "green":
            print(f"    [+] Bootloader is locked and verified (good)")
        else:
            print(f"    [!] Bootloader integrity issue detected")

        results["locked"] = locked
        results["verified_boot_state"] = vb_state
        results["verity_mode"] = verity

        self.report["phases"]["bootloader"] = results

    # ------------------------------------------------------------------
    # PHASE 6 — Report
    # ------------------------------------------------------------------
    def phase6_report(self):
        print("\n[PHASE 6] REPORT")

        confirmed = []
        # Version
        confirmed.append(f"version.android_{self.report['phases']['version']['android_version']}")

        # Mitigations
        m = self.report["phases"]["mitigations"]
        for k in ["kaslr", "pxn", "pan"]:
            if m[k]["enabled"]:
                confirmed.append(f"mitigation.{k}_enabled")
        if m["selinux"]["enforcing"]:
            confirmed.append("mitigation.selinux_enforcing")
        if m["verified_boot"]["green"]:
            confirmed.append("mitigation.verified_boot")

        # SELinux
        if self.report["phases"]["selinux"]["enforcing"]:
            confirmed.append("selinux.enforcing")

        # CVEs
        cve = self.report["phases"]["cve"]
        for k, v in cve.items():
            if k == "pwnkit":
                if v["patched"]:
                    confirmed.append("cve.pwnkit_patched")
            elif not v["vulnerable"]:
                confirmed.append(f"cve.{k}_not_vulnerable")

        # Bootloader
        if self.report["phases"]["bootloader"]["locked"]:
            confirmed.append("bootloader.locked")

        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        # Summary verdict
        vuln_count = sum(1 for k, v in cve.items()
                         if k != "pwnkit" and v["vulnerable"])
        if not m["selinux"]["enforcing"]:
            vuln_count += 1
        if not self.report["phases"]["bootloader"]["locked"]:
            vuln_count += 1

        verdict = "SECURE" if vuln_count == 0 else f"ISSUES ({vuln_count})"
        print(f"\n    [VERDICT] {verdict}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/android_kernel_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/android_kernel_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed, verdict))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed, verdict):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Android Kernel Audit</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#44cc44; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #44cc44; overflow:auto; }}
.verdict {{ font-size:1.5em; padding:10px; background:#1a3a1a; border-left:4px solid #55ff55; }}
</style></head><body>
<h1>Android Kernel Security Audit</h1>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p class="verdict"><b>Verdict:</b> {verdict}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Android Kernel Security Auditor - Project #74")
        print("=" * 64)
        self.phase1_version()
        self.phase2_mitigations()
        self.phase3_selinux()
        self.phase4_cve_check()
        self.phase5_bootloader()
        self.phase6_report()

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("ERROR: Linux only")
        sys.exit(1)
    AndroidKernelAuditor().run_all()
