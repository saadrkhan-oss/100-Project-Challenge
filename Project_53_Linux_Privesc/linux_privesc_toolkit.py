#!/usr/bin/env python3
"""
linux_privesc_toolkit.py — Linux Privilege Escalation Toolkit (Project #53)
Runs on Linux. Enumerates system, SUID, perms, cron, creds, kernel exploits.
"""
import os
import sys
import subprocess
import json
import re
import stat
import socket
from datetime import datetime
from pathlib import Path

REPORTS_DIR = "reports"
EXTRACTED_DIR = "extracted"

def run_cmd(cmd, timeout=30):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, errors="ignore"
        )
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT"
    except Exception as e:
        return "", str(e)

def is_root():
    return os.geteuid() == 0

class LinuxPrivescToolkit:
    def __init__(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(EXTRACTED_DIR, exist_ok=True)
        self.report = {
            "hostname": socket.gethostname(),
            "username": os.environ.get("USER", "unknown"),
            "is_root": is_root(),
            "timestamp": datetime.now().isoformat(),
            "phases": {}
        }

    # ------------------------------------------------------------------
    # PHASE 1 — System Enumeration
    # ------------------------------------------------------------------
    def phase1_system_enum(self):
        print("\n[PHASE 1] SYSTEM ENUMERATION")
        results = {}

        kernel, _ = run_cmd("uname -r")
        print(f"    Kernel: {kernel}")
        results["kernel"] = kernel

        uname, _ = run_cmd("uname -a")
        results["uname"] = uname

        os_rel, _ = run_cmd("cat /etc/os-release")
        os_name = "Unknown"
        for line in os_rel.split("\n"):
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[1].strip().strip('"')
        print(f"    OS: {os_name}")
        results["os"] = os_name

        users, _ = run_cmd("cat /etc/passwd")
        user_lines = [l for l in users.split("\n") if l and not l.startswith("#")]
        print(f"    Users: {len(user_lines)}")
        results["user_count"] = len(user_lines)
        results["users"] = [l.split(":")[0] for l in user_lines]

        groups, _ = run_cmd("cat /etc/group")
        group_lines = [l for l in groups.split("\n") if l and not l.startswith("#")]
        print(f"    Groups: {len(group_lines)}")
        results["group_count"] = len(group_lines)

        sudo, _ = run_cmd("sudo -n -l 2>&1")
        if "NOPASSWD" in sudo or "may run" in sudo:
            print(f"    Sudo: configured")
            results["sudo"] = sudo[:2000]
        else:
            print(f"    Sudo: not available (no password or no privileges)")
            results["sudo"] = "N/A"

        self.report["phases"]["system_enum"] = results

    # ------------------------------------------------------------------
    # PHASE 2 — SUID / SGID / Capabilities
    # ------------------------------------------------------------------
    def phase2_suid_sgid(self):
        print("\n[PHASE 2] SUID / SGID ENUMERATION")
        results = {}

        print("  [SUID] Scanning...")
        out, _ = run_cmd(
            "find / -perm -4000 -type f 2>/dev/null", timeout=120
        )
        suid = [l for l in out.split("\n") if l.strip()]
        print(f"    SUID binaries: {len(suid)}")

        interesting = ["find", "vim", "nmap", "less", "more",
                       "awk", "python", "python3", "bash", "sh",
                       "nano", "cp", "mv", "tar", "systemctl"]
        vuln = [s for s in suid if any(i in s.lower() for i in interesting)]
        if vuln:
            for v in vuln:
                print(f"    [!] VULNERABLE: {v}")

        results["suid_count"] = len(suid)
        results["suid_vulnerable"] = vuln

        print("  [SGID] Scanning...")
        out, _ = run_cmd(
            "find / -perm -2000 -type f 2>/dev/null", timeout=120
        )
        sgid = [l for l in out.split("\n") if l.strip()]
        print(f"    SGID binaries: {len(sgid)}")
        results["sgid_count"] = len(sgid)

        print("  [CAPABILITIES] Scanning...")
        out, _ = run_cmd("getcap -r / 2>/dev/null", timeout=60)
        caps = [l for l in out.split("\n") if l.strip()]
        print(f"    Files with capabilities: {len(caps)}")
        results["capabilities"] = caps[:30]

        self.report["phases"]["suid_sgid"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — Weak Permissions
    # ------------------------------------------------------------------
    def phase3_weak_perms(self):
        print("\n[PHASE 3] WEAK PERMISSIONS")
        results = {}

        print("  [SUDO NOPASSWD] Checking sudoers...")
        out1, _ = run_cmd("cat /etc/sudoers 2>/dev/null")
        out2, _ = run_cmd("cat /etc/sudoers.d/* 2>/dev/null")
        sudoers_text = out1 + "\n" + out2
        nopass = [l for l in sudoers_text.split("\n") if "NOPASSWD" in l and not l.startswith("#")]
        if nopass:
            print(f"    [!] NOPASSWD entries: {len(nopass)}")
            for n in nopass[:5]:
                print(f"        {n.strip()}")
        else:
            print(f"    No NOPASSWD entries")
        results["nopasswd"] = nopass

        print("  [WRITABLE /etc] Checking critical config dirs...")
        critical_dirs = ["/etc", "/etc/cron.d", "/etc/cron.daily", "/var/spool/cron"]
        writable = []
        for d in critical_dirs:
            if os.path.exists(d):
                try:
                    st = os.stat(d)
                    if st.st_mode & stat.S_IWOTH:
                        writable.append({"dir": d, "perm": oct(st.st_mode)})
                        print(f"    [!] WORLD-WRITABLE: {d}")
                except Exception:
                    pass
        results["world_writable_dirs"] = writable

        print("  [WRITABLE /tmp FILES] (user-owned)")
        out, _ = run_cmd("find /tmp -user $USER -type f 2>/dev/null | head -20")
        tmp_files = [l for l in out.split("\n") if l.strip()]
        print(f"    User files in /tmp: {len(tmp_files)}")
        results["tmp_files"] = tmp_files

        self.report["phases"]["weak_perms"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — Cron Jobs
    # ------------------------------------------------------------------
    def phase4_cron(self):
        print("\n[PHASE 4] CRON JOBS")
        results = {}

        print("  [USER CRONTAB]")
        out, _ = run_cmd("crontab -l 2>&1")
        if "no crontab" in out.lower():
            print("    No user crontab")
            results["user_crontab"] = []
        else:
            cron_lines = [l for l in out.split("\n") if l and not l.startswith("#")]
            print(f"    User cron entries: {len(cron_lines)}")
            for c in cron_lines[:5]:
                print(f"      {c}")
            results["user_crontab"] = cron_lines

        print("  [SYSTEM CRON]")
        system_crons = []
        for path in ["/etc/crontab", "/etc/cron.d/"]:
            if os.path.exists(path):
                if os.path.isdir(path):
                    files = os.listdir(path)
                    system_crons.extend([os.path.join(path, f) for f in files])
                else:
                    system_crons.append(path)
        print(f"    System cron files: {len(system_crons)}")
        results["system_cron_files"] = system_crons

        self.report["phases"]["cron"] = results

    # ------------------------------------------------------------------
    # PHASE 5 — Credential Discovery
    # ------------------------------------------------------------------
    def phase5_creds(self):
        print("\n[PHASE 5] CREDENTIAL DISCOVERY")
        results = {"bash_history": [], "ssh_keys": [], "config_secrets": []}

        print("  [BASH_HISTORY]")
        history_paths = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
        ]
        for h in history_paths:
            if os.path.exists(h):
                try:
                    with open(h, "r", errors="ignore") as f:
                        lines = f.read().split("\n")
                    interesting = [l for l in lines if any(
                        k in l.lower() for k in ["password", "passwd", "ssh", "mysql", "psql", "token", "key"]
                    )]
                    if interesting:
                        print(f"    [+] {h}: {len(interesting)} interesting commands")
                        for line in interesting[:5]:
                            print(f"        {line.strip()[:100]}")
                    results["bash_history"].extend(interesting[:20])
                except Exception:
                    pass

        print("  [SSH_KEYS]")
        out, _ = run_cmd(
            "find $HOME -name 'id_*' -type f 2>/dev/null | head -10"
        )
        keys = [l for l in out.split("\n") if l.strip()]
        for k in keys:
            print(f"    [+] {k}")
        results["ssh_keys"] = keys

        print("  [CONFIG_SECRETS] Grep /etc for 'password'")
        out, _ = run_cmd(
            "grep -rli 'password' /etc/ 2>/dev/null | head -10"
        )
        configs = [l for l in out.split("\n") if l.strip()]
        print(f"    Configs referencing 'password': {len(configs)}")
        for c in configs[:5]:
            print(f"    [+] {c}")
        results["config_secrets"] = configs

        self.report["phases"]["creds"] = results

    # ------------------------------------------------------------------
    # PHASE 6 — Kernel Exploit Detection
    # ------------------------------------------------------------------
    def phase6_kernel(self):
        print("\n[PHASE 6] KERNEL EXPLOIT DETECTION")
        results = {}

        kernel, _ = run_cmd("uname -r")
        print(f"    Kernel: {kernel}")

        try:
            parts = kernel.split("-")[0].split(".")
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2]) if len(parts) > 2 else 0
        except Exception:
            print("    Unable to parse kernel version")
            results["error"] = "parse_failed"
            self.report["phases"]["kernel"] = results
            return

        # Dirty Pipe — kernel 5.8 to 5.16.11
        dirty_pipe = (major == 5 and (
            (minor >= 8 and minor < 16) or
            (minor == 16 and patch < 11)
        ))
        print(f"    [DIRTY_PIPE] {'VULNERABLE' if dirty_pipe else 'Not affected'}")
        results["dirty_pipe"] = dirty_pipe

        # PwnKit — pkexec
        pkexec_present = os.path.exists("/usr/bin/pkexec")
        pkexec_suid = False
        if pkexec_present:
            try:
                st = os.stat("/usr/bin/pkexec")
                pkexec_suid = bool(st.st_mode & stat.S_ISUID)
            except Exception:
                pass
        print(f"    [PWNKIT] {'VULNERABLE (pkexec SUID)' if pkexec_suid else 'Not affected'}")
        results["pwnkit"] = pkexec_suid

        # Dirty COW — 2.6.22 to 3.9
        dirty_cow = (major == 2 and minor >= 6 and minor <= 3)
        print(f"    [DIRTY_COW] {'VULNERABLE' if dirty_cow else 'Not affected'}")
        results["dirty_cow"] = dirty_cow

        # OverlayFS — Ubuntu 20.04 (5.4.0)
        overlayfs = (major == 5 and minor == 4)
        print(f"    [OVERLAYFS] {'Potentially vulnerable' if overlayfs else 'Not affected'}")
        results["overlayfs"] = overlayfs

        results["kernel"] = kernel
        self.report["phases"]["kernel"] = results

    # ------------------------------------------------------------------
    # PHASE 7 — Report
    # ------------------------------------------------------------------
    def _collect_confirmed(self):
        confirmed = []
        s = self.report["phases"].get("suid_sgid", {})
        if s.get("suid_vulnerable"):
            confirmed.append(f"suid_sgid.vulnerable ({len(s['suid_vulnerable'])})")
        w = self.report["phases"].get("weak_perms", {})
        if w.get("nopasswd"):
            confirmed.append(f"weak_perms.nopasswd ({len(w['nopasswd'])})")
        if w.get("world_writable_dirs"):
            confirmed.append(f"weak_perms.writable_dirs ({len(w['world_writable_dirs'])})")
        c = self.report["phases"].get("creds", {})
        if c.get("bash_history"):
            confirmed.append(f"creds.bash_history ({len(c['bash_history'])})")
        if c.get("ssh_keys"):
            confirmed.append(f"creds.ssh_keys ({len(c['ssh_keys'])})")
        k = self.report["phases"].get("kernel", {})
        if k.get("dirty_pipe"):
            confirmed.append("kernel.dirty_pipe")
        if k.get("pwnkit"):
            confirmed.append("kernel.pwnkit")
        return confirmed

    def phase7_report(self):
        print("\n[PHASE 7] REPORT")
        confirmed = self._collect_confirmed()
        print(f"\n    Total findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/linux_privesc_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/linux_privesc_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Linux Privesc Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>Linux Privilege Escalation Report</h1>
<p><b>Hostname:</b> {self.report['hostname']}</p>
<p><b>User:</b> {self.report['username']}</p>
<p><b>Root:</b> {self.report['is_root']}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print("  Linux Privilege Escalation Toolkit - Project #53")
        print("=" * 64)
        print(f"[+] Hostname: {self.report['hostname']}")
        print(f"[+] User:     {self.report['username']}")
        print(f"[+] Root:     {self.report['is_root']}")
        self.phase1_system_enum()
        self.phase2_suid_sgid()
        self.phase3_weak_perms()
        self.phase4_cron()
        self.phase5_creds()
        self.phase6_kernel()
        self.phase7_report()

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("ERROR: This toolkit must run on Linux.")
        sys.exit(1)
    LinuxPrivescToolkit().run_all()
