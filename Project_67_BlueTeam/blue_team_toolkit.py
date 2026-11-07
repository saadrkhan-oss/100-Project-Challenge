#!/usr/bin/env python3
"""
blue_team_toolkit.py — Blue Team Defense Toolkit (Project #67)
Detection, response, hunting, forensics, reporting.
"""
import os, sys, json, re, shutil
from datetime import datetime

MOCK_DIR = "mock"
QUARANTINE_DIR = "quarantine"
REPORTS_DIR = "reports"
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

class BlueTeamToolkit:
    def __init__(self):
        self.report = {
            "timestamp": datetime.now().isoformat(),
            "mock_dir": MOCK_DIR,
            "phases": {},
        }
        self.timeline = []

    def _log_event(self, time_str, event):
        self.timeline.append({"time": time_str, "event": event})

    # ------------------------------------------------------------------
    # PHASE 1 — Detection
    # ------------------------------------------------------------------
    def phase1_detection(self):
        print("\n[PHASE 1] DETECTION")
        with open(os.path.join(MOCK_DIR, "state.json")) as f:
            state = json.load(f)

        results = {"sigma": [], "yara": [], "ids": []}

        # --- Sigma: brute force (failed logins > 10) ---
        print("\n    [SIGMA] Brute Force Detection")
        for login in state.get("failed_logins", []):
            if login["count"] > 10:
                print(f"      Detected: {login['count']} failed logins from {login['ip']} (user={login['user']})")
                print(f"      [+] ALERT! Brute force from {login['ip']}")
                results["sigma"].append({"ip": login["ip"], "user": login["user"],
                                          "count": login["count"], "rule": "brute_force"})
                self._log_event("10:00", f"Brute force detected from {login['ip']}")

        # --- YARA: malware files ---
        print("\n    [YARA] Malware Detection")
        for m in state.get("malware_files", []):
            if m.get("detected"):
                print(f"      Detected: {m['path']} (hash={m['hash']})")
                print(f"      [+] ALERT! Malware detected")
                results["yara"].append({"path": m["path"], "hash": m["hash"], "rule": "mimikatz_or_shell"})
                self._log_event("10:05", f"Malware detected: {m['path']}")

        # --- IDS: SQL injection ---
        print("\n    [IDS] SQL Injection Detection")
        for sqli in state.get("sql_injection_attempts", []):
            print(f"      Detected: {sqli['count']} attempts from {sqli['ip']} (payload: {sqli['payload']})")
            print(f"      [+] ALERT! SQL injection detected")
            results["ids"].append({"ip": sqli["ip"], "payload": sqli["payload"],
                                    "count": sqli["count"], "rule": "sql_injection"})

        total = sum(len(v) for v in results.values())
        print(f"\n    [+] {total} alerts across Sigma/YARA/IDS")
        self.report["phases"]["detection"] = results

    # ------------------------------------------------------------------
    # PHASE 2 — Incident Response
    # ------------------------------------------------------------------
    def phase2_response(self):
        print("\n[PHASE 2] INCIDENT RESPONSE")
        results = {"containment": [], "eradication": [], "recovery": []}

        with open(os.path.join(MOCK_DIR, "state.json")) as f:
            state = json.load(f)

        # Containment: isolate attackers
        print("\n    [CONTAINMENT]")
        blocked_ips = set()
        for login in state.get("failed_logins", []):
            if login["count"] > 10 and login["ip"] not in blocked_ips:
                blocked_ips.add(login["ip"])
                print(f"      Isolating {login['ip']} (network blocked)")
                with open(os.path.join(QUARANTINE_DIR, "containment.log"), "a") as f:
                    f.write(f"{datetime.now().isoformat()} BLOCKED {login['ip']}\n")
                results["containment"].append(login["ip"])
                self._log_event("10:10", f"Host {login['ip']} isolated")

        # Eradication: quarantine malware files
        print("\n    [ERADICATION]")
        for m in state.get("malware_files", []):
            if m.get("detected"):
                safe_name = m["path"].replace("/", "_")
                dst = os.path.join(QUARANTINE_DIR, safe_name)
                with open(dst, "w") as f:
                    f.write(f"QUARANTINED: {m['path']}\nHash: {m['hash']}\n")
                print(f"      Quarantined: {m['path']} → {dst}")
                results["eradication"].append({"path": m["path"], "quarantine": dst})
                self._log_event("10:15", f"Malware {m['path']} quarantined")

        # Recovery
        print("\n    [RECOVERY]")
        print(f"      System restored from backup (simulated)")
        results["recovery"].append("restored_from_backup")
        self._log_event("10:20", "System restored from backup")

        self.report["phases"]["response"] = results

    # ------------------------------------------------------------------
    # PHASE 3 — Threat Hunting
    # ------------------------------------------------------------------
    def phase3_hunting(self):
        print("\n[PHASE 3] THREAT HUNTING")
        with open(os.path.join(MOCK_DIR, "state.json")) as f:
            state = json.load(f)

        iocs = state.get("iocs", {})
        results = {"ioc_hits": [], "anomalies": []}

        # Read all artifacts
        artifacts = {}
        for fname in ["memory.dump", "capture.pcap", "disk.img"]:
            path = os.path.join(MOCK_DIR, fname)
            with open(path) as f:
                artifacts[fname] = f.read()

        # IOC scan
        print("\n    [IOC_SCAN]")
        for ioc_type, values in iocs.items():
            for value in values:
                for fname, content in artifacts.items():
                    if value in content:
                        print(f"      IOC {value} found in {fname}")
                        results["ioc_hits"].append({"ioc": value, "type": ioc_type, "artifact": fname})

        print(f"\n    [+] {len(results['ioc_hits'])} IOC hits")

        # Anomaly detection
        print("\n    [ANOMALY]")
        pcap = artifacts.get("capture.pcap", "")
        c2_connections = re.findall(r"(\d+\.\d+\.\d+\.\d+) -> (192\.168\.1\.100):\d+ \(C2\)", pcap)
        if c2_connections:
            print(f"      Anomaly: {len(c2_connections)} C2 connections to 192.168.1.100")
            results["anomalies"].append({
                "type": "c2_traffic",
                "count": len(c2_connections),
                "target": "192.168.1.100",
            })

        self.report["phases"]["hunting"] = results

    # ------------------------------------------------------------------
    # PHASE 4 — Forensics
    # ------------------------------------------------------------------
    def phase4_forensics(self):
        print("\n[PHASE 4] FORENSICS")
        results = {"memory": {}, "disk": {}, "network": {}}

        # Memory analysis
        print("\n    [MEMORY] Volatility-style analysis")
        with open(os.path.join(MOCK_DIR, "memory.dump")) as f:
            mem = f.read()

        procs = re.findall(r"(\w+\.exe) \(PID (\d+)\)", mem)
        suspicious = [p for p in procs if any(k in p[0].lower() for k in ["mimikatz", "powershell"])]
        print(f"      Processes: {len(procs)}")
        print(f"      Suspicious: {len(suspicious)}")
        for p in suspicious:
            print(f"        - {p[0]} (PID {p[1]})")

        creds = re.findall(r"(\w+):(\S+)", mem)
        creds = [c for c in creds if c[0] in ["admin", "user1", "user2"]]
        print(f"      Credentials: {len(creds)}")
        for c in creds:
            print(f"        - {c[0]}:{c[1]}")

        results["memory"] = {
            "process_count": len(procs),
            "suspicious_processes": [p[0] for p in suspicious],
            "credentials_found": len(creds),
        }

        # Disk analysis
        print("\n    [DISK] Sleuthkit-style analysis")
        with open(os.path.join(MOCK_DIR, "disk.img")) as f:
            disk = f.read()
        deleted = re.findall(r"\[DELETED\] (\S+)", disk)
        print(f"      Deleted files: {len(deleted)}")
        for d in deleted:
            print(f"        - {d} (recovered)")

        results["disk"] = {"deleted_files": deleted, "recovered": len(deleted)}

        # Network analysis
        print("\n    [NETWORK] PCAP analysis")
        with open(os.path.join(MOCK_DIR, "capture.pcap")) as f:
            pcap = f.read()
        connections = re.findall(r"(\d+\.\d+\.\d+\.\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)", pcap)
        malicious = [c for c in connections if "192.168.1.100" in c[1] or "203.0.113.5" in c[1]]
        print(f"      Connections: {len(connections)}")
        print(f"      Malicious: {len(malicious)}")
        for m in malicious:
            print(f"        - {m[0]} -> {m[1]}:{m[2]}")

        results["network"] = {
            "total_connections": len(connections),
            "malicious": [f"{m[0]} -> {m[1]}:{m[2]}" for m in malicious],
        }

        self.report["phases"]["forensics"] = results

    # ------------------------------------------------------------------
    # PHASE 5 — Incident Report
    # ------------------------------------------------------------------
    def phase5_incident_report(self):
        print("\n[PHASE 5] INCIDENT REPORT")
        print("\n    Timeline:")
        for ev in self.timeline:
            print(f"      - {ev['time']}: {ev['event']}")

        impact = {
            "hosts_compromised": 1,
            "data_exfiltrated_kb": 0,
            "downtime_minutes": 20,
            "alerts_total": sum(
                len(v) if isinstance(v, list) else 0
                for v in self.report["phases"].get("detection", {}).values()
            ),
        }
        print(f"\n    Impact:")
        print(f"      - Hosts compromised: {impact['hosts_compromised']}")
        print(f"      - Data exfiltrated: {impact['data_exfiltrated_kb']} KB")
        print(f"      - Downtime: {impact['downtime_minutes']} minutes")
        print(f"      - Alerts: {impact['alerts_total']}")

        self.report["phases"]["incident_report"] = {
            "timeline": self.timeline,
            "impact": impact,
        }

    # ------------------------------------------------------------------
    # PHASE 6 — Lessons Learned
    # ------------------------------------------------------------------
    def phase6_lessons(self):
        print("\n[PHASE 6] LESSONS LEARNED")
        recommendations = [
            "Enable MFA to prevent credential-based brute force",
            "Update YARA rules with new malware signatures",
            "Improve IDS rules for SQLi and C2 traffic",
            "Add network segmentation (VLANs) between prod and users",
            "Test backups monthly to ensure recovery works",
        ]
        for r in recommendations:
            print(f"    - {r}")
        print(f"\n    [+] {len(recommendations)} improvements identified")
        self.report["phases"]["lessons_learned"] = recommendations

    # ------------------------------------------------------------------
    # PHASE 7 — Report
    # ------------------------------------------------------------------
    def phase7_report(self):
        print("\n[PHASE 7] REPORT")

        confirmed = []
        d = self.report["phases"].get("detection", {})
        for k, v in d.items():
            for item in v:
                confirmed.append(f"detection.{k} ({item.get('ip') or item.get('path') or item.get('payload')})")
        r = self.report["phases"].get("response", {})
        for ip in r.get("containment", []):
            confirmed.append(f"response.containment ({ip})")
        for item in r.get("eradication", []):
            confirmed.append(f"response.eradication ({item['path']})")
        h = self.report["phases"].get("hunting", {})
        for hit in h.get("ioc_hits", []):
            confirmed.append(f"hunting.ioc ({hit['ioc']})")
        f = self.report["phases"].get("forensics", {})
        if f.get("memory", {}).get("suspicious_processes"):
            confirmed.append(f"forensics.memory ({len(f['memory']['suspicious_processes'])} suspicious)")
        if f.get("disk", {}).get("deleted_files"):
            confirmed.append(f"forensics.disk ({len(f['disk']['deleted_files'])} recovered)")
        if f.get("network", {}).get("malicious"):
            confirmed.append(f"forensics.network ({len(f['network']['malicious'])} C2)")

        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/blue_team_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/blue_team_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Blue Team Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#4488ff; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #4488ff; overflow:auto; }}
</style></head><body>
<h1>Blue Team Defense Report</h1>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Blue Team Defense Toolkit - Project #67")
        print("=" * 64)
        self.phase1_detection()
        self.phase2_response()
        self.phase3_hunting()
        self.phase4_forensics()
        self.phase5_incident_report()
        self.phase6_lessons()
        self.phase7_report()

if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        print("ERROR: Linux only")
        sys.exit(1)
    BlueTeamToolkit().run_all()
