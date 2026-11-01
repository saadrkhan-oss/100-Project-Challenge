#!/usr/bin/env python3
"""
siem_analyzer.py — Log Analysis & SIEM Dashboard (Project #61)
Parses Apache logs, detects attacks, generates alerts, exports reports.
"""
import os, re, json, csv
from datetime import datetime
from collections import defaultdict

LOG_FILE = "logs/access.log"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Apache combined log format regex
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>.+?) HTTP/[\d.]+" '
    r'(?P<status>\d+) (?P<bytes>\d+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# Detection patterns
ATTACK_PATTERNS = {
    "SQLi": [
        r"' OR '",
        r"UNION SELECT",
        r"SLEEP\(",
        r"sqlmap",
    ],
    "XSS": [
        r"<script>",
        r"onerror=",
        r"javascript:",
    ],
    "BruteForce": [
        r"Hydra",
    ],
    "PortScan": [
        r"Nmap",
        r"/:\d+",
    ],
}

SEVERITY_THRESHOLDS = {
    "SQLi":       {"CRITICAL": 10, "HIGH": 3,  "MEDIUM": 1},
    "XSS":        {"CRITICAL": 5,  "HIGH": 2,  "MEDIUM": 1},
    "BruteForce": {"CRITICAL": 30, "HIGH": 10, "MEDIUM": 3},
    "PortScan":   {"CRITICAL": 10, "HIGH": 5,  "MEDIUM": 1},
}

class SIEMAnalyzer:
    def __init__(self, log_file=LOG_FILE):
        self.log_file = log_file
        self.report = {
            "log_file": log_file,
            "timestamp": datetime.now().isoformat(),
            "phases": {},
        }

    # ------------------------------------------------------------------
    def phase1_parse(self):
        print("\n[PHASE 1] LOG PARSING")
        entries = []
        failed = 0

        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    m = LOG_PATTERN.match(line)
                    if m:
                        entries.append({
                            "ip": m.group("ip"),
                            "time": m.group("time"),
                            "method": m.group("method"),
                            "path": m.group("path"),
                            "status": int(m.group("status")),
                            "bytes": int(m.group("bytes")),
                            "ua": m.group("ua"),
                        })
                    else:
                        failed += 1
        except FileNotFoundError:
            print(f"    [!] {self.log_file} not found")
            return

        unique_ips = set(e["ip"] for e in entries)
        times = sorted(e["time"] for e in entries)
        time_range = f"{times[0]} → {times[-1]}" if times else "N/A"

        print(f"    Format: Apache Combined")
        print(f"    Lines: {len(entries)} (parsed), {failed} (failed)")
        print(f"    Unique IPs: {len(unique_ips)}")
        print(f"    Time range: {time_range}")

        self.entries = entries
        self.report["phases"]["parse"] = {
            "total_lines": len(entries),
            "failed_lines": failed,
            "unique_ips": len(unique_ips),
            "time_range": time_range,
        }

    # ------------------------------------------------------------------
    def phase2_detect(self):
        print("\n[PHASE 2] ATTACK DETECTION")
        detections = defaultdict(lambda: defaultdict(int))  # ip -> attack_type -> count

        for entry in self.entries:
            for attack_type, patterns in ATTACK_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, entry["path"], re.IGNORECASE) or \
                       re.search(pattern, entry["ua"], re.IGNORECASE):
                        detections[entry["ip"]][attack_type] += 1
                        break

        # Print results
        for attack_type in ATTACK_PATTERNS.keys():
            total = sum(d[attack_type] for d in detections.values())
            if total == 0:
                continue
            print(f"\n    [{attack_type}] {total} attempts")
            for ip, attacks in detections.items():
                if attacks[attack_type] > 0:
                    print(f"      - {ip}: {attacks[attack_type]} attempts")

        self.detections = detections
        self.report["phases"]["detect"] = {
            ip: dict(attacks) for ip, attacks in detections.items()
        }

    # ------------------------------------------------------------------
    def phase3_correlate(self):
        print("\n[PHASE 3] CORRELATION")
        # Group by IP
        ip_summary = {}
        for ip, attacks in self.detections.items():
            total = sum(attacks.values())
            types = [t for t, c in attacks.items() if c > 0]
            ip_summary[ip] = {
                "total_attacks": total,
                "attack_types": types,
                "counts": dict(attacks),
            }

        # Sort by severity
        sorted_ips = sorted(ip_summary.items(),
                            key=lambda x: x[1]["total_attacks"], reverse=True)
        print(f"    Correlated {len(sorted_ips)} attacker IPs")
        for ip, info in sorted_ips[:10]:
            print(f"      {ip}: {info['total_attacks']} attacks ({', '.join(info['attack_types'])})")

        self.ip_summary = ip_summary
        self.report["phases"]["correlate"] = ip_summary

    # ------------------------------------------------------------------
    def phase4_alerts(self):
        print("\n[PHASE 4] ALERTS")
        alerts = []

        for ip, info in self.ip_summary.items():
            for attack_type, count in info["counts"].items():
                if count == 0:
                    continue
                severity = "MEDIUM"
                for sev, threshold in SEVERITY_THRESHOLDS[attack_type].items():
                    if count >= threshold:
                        severity = sev
                        break

                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "ip": ip,
                    "attack_type": attack_type,
                    "count": count,
                    "severity": severity,
                    "message": f"{attack_type} from {ip} ({count} attempts)",
                }
                alerts.append(alert)

        # Sort by severity: CRITICAL > HIGH > MEDIUM
        sev_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
        alerts.sort(key=lambda x: (sev_order[x["severity"]], x["count"]), reverse=True)

        for a in alerts:
            print(f"    [{a['severity']}] {a['message']}")

        self.alerts = alerts
        self.report["phases"]["alerts"] = alerts

    # ------------------------------------------------------------------
    def phase5_export(self):
        print("\n[PHASE 5] EXPORT")

        # JSON
        json_path = f"{REPORTS_DIR}/log_analysis.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"    [+] JSON: {json_path}")

        # CSV
        csv_path = f"{REPORTS_DIR}/log_analysis.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["severity", "ip", "attack_type", "count", "message"])
            for a in self.alerts:
                writer.writerow([a["severity"], a["ip"], a["attack_type"],
                                 a["count"], a["message"]])
        print(f"    [+] CSV: {csv_path}")

        # HTML
        html_path = f"{REPORTS_DIR}/log_analysis.html"
        with open(html_path, "w") as f:
            f.write(self._build_html())
        print(f"    [+] HTML: {html_path}")

        self.report["phases"]["export"] = {
            "json": json_path, "csv": csv_path, "html": html_path,
        }

    def _build_html(self):
        alert_rows = ""
        for a in self.alerts:
            color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00"}[a["severity"]]
            alert_rows += f"""<tr>
                <td style="color:{color};font-weight:bold">{a['severity']}</td>
                <td>{a['ip']}</td>
                <td>{a['attack_type']}</td>
                <td>{a['count']}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html><head><title>SIEM Log Analysis Report</title>
<style>
body {{ font-family: monospace; background:#0a0a0a; color:#e0e0e0; padding:20px; }}
h1 {{ color:#ff4444; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
th {{ background: #1a1a1a; color: #ff4444; }}
tr:nth-child(even) {{ background: #0f0f0f; }}
</style></head><body>
<h1>SIEM Log Analysis Report</h1>
<p><b>Log file:</b> {self.log_file}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Total lines parsed:</b> {self.report['phases']['parse']['total_lines']}</p>
<p><b>Alerts:</b> {len(self.alerts)}</p>
<h2>Alerts</h2>
<table>
<tr><th>Severity</th><th>IP</th><th>Attack Type</th><th>Count</th></tr>
{alert_rows}
</table>
</body></html>"""

    # ------------------------------------------------------------------
    def run_all(self):
        print("=" * 64)
        print(" Log Analysis & SIEM Dashboard - Project #61")
        print("=" * 64)
        self.phase1_parse()
        if not self.entries:
            print("  [!] No entries parsed, aborting")
            return
        self.phase2_detect()
        self.phase3_correlate()
        self.phase4_alerts()
        self.phase5_export()
        print(f"\n[✓] Analysis complete")
        print(f"    {len(self.alerts)} alerts generated")
        print(f"    Run: python3 dashboard.py  (for web UI)")

if __name__ == "__main__":
    SIEMAnalyzer().run_all()
