#!/usr/bin/env python3
"""
iot_scanner.py — IoT Device Security Assessment (Project #64)
6-phase scanner against a simulated IoT network.
"""
import os, sys, json, re, hashlib
from datetime import datetime

NETWORK_FILE = "mock/network.json"
FIRMWARE_FILE = "mock/camera_firmware.bin"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Vulnerability descriptions
VULN_DESCRIPTIONS = {
    "telnet_enabled":      ("Telnet enabled (insecure)", "CRITICAL"),
    "upnp_exposed":        ("UPnP exposed to network", "HIGH"),
    "http_no_https":       ("HTTP (no HTTPS)", "HIGH"),
    "rtsp_unauthenticated":("RTSP stream unauthenticated", "CRITICAL"),
    "mqtt_unauthenticated":("MQTT broker unauthenticated", "CRITICAL"),
    "debug_exposed":       ("Debug interface exposed", "HIGH"),
}

# Secret patterns for firmware analysis
SECRET_PATTERNS = {
    "passwords": [r"password=(\S+)", r"passwd=(\S+)"],
    "api_keys":  [r"api_key=(\S+)", r"AKIA[0-9A-Z]{16}"],
    "wifi":      [r"wifi_password=(\S+)", r"wifi_ssid=(\S+)"],
}

class IoTScanner:
    def __init__(self):
        self.report = {
            "network_file": NETWORK_FILE,
            "firmware_file": FIRMWARE_FILE,
            "timestamp": datetime.now().isoformat(),
            "phases": {},
        }

    # ------------------------------------------------------------------
    def phase1_discovery(self):
        print("\n[PHASE 1] DEVICE DISCOVERY")
        with open(NETWORK_FILE) as f:
            network = json.load(f)

        self.devices = network["devices"]
        print(f"    Scanning network...")
        print(f"    Devices found: {len(self.devices)}")
        for d in self.devices:
            print(f"      - {d['ip']} ({d['type']}) — {d['vendor']}")

        self.report["phases"]["discovery"] = {
            "count": len(self.devices),
            "devices": [{"ip": d["ip"], "type": d["type"], "vendor": d["vendor"]} for d in self.devices],
        }

    # ------------------------------------------------------------------
    def phase2_fingerprint(self):
        print("\n[PHASE 2] FINGERPRINTING")
        results = []
        for d in self.devices:
            print(f"\n    [{d['ip']}] {d['type'].title()} ({d['vendor']}):")
            print(f"      Open ports: {d['open_ports']}")
            for svc, banner in d["services"].items():
                print(f"      {svc.upper()}: {banner}")

            results.append({
                "ip": d["ip"],
                "type": d["type"],
                "vendor": d["vendor"],
                "open_ports": d["open_ports"],
                "services": d["services"],
            })

        print(f"\n    [+] {len(results)} devices fingerprinted")
        self.report["phases"]["fingerprinting"] = results

    # ------------------------------------------------------------------
    def phase3_default_creds(self):
        print("\n[PHASE 3] DEFAULT CREDENTIALS")
        results = []
        for d in self.devices:
            if not d["default_creds"]:
                continue
            print(f"\n    [{d['ip']}] {d['type'].title()}:")
            for user, pwd in d["default_creds"]:
                # Simulate auth: any default cred from the list "succeeds"
                print(f"      {user}:{pwd} → SUCCESS!")
                results.append({
                    "ip": d["ip"],
                    "type": d["type"],
                    "username": user,
                    "password": pwd,
                })

        print(f"\n    [+] {len(results)} devices with default credentials!")
        self.report["phases"]["default_creds"] = results

    # ------------------------------------------------------------------
    def phase4_vulnerabilities(self):
        print("\n[PHASE 4] VULNERABILITIES")
        results = []
        for d in self.devices:
            if not d["vulnerabilities"]:
                continue
            print(f"\n    [{d['ip']}] {d['type'].title()}:")
            for v in d["vulnerabilities"]:
                desc, severity = VULN_DESCRIPTIONS.get(v, (v, "MEDIUM"))
                print(f"      {desc} ← {severity}")
                results.append({
                    "ip": d["ip"],
                    "type": d["type"],
                    "vulnerability": v,
                    "description": desc,
                    "severity": severity,
                })

        print(f"\n    [+] {len(results)} vulnerabilities found")
        self.report["phases"]["vulnerabilities"] = results

    # ------------------------------------------------------------------
    def phase5_firmware(self):
        print("\n[PHASE 5] FIRMWARE ANALYSIS")
        if not os.path.exists(FIRMWARE_FILE):
            print(f"    [!] {FIRMWARE_FILE} not found")
            return

        with open(FIRMWARE_FILE, "rb") as f:
            data = f.read()

        # Extract printable strings
        strings = re.findall(rb"[\x20-\x7e]{4,}", data)
        strings = [s.decode("ascii", errors="ignore") for s in strings]

        print(f"    Firmware: {FIRMWARE_FILE} ({len(data)} bytes)")
        print(f"    Strings extracted: {len(strings)}")

        # Extract secrets
        secrets = {}
        for category, patterns in SECRET_PATTERNS.items():
            matches = []
            for s in strings:
                for pattern in patterns:
                    for m in re.findall(pattern, s):
                        if m and m not in matches:
                            matches.append(m)
            if matches:
                secrets[category] = matches
                print(f"\n    [{category.upper()}] Found {len(matches)}:")
                for m in matches:
                    print(f"      - {m}")

        if secrets:
            print(f"\n    [+] CRITICAL! Hardcoded secrets found in firmware")

        self.report["phases"]["firmware"] = {
            "size": len(data),
            "strings": len(strings),
            "secrets": secrets,
        }

    # ------------------------------------------------------------------
    def phase6_report(self):
        print("\n[PHASE 6] EXPLOITATION SUMMARY")

        confirmed = []
        # Vulnerabilities
        for v in self.report["phases"].get("vulnerabilities", []):
            confirmed.append(f"{v['ip']} — {v['vulnerability']} ({v['severity']})")
        # Default creds
        for c in self.report["phases"].get("default_creds", []):
            confirmed.append(f"{c['ip']} — default creds ({c['username']}:{c['password']})")
        # Firmware secrets
        for cat, matches in self.report["phases"].get("firmware", {}).get("secrets", {}).items():
            for m in matches:
                confirmed.append(f"firmware — {cat}: {m}")

        print(f"\n    Total confirmed findings: {len(confirmed)}")
        for c in confirmed[:20]:  # Limit output
            print(f"      * {c}")
        if len(confirmed) > 20:
            print(f"      ... and {len(confirmed) - 20} more")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/iot_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/iot_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>IoT Security Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>IoT Security Assessment Report</h1>
<p><b>Network:</b> {self.report['network_file']}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed[:50])}</ul>
{rows}
</body></html>"""

    # ------------------------------------------------------------------
    def run(self):
        print("=" * 64)
        print(" IoT Device Security Assessment - Project #64")
        print("=" * 64)
        self.phase1_discovery()
        self.phase2_fingerprint()
        self.phase3_default_creds()
        self.phase4_vulnerabilities()
        self.phase5_firmware()
        self.phase6_report()

if __name__ == "__main__":
    IoTScanner().run()
