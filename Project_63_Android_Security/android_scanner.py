#!/usr/bin/env python3
"""
android_scanner.py — Android App Security Scanner (Project #63)
Analyzes APK structure, manifest, and resources for vulnerabilities.
"""
import os, sys, json, zipfile, re
from datetime import datetime
import xml.etree.ElementTree as ET

APK_FILE = "vulnerable.apk"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

class AndroidScanner:
    def __init__(self, apk_path=APK_FILE):
        self.apk_path = apk_path
        self.report = {
            "apk": apk_path,
            "timestamp": datetime.now().isoformat(),
            "phases": {},
        }

    def phase1_extract(self):
        print("\n[PHASE 1] APK EXTRACTION")
        print(f"    Target: {self.apk_path}")
        try:
            z = zipfile.ZipFile(self.apk_path, 'r')
            self.file_list = z.namelist()
            print(f"    Files in APK: {len(self.file_list)}")
            for f in self.file_list:
                print(f"      - {f}")
            self.report["phases"]["extract"] = {"file_count": len(self.file_list), "files": self.file_list}
            return z
        except Exception as e:
            print(f"    [!] Error: {e}")
            return None

    def phase2_manifest(self, z):
        print("\n[PHASE 2] MANIFEST ANALYSIS")
        try:
            manifest_data = z.read("AndroidManifest.xml")
            # Mock APK uses plain XML (not binary), so parse directly
            root = ET.fromstring(manifest_data)

            package = root.get('package', 'unknown')
            print(f"    Package: {package}")

            # Check application attributes
            app = root.find('application')
            results = {"package": package}

            if app is not None:
                debuggable = app.get('{http://schemas.android.com/apk/res/android}debuggable')
                backup = app.get('{http://schemas.android.com/apk/res/android}allowBackup')
                cleartext = app.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')

                print(f"    Debuggable: {debuggable}")
                print(f"    AllowBackup: {backup}")
                print(f"    Cleartext: {cleartext}")

                results["debuggable"] = debuggable == "true"
                results["allow_backup"] = backup == "true"
                results["cleartext"] = cleartext == "true"

                if results["debuggable"]:
                    print("      [+] VULNERABLE! Debuggable=true")
                if results["allow_backup"]:
                    print("      [+] VULNERABLE! AllowBackup=true")
                if results["cleartext"]:
                    print("      [+] VULNERABLE! Cleartext traffic allowed")

            # Check exported components
            exported = []
            for tag in ['activity', 'service', 'receiver', 'provider']:
                for comp in root.findall(f'.//{tag}'):
                    name = comp.get('{http://schemas.android.com/apk/res/android}name', '')
                    is_exported = comp.get('{http://schemas.android.com/apk/res/android}exported')
                    if is_exported == "true":
                        exported.append({"type": tag, "name": name})
                        print(f"    [!] Exported {tag}: {name}")

            results["exported_components"] = exported
            self.report["phases"]["manifest"] = results
        except Exception as e:
            print(f"    [!] Manifest error: {e}")

    def phase3_secrets(self, z):
        print("\n[PHASE 3] SECRET DISCOVERY")
        try:
            strings_data = z.read("res/values/strings.xml").decode()
            secrets = {}

            # AWS keys
            aws = re.findall(r'AKIA[0-9A-Z]{16}', strings_data)
            if aws:
                secrets["aws_keys"] = aws
                print(f"    [AWS] Found: {aws}")

            # Google API keys
            google = re.findall(r'AIza[0-9A-Za-z\-_]{35}', strings_data)
            if google:
                secrets["google_keys"] = google
                print(f"    [GOOGLE] Found: {google}")

            # Passwords
            pwd = re.findall(r'<string name="[^"]*password[^"]*">([^<]+)</string>', strings_data)
            if pwd:
                secrets["passwords"] = pwd
                print(f"    [PASSWORD] Found: {pwd}")

            # Firebase
            firebase = re.findall(r'https://[a-z0-9-]+\.firebaseio\.com', strings_data)
            if firebase:
                secrets["firebase"] = firebase
                print(f"    [FIREBASE] Found: {firebase}")

            if secrets:
                print("      [+] CRITICAL! Hardcoded secrets found")

            self.report["phases"]["secrets"] = secrets
        except Exception as e:
            print(f"    [!] {e}")

    def phase4_network(self, z):
        print("\n[PHASE 4] NETWORK SECURITY")
        try:
            net_config = z.read("res/xml/network_security_config.xml").decode()
            cleartext_allowed = 'cleartextTrafficPermitted="true"' in net_config
            print(f"    Cleartext Permitted: {cleartext_allowed}")
            if cleartext_allowed:
                print("      [+] VULNERABLE! Cleartext traffic allowed in network config")
            self.report["phases"]["network"] = {"cleartext_allowed": cleartext_allowed}
        except Exception as e:
            print(f"    [!] No network config found: {e}")

    def phase5_report(self):
        print("\n[PHASE 5] EXPLOITATION SUMMARY")
        confirmed = []
        m = self.report["phases"].get("manifest", {})
        if m.get("debuggable"): confirmed.append("manifest.debuggable")
        if m.get("allow_backup"): confirmed.append("manifest.allow_backup")
        if m.get("cleartext"): confirmed.append("manifest.cleartext")
        if m.get("exported_components"): confirmed.append(f"manifest.exported ({len(m['exported_components'])})")
        s = self.report["phases"].get("secrets", {})
        if s.get("aws_keys"): confirmed.append("secrets.aws")
        if s.get("google_keys"): confirmed.append("secrets.google")
        if s.get("passwords"): confirmed.append("secrets.passwords")
        if s.get("firebase"): confirmed.append("secrets.firebase")
        n = self.report["phases"].get("network", {})
        if n.get("cleartext_allowed"): confirmed.append("network.cleartext")

        print(f"\n    Total confirmed vulnerabilities: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/android_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/android_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:3000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Android Security Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>Android Security Report</h1>
<p><b>APK:</b> {self.apk_path}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Vulnerabilities:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run(self):
        print("=" * 64)
        print(" Android Security Testing Toolkit - Project #63")
        print("=" * 64)
        z = self.phase1_extract()
        if z:
            self.phase2_manifest(z)
            self.phase3_secrets(z)
            self.phase4_network(z)
            z.close()
            self.phase5_report()

if __name__ == "__main__":
    AndroidScanner().run()
