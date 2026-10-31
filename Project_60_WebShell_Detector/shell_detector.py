#!/usr/bin/env python3
"""
shell_detector.py — Web Shell Detection & Removal (Project #60)
Scans PHP files, matches malicious patterns, quarantines shells, reports.
"""
import os, sys, json, re, shutil, hashlib
from datetime import datetime

TARGET_DIR = "webroot"
QUARANTINE_DIR = "quarantine"
REPORTS_DIR = "reports"
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Pattern database: (regex, category, severity)
PATTERNS = [
    # Direct command execution
    (r'\bsystem\s*\(',           "direct_exec",   "HIGH"),
    (r'\bexec\s*\(',             "direct_exec",   "HIGH"),
    (r'\bpassthru\s*\(',         "direct_exec",   "HIGH"),
    (r'\bshell_exec\s*\(',       "direct_exec",   "HIGH"),
    (r'\bpopen\s*\(',            "direct_exec",   "HIGH"),
    (r'\bproc_open\s*\(',        "direct_exec",   "HIGH"),

    # Code evaluation (critical)
    (r'\beval\s*\(',             "code_eval",     "CRITICAL"),
    (r'\bassert\s*\(',           "code_eval",     "HIGH"),
    (r'create_function\s*\(',    "code_eval",     "CRITICAL"),

    # Obfuscation
    (r'base64_decode\s*\(',      "obfuscation",   "CRITICAL"),
    (r'gzinflate\s*\(',          "obfuscation",   "CRITICAL"),
    (r'str_rot13\s*\(',          "obfuscation",   "HIGH"),
    (r'hex2bin\s*\(',            "obfuscation",   "HIGH"),

    # File operations (webshell features)
    (r'move_uploaded_file\s*\(', "file_manager",  "CRITICAL"),
    (r'file_put_contents\s*\(',  "file_manager",  "CRITICAL"),
    (r'fwrite\s*\(',             "file_manager",  "MEDIUM"),
    (r'unlink\s*\(',             "file_manager",  "MEDIUM"),
    (r'chmod\s*\(',              "file_manager",  "HIGH"),

    # Variable function (stealth)
    (r'\$\w+\s*=\s*\$_GET\[',    "stealth_var",   "HIGH"),
    (r'\$\w+\s*=\s*\$_POST\[',   "stealth_var",   "HIGH"),
    (r'\$[a-zA-Z_]\w*\s*\([^)]*\)\s*;', "variable_function", "MEDIUM"),

    # Superglobals in executable context
    (r'\$_GET\s*\[.*?\]\s*\(',   "user_input_exec", "HIGH"),
    (r'\$_POST\s*\[.*?\]\s*\(',  "user_input_exec", "HIGH"),
    (r'\$_REQUEST\s*\[.*?\]\s*\(', "user_input_exec", "HIGH"),
]

SEVERITY_ORDER = {"CLEAN": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

class ShellDetector:
    def __init__(self, target_dir=TARGET_DIR):
        self.target_dir = target_dir
        self.findings = []
        self.report = {
            "target": target_dir,
            "timestamp": datetime.now().isoformat(),
            "phases": {},
        }

    # ------------------------------------------------------------------
    def phase1_scan(self):
        print(f"\n[PHASE 1] SCANNING DIRECTORY")
        print(f"    Scanning: {self.target_dir}")

        php_files = []
        for root, dirs, files in os.walk(self.target_dir):
            for f in files:
                if f.endswith(".php"):
                    php_files.append(os.path.join(root, f))

        print(f"    PHP files found: {len(php_files)}")
        for f in php_files:
            print(f"      {f}")

        self.php_files = php_files
        self.report["phases"]["scan"] = {"count": len(php_files), "files": php_files}

    # ------------------------------------------------------------------
    def phase2_analyze(self):
        print(f"\n[PHASE 2] ANALYZING FILES")

        for path in self.php_files:
            try:
                with open(path, "r", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                print(f"    [!] {path}: {e}")
                continue

            # Compute hash
            sha256 = hashlib.sha256(content.encode()).hexdigest()

            # Match patterns
            matches = []
            max_severity = "CLEAN"
            for regex, category, severity in PATTERNS:
                if re.search(regex, content):
                    matches.append({
                        "pattern": regex,
                        "category": category,
                        "severity": severity,
                    })
                    if SEVERITY_ORDER[severity] > SEVERITY_ORDER[max_severity]:
                        max_severity = severity

            # Classify based on matches
            if max_severity == "CLEAN":
                print(f"    {path}: CLEAN")
                continue

            # Classify shell type
            categories = set(m["category"] for m in matches)
            if "code_eval" in categories or "obfuscation" in categories:
                shell_type = "OBFUSCATED SHELL"
            elif "file_manager" in categories:
                shell_type = "FILE MANAGER SHELL"
            elif "stealth_var" in categories or "variable_function" in categories:
                shell_type = "STEALTH SHELL"
            elif "direct_exec" in categories:
                shell_type = "BASIC SHELL"
            else:
                shell_type = "SUSPICIOUS FILE"

            color = "CRITICAL" if max_severity == "CRITICAL" else "HIGH"
            print(f"\n    [+] {path}: {shell_type}")
            print(f"        Severity: {max_severity}")
            print(f"        SHA256:   {sha256[:16]}...")
            for m in matches:
                print(f"        Pattern:  {m['pattern']}")

            self.findings.append({
                "file": path,
                "type": shell_type,
                "severity": max_severity,
                "sha256": sha256,
                "matches": matches,
                "quarantined": False,
            })

        self.report["phases"]["analysis"] = {
            "total_files": len(self.php_files),
            "detected_shells": len(self.findings),
            "findings": self.findings,
        }

    # ------------------------------------------------------------------
    def phase3_summary(self):
        print(f"\n[PHASE 3] DETECTION SUMMARY")
        print(f"    Total shells detected: {len(self.findings)}")

        by_type = {}
        by_severity = {}
        for f in self.findings:
            by_type[f["type"]] = by_type.get(f["type"], 0) + 1
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

        print(f"    By type:")
        for t, c in by_type.items():
            print(f"      {t}: {c}")
        print(f"    By severity:")
        for s, c in by_severity.items():
            print(f"      {s}: {c}")

        self.report["phases"]["summary"] = {
            "by_type": by_type,
            "by_severity": by_severity,
        }

    # ------------------------------------------------------------------
    def phase4_quarantine(self):
        print(f"\n[PHASE 4] QUARANTINING SHELLS (safe removal)")
        print(f"    Moving to: {QUARANTINE_DIR}/")

        for finding in self.findings:
            src = finding["file"]
            name = os.path.basename(src)
            dst = os.path.join(QUARANTINE_DIR, name + ".quarantined")

            try:
                shutil.move(src, dst)
                finding["quarantined"] = True
                finding["quarantine_path"] = dst
                print(f"    [+] {src} → {dst}")
            except Exception as e:
                print(f"    [!] {src}: {e}")

        self.report["phases"]["quarantine"] = {
            "dir": QUARANTINE_DIR,
            "moved": sum(1 for f in self.findings if f["quarantined"]),
        }

    # ------------------------------------------------------------------
    def phase5_cleanup_script(self):
        print(f"\n[PHASE 5] GENERATING CLEANUP SCRIPT")
        script_lines = [
            "#!/bin/bash",
            "# cleanup_shells.sh — Auto-generated by shell_detector.py",
            f"# Generated: {datetime.now().isoformat()}",
            "# Run this on your web server to PERMANENTLY delete quarantined shells.",
            "",
            "QUARANTINE_DIR=\"" + QUARANTINE_DIR + "\"",
            "",
            "if [ ! -d \"$QUARANTINE_DIR\" ]; then",
            "    echo \"No quarantine directory. Nothing to clean.\"",
            "    exit 0",
            "fi",
            "",
            "echo \"Removing quarantined shells...\"",
            "find \"$QUARANTINE_DIR\" -name '*.quarantined' -type f -print -delete",
            "",
            "echo \"Done. Quarantined shells permanently removed.\"",
        ]
        with open("cleanup_shells.sh", "w") as f:
            f.write("\n".join(script_lines))
        os.chmod("cleanup_shells.sh", 0o755)
        print(f"    [+] Generated: cleanup_shells.sh")
        print(f"    Run: ./cleanup_shells.sh")
        self.report["phases"]["cleanup_script"] = {"file": "cleanup_shells.sh"}

    # ------------------------------------------------------------------
    def phase6_report(self):
        print(f"\n[PHASE 6] REPORT")

        confirmed = [f"{f['type']} ({f['file']})" for f in self.findings]
        print(f"\n    Total findings: {len(confirmed)}")
        for c in confirmed:
            print(f"      * {c}")

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{REPORTS_DIR}/shell_detection_report_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"\n    [OK] JSON: {json_path}")

        html_path = f"{REPORTS_DIR}/shell_detection_report_{ts}.html"
        with open(html_path, "w") as f:
            f.write(self._build_html(confirmed))
        print(f"    [OK] HTML: {html_path}")

    def _build_html(self, confirmed):
        rows = ""
        for phase, data in self.report["phases"].items():
            rows += f"<h3>{phase}</h3><pre>{json.dumps(data, indent=2, default=str)[:4000]}</pre>"
        return f"""<!DOCTYPE html><html><head><title>Shell Detection Report</title>
<style>
body {{ font-family: monospace; background:#111; color:#eee; padding:20px; }}
h1 {{ color:#ff5555; }} h3 {{ color:#55ff55; border-bottom:1px solid #333; }}
pre {{ background:#1a1a1a; padding:10px; border-left:3px solid #ff5555; overflow:auto; }}
</style></head><body>
<h1>Web Shell Detection Report</h1>
<p><b>Target:</b> {self.report['target']}</p>
<p><b>Timestamp:</b> {self.report['timestamp']}</p>
<p><b>Findings:</b> {len(confirmed)}</p>
<ul>{''.join(f'<li>{c}</li>' for c in confirmed)}</ul>
{rows}
</body></html>"""

    def run_all(self):
        print("=" * 64)
        print(" Web Shell Detection & Removal - Project #60")
        print("=" * 64)
        self.phase1_scan()
        self.phase2_analyze()
        self.phase3_summary()
        self.phase4_quarantine()
        self.phase5_cleanup_script()
        self.phase6_report()

if __name__ == "__main__":
    ShellDetector().run_all()
