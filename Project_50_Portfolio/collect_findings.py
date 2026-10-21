#!/usr/bin/env python3
"""
collect_findings.py — Scan all Project_4X/5X reports and build findings.json
"""
import json
import os
import glob
from datetime import datetime

BASE = "/mnt/d/100 Project Challenge"

# Metadata for each project we built this session
PROJECT_META = {
    "Project_42_SSRF_Toolkit": {
        "id": 42,
        "name": "SSRF Basic",
        "category": "Web Exploitation",
        "severity": "HIGH",
        "cvss": 8.1,
        "vuln_class": "CWE-918: Server-Side Request Forgery",
        "tool": "ssrf_toolkit.py",
        "remediation": "Whitelist URLs, block private IPs, disable dangerous protocols",
    },
    "Project_43_XXE_Toolkit": {
        "id": 43,
        "name": "XXE Advanced",
        "category": "Web Exploitation",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "vuln_class": "CWE-611: Improper Restriction of XML External Entity Reference",
        "tool": "xxe_toolkit.py",
        "remediation": "Disable external entities, use defusedxml, disable DTDs",
    },
    "Project_44_SSI_Toolkit": {
        "id": 44,
        "name": "SSI Injection",
        "category": "Web Exploitation",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "vuln_class": "CWE-94: Code Injection via SSI",
        "tool": "ssi_toolkit.py",
        "remediation": "Disable SSI, use IncludesNOEXEC, sanitize user input",
    },
    "project_45_LDAP_toolkit": {
        "id": 45,
        "name": "LDAP Injection",
        "category": "Web Exploitation",
        "severity": "CRITICAL",
        "cvss": 9.0,
        "vuln_class": "CWE-90: LDAP Injection",
        "tool": "ldap_toolkit.py",
        "remediation": "Parameterized LDAP queries, escape special chars, whitelist input",
    },
    "project_46_nosql_toolkit": {
        "id": 46,
        "name": "NoSQL Injection",
        "category": "Web Exploitation",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "vuln_class": "CWE-943: Improper Neutralization of NoSQL Operators",
        "tool": "nosql_toolkit.py",
        "remediation": "Validate input types, reject $-prefixed keys, use schema validation",
    },
    "Project_47_SSRF_Advanced": {
        "id": 47,
        "name": "SSRF Advanced (Blind + OOB)",
        "category": "Web Exploitation",
        "severity": "CRITICAL",
        "cvss": 9.3,
        "vuln_class": "CWE-918: SSRF with Blind OOB exfiltration",
        "tool": "ssrf_advanced_toolkit.py",
        "remediation": "Disable IPv6, block cloud metadata IPs, egress firewall",
    },
    "Project_48_Deserialization_Toolkit": {
        "id": 48,
        "name": "Deserialization (Java + Python)",
        "category": "Advanced Attacks",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "vuln_class": "CWE-502: Deserialization of Untrusted Data",
        "tool": "deserialization_toolkit.py",
        "remediation": "Never deserialize untrusted data, use JSON, class whitelisting",
    },
    "Project_49_Cloud_Security": {
        "id": 49,
        "name": "Cloud Security (AWS/LocalStack)",
        "category": "Cloud Security",
        "severity": "CRITICAL",
        "cvss": 9.5,
        "vuln_class": "CWE-16: Cloud Misconfiguration (S3/IAM/SG)",
        "tool": "cloud_toolkit.py",
        "remediation": "Block public S3, enforce least-privilege IAM, restrict security groups",
    },
}

def scan_project(proj_dir_name, meta):
    """Scan a project folder for reports and tools."""
    proj_path = os.path.join(BASE, proj_dir_name)
    if not os.path.isdir(proj_path):
        return None

    # Find latest JSON report
    reports = glob.glob(os.path.join(proj_path, "reports", "*.json"))
    reports.sort(reverse=True)
    report_data = None
    if reports:
        try:
            with open(reports[0]) as f:
                report_data = json.load(f)
        except Exception:
            pass

    # Find tool script
    tool_path = None
    if meta.get("tool"):
        candidate = os.path.join(proj_path, meta["tool"])
        if os.path.exists(candidate):
            tool_path = candidate

    # Count confirmed findings from report
    finding_count = 0
    confirmed_list = []
    if report_data and "phases" in report_data:
        for phase_name, phase_data in report_data["phases"].items():
            if isinstance(phase_data, dict):
                for k, v in phase_data.items():
                    if isinstance(v, dict):
                        if (v.get("confirmed") or v.get("hit")
                                or v.get("bypassed") or v.get("worked")
                                or v.get("found")
                                or v.get("status") == "FAIL"
                                or v.get("count", 0) > 0):
                            confirmed_list.append(f"{phase_name}.{k}")
                            finding_count += 1
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict) and (
                                item.get("bypassed") or item.get("worked")
                                or item.get("hit") or item.get("found")
                                or item.get("executed")
                            ):
                                finding_count += 1

    return {
        "id": meta["id"],
        "name": meta["name"],
        "category": meta["category"],
        "severity": meta["severity"],
        "cvss": meta["cvss"],
        "vuln_class": meta["vuln_class"],
        "tool": meta["tool"],
        "tool_path": tool_path,
        "remediation": meta["remediation"],
        "finding_count": finding_count,
        "confirmed_findings": confirmed_list,
        "report_path": reports[0] if reports else None,
        "project_dir": proj_dir_name,
    }

def main():
    print("[*] Scanning projects...")
    findings = []

    for proj_dir_name, meta in PROJECT_META.items():
        result = scan_project(proj_dir_name, meta)
        if result:
            findings.append(result)
            print(f"  [+] #{meta['id']:2d} {meta['name']:<30} "
                  f"({result['finding_count']} findings)")
        else:
            print(f"  [-] #{meta['id']:2d} {meta['name']:<30} (folder missing)")

    # Sort by project ID
    findings.sort(key=lambda x: x["id"])

    output = {
        "portfolio_owner": "Saad",  # ← change this
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_projects": len(findings),
        "total_findings": sum(f["finding_count"] for f in findings),
        "projects": findings,
    }

    with open("findings.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n[✓] findings.json created")
    print(f"    Projects: {output['total_projects']}")
    print(f"    Total findings: {output['total_findings']}")

if __name__ == "__main__":
    main()
