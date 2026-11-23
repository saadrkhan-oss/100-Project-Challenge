#!/usr/bin/env python3
"""
Project 80 — SCADA/ICS Security Toolkit (Modbus/DNP3/OPC/S7)
All operations SIMULATED against mock scan data. No network traffic generated.
Defensive/educational use only.
"""
import os, sys, json, time, html
from datetime import datetime
from pathlib import Path

ROOT     = Path(__file__).resolve().parent
MOCK     = ROOT / "mock"
REPORTS  = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)
SCAN     = MOCK / "ics_scan.json"

SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

def banner(s): print(f"\n[📊] {s}")

# ------------------------------------------------------------------ Phase 1
def phase1_detect(data):
    banner("PHASE 1: PROTOCOL DETECTION (SIMULATED)")
    total = 0
    counts = {}
    for proto in ("modbus", "dnp3", "opc", "s7"):
        devs = data[proto]["devices"]
        counts[proto] = len(devs)
        total += len(devs)
        print(f"    [{proto.upper()}] {len(devs)} devices")
        for d in devs:
            model = d.get('model', d.get('endpoint', 'unknown'))
            print(f"      - {d['ip']}:{d['port']} ({d['type']}, {d['vendor']} {model})")
    print(f"    [+] {total} ICS devices detected across {len([k for k,v in counts.items() if v>0])} protocols")
    return counts

# ------------------------------------------------------------------ Phase 2
def phase2_identify(data):
    banner("PHASE 2: DEVICE IDENTIFICATION")
    by_type = {}
    for proto in ("modbus", "dnp3", "opc", "s7"):
        for d in data[proto]["devices"]:
            t = d["type"]
            by_type.setdefault(t, []).append({"proto": proto, **d})
    for t, devs in sorted(by_type.items()):
        print(f"    [{t.upper()}] {len(devs)} devices")
        for d in devs:
            model = d.get('model', d.get('endpoint', 'unknown'))
            print(f"      - {d['ip']} ({d['vendor']} {model}) via {d['proto'].upper()}")
    print(f"    [+] {sum(len(v) for v in by_type.values())} devices identified across {len(by_type)} types")
    return by_type

# ------------------------------------------------------------------ Phase 3
def phase3_audit(data):
    banner("PHASE 3: CONFIGURATION AUDIT")
    findings = []
    ca = data["config_audit"]

    print(f"    [DEFAULT_PASSWORDS] Found {len(ca['default_credentials'])}")
    for c in ca["default_credentials"]:
        print(f"      - {c['ip']}: {c['user']}:{c['pass']}")
        findings.append({
            "id": "default_credentials", "severity": "Critical", "cwe": "CWE-1392",
            "target": c["ip"],
            "detail": f"Default credentials {c['user']}:{c['pass']} on {c['ip']}",
            "remediation": "Change default passwords immediately; enforce strong auth; "
                           "use IEC 62443 account management controls.",
        })

    print(f"    [OPEN_PORTS] {len(ca['open_ports'])} ports: {ca['open_ports']}")
    findings.append({
        "id": "exposed_ics_ports", "severity": "High", "cwe": "CWE-284",
        "target": "network",
        "detail": f"ICS ports exposed: {', '.join(str(p) for p in ca['open_ports'])}",
        "remediation": "Segment ICS network from IT (Purdue model); firewall port 502/102/20000/4840; "
                       "deploy unidirectional gateways where possible.",
    })

    print(f"    [UNENCRYPTED_PROTOCOLS] {len(ca['unencrypted_protocols'])}")
    for p in ca["unencrypted_protocols"]:
        print(f"      - {p} (cleartext)")
    findings.append({
        "id": "unencrypted_ics_protocols", "severity": "High", "cwe": "CWE-319",
        "target": "network",
        "detail": f"Unencrypted protocols in use: {', '.join(ca['unencrypted_protocols'])}",
        "remediation": "Use Modbus/TCP Security (TLS), DNP3 Secure Auth, OPC UA SignAndEncrypt; "
                       "tunnel legacy protocols through VPN/IPsec.",
    })

    print(f"    [OUTDATED_FIRMWARE] {sum(1 for f in ca['firmware'] if f['outdated'])} devices")
    for f in ca["firmware"]:
        if f["outdated"]:
            print(f"      - {f['ip']}: {f['version']} (latest: {f['latest']})")
            findings.append({
                "id": "outdated_firmware", "severity": "High", "cwe": "CWE-1104",
                "target": f["ip"],
                "detail": f"Firmware {f['version']} outdated (latest {f['latest']}) on {f['ip']}",
                "remediation": "Patch firmware per vendor advisory; establish change management "
                               "and staged rollouts for ICS environments.",
            })

    print(f"    [+] {len(findings)} misconfigurations found")
    return findings

# ------------------------------------------------------------------ Phase 4
def phase4_analysis(data):
    banner("PHASE 4: PROTOCOL ANALYSIS")
    findings = []
    total_fc = 0

    dangerous_modbus = {5, 6, 15, 16}
    for proto in ("modbus", "dnp3", "s7"):
        fcs = data[proto]["function_codes"]
        total_fc += len(fcs)
        print(f"    [{proto.upper()}] {len(data[proto]['devices'])} devices, {len(fcs)} function codes")
        for fc in fcs:
            print(f"      - {fc['name']} ({fc['code']})")
        if proto == "modbus":
            write_fcs = [fc for fc in fcs if fc["code"] in dangerous_modbus]
            if write_fcs:
                findings.append({
                    "id": "modbus_write_functions", "severity": "High", "cwe": "CWE-306",
                    "target": "Modbus network",
                    "detail": f"Write function codes enabled without auth: "
                              f"{', '.join(fc['name'] for fc in write_fcs)}",
                    "remediation": "Disable write function codes for read-only devices; "
                                   "enforce Modbus/TCP Security (TLS + cert); deploy deep-packet inspection.",
                })
        if proto == "dnp3":
            control = [fc for fc in fcs if "Operate" in fc["name"]]
            if control:
                findings.append({
                    "id": "dnp3_control_ops", "severity": "High", "cwe": "CWE-306",
                    "target": "DNP3 network",
                    "detail": f"Control operations enabled without Secure Auth: "
                              f"{', '.join(fc['name'] for fc in control)}",
                    "remediation": "Enable DNP3 Secure Authentication v5; restrict operate commands "
                                   "to authorized masters only.",
                })
        if proto == "s7":
            download = [fc for fc in fcs if "Download" in fc["name"]]
            if download:
                findings.append({
                    "id": "s7_download_enabled", "severity": "Critical", "cwe": "CWE-306",
                    "target": "Siemens PLC network",
                    "detail": "S7comm Request Download enabled — PLC logic can be replaced remotely",
                    "remediation": "Disable PG/download access in TIA Portal; enable S7-1500 "
                                   "integrity protection; restrict port 102 to engineering workstations.",
                })

    print(f"    [+] {total_fc} function codes identified across 3 protocols")
    return findings

# ------------------------------------------------------------------ Phase 5
def phase5_vulns(data, audit_findings):
    banner("PHASE 5: VULNERABILITY ASSESSMENT")
    findings = []

    print(f"    [CVE] Checking CVE database ({len(data['cve_db'])} entries)...")
    for c in data["cve_db"]:
        sev = "Critical" if c["cvss"] >= 9.0 else ("High" if c["cvss"] >= 7.0 else "Medium")
        print(f"      - {c['cve']} ({c['device']}) CVSS {c['cvss']}: {c['desc']}")
        findings.append({
            "id": f"cve_{c['cve']}", "severity": sev, "cwe": "CWE-1104",
            "target": c["device"],
            "detail": f"{c['cve']} (CVSS {c['cvss']}): {c['desc']}",
            "remediation": f"Apply vendor patch for {c['cve']}; verify mitigations per CISA ICS advisory.",
        })

    print(f"    [OPC_UA] Auth: {data['opc']['auth']}, endpoints: {data['opc']['endpoints']}")
    if "Anonymous" in data["opc"]["auth"]:
        findings.append({
            "id": "opcua_anonymous", "severity": "High", "cwe": "CWE-306",
            "target": "OPC UA Server",
            "detail": "OPC UA allows anonymous authentication",
            "remediation": "Require certificate-based authentication; disable None security policy; "
                           "use SignAndEncrypt for all sessions.",
        })
    if "None" in data["opc"]["endpoints"]:
        findings.append({
            "id": "opcua_no_encryption", "severity": "High", "cwe": "CWE-319",
            "target": "OPC UA Server",
            "detail": "OPC UA endpoint accepts None security policy (no encryption)",
            "remediation": "Remove None endpoint; enforce SignAndEncrypt with AES-256.",
        })

    print(f"    [+] {len(findings)} CVE/misconfig findings")
    return findings

# ------------------------------------------------------------------ Phase 6
def phase6_report(data, counts, by_type, audit, proto_findings, vuln_findings, elapsed):
    banner("PHASE 6: REPORT")
    all_findings = audit + proto_findings + vuln_findings
    all_findings.sort(key=lambda x: (-SEV_RANK[x["severity"]], x["id"]))
    sev_counts = {}
    for f in all_findings: sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    cwe_set = sorted(set(f["cwe"] for f in all_findings))

    report = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "project": "Project 80 — SCADA/ICS Security Toolkit",
        "environment": data["environment"],
        "protocols": counts,
        "device_types": {t: len(v) for t, v in by_type.items()},
        "summary": {"total_findings": len(all_findings),
                    "by_severity": sev_counts, "cwes": cwe_set},
        "findings": all_findings,
        "elapsed_s": round(elapsed, 2),
        "disclaimer": "All scanning and protocol analysis SIMULATED against mock data. "
                      "No network traffic generated. Defensive/educational use only.",
    }
    (REPORTS / "ics_report.json").write_text(json.dumps(report, indent=2))
    print(f"    [OK] JSON: reports/ics_report.json ({len(all_findings)} findings)")

    rows = "\n".join(
        f"""<tr class="sev-{f['severity'].lower()}">
          <td><span class="badge {f['severity'].lower()}">{f['severity']}</span></td>
          <td><code>{f['cwe']}</code></td>
          <td><b>{html.escape(f['id'])}</b></td>
          <td>{html.escape(str(f['target']))}</td>
          <td>{html.escape(f['detail'])}</td>
          <td>{html.escape(f['remediation'])}</td>
        </tr>""" for f in all_findings)
    cards = "\n".join(
        f'<div class="card"><b>{v}</b>{k}</div>' for k, v in sorted(
            sev_counts.items(), key=lambda x: -SEV_RANK[x[0]]))
    proto_cards = "\n".join(
        f'<div class="fact"><b>{k.upper()}</b>{v} device(s)</div>'
        for k, v in counts.items())

    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Project 80 — ICS Security Report</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;background:#fafafa;color:#1a1a1a}}
 h1{{border-bottom:3px solid #c62828;padding-bottom:.4rem}}
 .meta{{color:#666;font-size:.9rem;margin-bottom:1rem}}
 .warning{{background:#fff3e0;border-left:4px solid #f57c00;padding:.7rem 1rem;border-radius:6px;
          font-size:.85rem;margin-bottom:1rem}}
 .cards{{display:flex;gap:1rem;margin:1rem 0 1.5rem;flex-wrap:wrap}}
 .card{{flex:1;min-width:110px;background:#fff;padding:.8rem 1rem;border-radius:8px;
       box-shadow:0 1px 3px rgba(0,0,0,.08);border-left:4px solid #c62828;font-size:.85rem;color:#666}}
 .card b{{display:block;font-size:1.5rem;color:#1a1a1a}}
 .facts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.8rem;margin:1rem 0 2rem}}
 .fact{{background:#fff;padding:.8rem 1rem;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.06);font-size:.85rem;color:#666}}
 .fact b{{display:block;color:#c62828;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;
        box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 th,td{{padding:.6rem .7rem;text-align:left;border-bottom:1px solid #eee;font-size:.82rem;vertical-align:top}}
 th{{background:#263238;color:#fff}}
 code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px;font-size:.78rem}}
 .badge{{padding:.1rem .45rem;border-radius:10px;color:#fff;font-weight:600;font-size:.72rem}}
 .badge.critical{{background:#b71c1c}} .badge.high{{background:#d32f2f}}
 .badge.medium{{background:#f57c00}} .badge.low{{background:#388e3c}} .badge.info{{background:#0288d1}}
 tr.sev-critical td{{background:#ffebee}} tr.sev-high td{{background:#fff3e0}}
</style></head><body>
<h1>🏭 Project 80 — SCADA/ICS Security Report</h1>
<div class="meta">Environment: {html.escape(data['environment'])} · Generated {report['generated']}</div>
<div class="warning">⚠️ All scanning and protocol analysis SIMULATED against mock data.
No network traffic generated. Defensive/educational use only.</div>
<div class="facts">{proto_cards}
  <div class="fact"><b>DEVICE TYPES</b>{len(by_type)}</div>
  <div class="fact"><b>CVEs</b>{len(data['cve_db'])}</div>
</div>
<div class="cards">{cards}</div>
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>CWE</th><th>ID</th><th>Target</th><th>Detail</th><th>Remediation</th></tr></thead>
<tbody>{rows}</tbody></table>
<p style="margin-top:2rem;color:#888;font-size:.8rem">
Generated by ics_toolkit.py — defensive/educational use only. Only scan your own ICS lab.
</p>
</body></html>"""
    (REPORTS / "ics_report.html").write_text(doc)
    print(f"    [OK] HTML: reports/ics_report.html")
    print(f"\n    Total findings: {len(all_findings)}")
    for sev in ("Critical","High","Medium","Low","Info"):
        if sev in sev_counts:
            print(f"      {sev:9s}: {sev_counts[sev]}")

# ------------------------------------------------------------------ main
def main():
    t0 = time.time()
    print("[+] SCADA/ICS Security Toolkit (Modbus/DNP3/OPC/S7)")
    print(f"[+] Target: {json.loads(SCAN.read_text())['environment']}")
    print("[!] All operations SIMULATED — no network traffic generated")
    if not SCAN.exists():
        print(f"[!] run Block 1 first — mock/ics_scan.json missing"); sys.exit(1)

    data = json.loads(SCAN.read_text())
    counts       = phase1_detect(data)
    by_type      = phase2_identify(data)
    audit        = phase3_audit(data)
    proto_finds  = phase4_analysis(data)
    vuln_finds   = phase5_vulns(data, audit)
    phase6_report(data, counts, by_type, audit, proto_finds, vuln_finds, time.time() - t0)
    print(f"\n✅ Done in {time.time()-t0:.2f}s")

if __name__ == "__main__":
    main()
